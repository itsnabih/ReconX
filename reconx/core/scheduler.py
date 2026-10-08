"""Dependency-aware DAG task scheduler with bounded multi-class concurrency."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import heapq
import logging
import time
from typing import Sequence

from reconx.core.caching import ResultCache, TaskDeduplicator, make_cache_key
from reconx.core.cancellation import CancellationToken
from reconx.core.metrics import PerformanceMetrics, PerformanceProfiler
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.task import Task, TaskResult, TaskState
from reconx.scope.validator import ScopeValidator

logger = logging.getLogger("reconx.core.scheduler")


@dataclass
class SchedulerConfig:
    """Concurrency and timeout configuration for the scheduler."""

    global_concurrency: int = 20
    resource_concurrency: dict[str, int] = field(
        default_factory=lambda: {
            "dns": 8,
            "network": 4,
            "http": 10,
            "discovery": 6,
            "vulnerability": 2,
            "default": 10,
        }
    )
    default_resource_concurrency: int = 10
    default_timeout: float | None = None


@dataclass
class SchedulerSummary:
    """Summary of scheduled execution run."""

    total_tasks: int
    completed: int
    failed: int
    timed_out: int
    cancelled: int
    skipped: int
    duration: float
    started_at: datetime
    finished_at: datetime
    results: dict[str, TaskResult]
    metrics: PerformanceMetrics | None = None


class Scheduler:
    """DAG-based task scheduler enforcing bounded global and resource concurrency."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        config: SchedulerConfig | None = None,
        cancellation_token: CancellationToken | None = None,
        scope: ScopeValidator | None = None,
        profiler: PerformanceProfiler | None = None,
        cache: ResultCache | None = None,
        deduplicator: TaskDeduplicator | None = None,
    ) -> None:
        self.runner = runner or CommandRunner()
        self.config = config or SchedulerConfig()
        self.cancellation_token = cancellation_token or CancellationToken()
        self.scope = scope
        self.profiler = profiler
        self.cache = cache
        self.deduplicator = deduplicator

        self._tasks: dict[str, Task] = {}
        self._results: dict[str, TaskResult] = {}
        self._resource_semaphores: dict[str, asyncio.Semaphore] = {}
        self._global_semaphore: asyncio.Semaphore | None = None

    def add_task(self, task: Task) -> None:
        """Add a single task to the scheduler."""
        if task.id in self._tasks:
            raise ValueError(f"Task with id '{task.id}' already exists in scheduler")

        if self.deduplicator is not None:
            existing_id = self.deduplicator.register(task)
            if existing_id is not None:
                if self.profiler is not None:
                    self.profiler.record_dedup_skip()
                skip_res = TaskResult(
                    task_id=task.id,
                    state=TaskState.SKIPPED,
                    error_message=f"Duplicate of task '{existing_id}'; redundant execution skipped",
                )
                task.mark_finished(TaskState.SKIPPED, skip_res)
                self._tasks[task.id] = task
                self._results[task.id] = skip_res
                return

        task.mark_queued()
        self._tasks[task.id] = task

    def add_tasks(self, tasks: Sequence[Task]) -> None:
        """Add multiple tasks to the scheduler."""
        for task in tasks:
            self.add_task(task)

    def cancel(self) -> None:
        """Cancel all pending and running tasks."""
        self.cancellation_token.cancel()

    def validate_graph(self) -> None:
        """Validate DAG: ensure all dependencies exist and there are no cycles."""
        # 1. Check for missing dependencies
        for task in self._tasks.values():
            for dep_id in task.dependencies:
                if dep_id not in self._tasks:
                    raise ValueError(f"Task '{task.id}' depends on unknown task '{dep_id}'")

        # 2. Cycle detection using 3-color DFS
        # 0 = unvisited, 1 = visiting (in recursion stack), 2 = visited
        state: dict[str, int] = {task_id: 0 for task_id in self._tasks}

        def dfs(node_id: str) -> None:
            state[node_id] = 1
            task = self._tasks[node_id]
            for dep_id in task.dependencies:
                if state[dep_id] == 1:
                    raise ValueError(f"Cyclic dependency detected: '{node_id}' -> '{dep_id}'")
                if state[dep_id] == 0:
                    dfs(dep_id)
            state[node_id] = 2

        for task_id in self._tasks:
            if state[task_id] == 0:
                dfs(task_id)

    def _get_resource_semaphore(self, resource_class: str) -> asyncio.Semaphore:
        """Get or initialize semaphore for a specific resource class."""
        if resource_class not in self._resource_semaphores:
            limit = self.config.resource_concurrency.get(
                resource_class, self.config.default_resource_concurrency
            )
            self._resource_semaphores[resource_class] = asyncio.Semaphore(limit)
        return self._resource_semaphores[resource_class]

    async def run(self) -> SchedulerSummary:
        """Execute all scheduled tasks respecting dependencies and concurrency limits."""
        self.validate_graph()

        if self.profiler is not None:
            self.profiler.start()

        started_at = datetime.now(timezone.utc)
        start_mono = time.monotonic()

        self._global_semaphore = asyncio.Semaphore(self.config.global_concurrency)
        self._resource_semaphores.clear()

        # Build reverse dependency map: parent_id -> list of child_ids that depend on parent
        children_map: dict[str, list[str]] = {task_id: [] for task_id in self._tasks}
        # In-degree tracking: number of unfinished dependencies remaining for each task
        unmet_dependencies: dict[str, set[str]] = {}

        for task_id, task in self._tasks.items():
            if task.is_terminal:
                continue
            unmet_dependencies[task_id] = set(task.dependencies)
            for dep_id in task.dependencies:
                children_map[dep_id].append(task_id)

        # Priority queue using min-heap with (-priority, seq, task_id)
        ready_heap: list[tuple[int, int, str]] = []
        heap_seq = 0

        def _push_ready(tid: str) -> None:
            nonlocal heap_seq
            self._tasks[tid].mark_ready()
            heapq.heappush(ready_heap, (-self._tasks[tid].priority, heap_seq, tid))
            heap_seq += 1

        def _pop_ready() -> str:
            _, _, tid = heapq.heappop(ready_heap)
            return tid

        for tid, deps in unmet_dependencies.items():
            if len(deps) == 0:
                _push_ready(tid)

        active_tasks: set[asyncio.Task] = set()
        finished_event = asyncio.Event()

        def skip_descendants(parent_id: str, reason: str) -> None:
            """Recursively mark all descendants of a failed or skipped task as SKIPPED."""
            descendants_queue = list(children_map.get(parent_id, []))
            while descendants_queue:
                child_id = descendants_queue.pop(0)
                child_task = self._tasks[child_id]
                if not child_task.is_terminal:
                    child_result = TaskResult(
                        task_id=child_id,
                        state=TaskState.SKIPPED,
                        error_message=f"Prerequisite '{parent_id}' did not succeed ({reason})",
                    )
                    child_task.mark_finished(TaskState.SKIPPED, child_result)
                    self._results[child_id] = child_result
                    logger.info("Task '%s' skipped because prerequisite '%s' %s", child_id, parent_id, reason)
                    descendants_queue.extend(children_map.get(child_id, []))

        async def execute_task_wrapper(task: Task) -> None:
            res = await self._execute_task(task)
            self._results[task.id] = res

            if res.state == TaskState.COMPLETED:
                # Notify downstream tasks
                for child_id in children_map.get(task.id, []):
                    child_task = self._tasks[child_id]
                    if child_task.is_terminal:
                        continue
                    unmet = unmet_dependencies.get(child_id)
                    if unmet is not None and task.id in unmet:
                        unmet.remove(task.id)
                        if len(unmet) == 0:
                            _push_ready(child_id)
            else:
                # Task did not succeed (FAILED, TIMEOUT, CANCELLED)
                skip_descendants(task.id, f"ended in state {res.state.value}")

            finished_event.set()

        try:
            while True:
                if self.cancellation_token.is_cancelled:
                    ready_heap.clear()
                    # Mark all unstarted tasks as CANCELLED
                    active_task_names = {t.get_name() for t in active_tasks}
                    for tid, t in self._tasks.items():
                        if not t.is_terminal and tid not in active_task_names:
                            if unmet_dependencies.get(tid):
                                skip_res = TaskResult(
                                    task_id=tid,
                                    state=TaskState.SKIPPED,
                                    error_message="Prerequisite dependencies not met due to cancellation",
                                )
                                t.mark_finished(TaskState.SKIPPED, skip_res)
                                self._results[tid] = skip_res
                            else:
                                can_res = TaskResult(
                                    task_id=tid,
                                    state=TaskState.CANCELLED,
                                    error_message="Cancelled by user or system",
                                )
                                t.mark_finished(TaskState.CANCELLED, can_res)
                                self._results[tid] = can_res
                    if not active_tasks:
                        break

                # Launch ready tasks that can be scheduled
                while ready_heap and not self.cancellation_token.is_cancelled:
                    next_task_id = _pop_ready()
                    next_task = self._tasks[next_task_id]
                    if next_task.is_terminal:
                        continue

                    coro = execute_task_wrapper(next_task)
                    t_async = asyncio.create_task(coro, name=next_task_id)
                    active_tasks.add(t_async)

                    def _task_done(fut: asyncio.Task) -> None:
                        active_tasks.discard(fut)
                        finished_event.set()

                    t_async.add_done_callback(_task_done)

                if not active_tasks:
                    # All tasks scheduled and finished
                    break

                # Wait until at least one running task finishes or cancellation fires
                finished_event.clear()
                await finished_event.wait()

        except asyncio.CancelledError:
            self.cancellation_token.cancel()
            if active_tasks:
                await asyncio.gather(*active_tasks, return_exceptions=True)
            raise

        finished_at = datetime.now(timezone.utc)
        duration = time.monotonic() - start_mono

        # Count states
        completed = sum(1 for r in self._results.values() if r.state == TaskState.COMPLETED)
        failed = sum(1 for r in self._results.values() if r.state == TaskState.FAILED)
        timed_out = sum(1 for r in self._results.values() if r.state == TaskState.TIMEOUT)
        cancelled = sum(1 for r in self._results.values() if r.state == TaskState.CANCELLED)
        skipped = sum(1 for r in self._results.values() if r.state == TaskState.SKIPPED)

        if self.profiler is not None:
            self.profiler.stop()
            metrics = self.profiler.get_metrics()
        else:
            metrics = None

        return SchedulerSummary(
            total_tasks=len(self._tasks),
            completed=completed,
            failed=failed,
            timed_out=timed_out,
            cancelled=cancelled,
            skipped=skipped,
            duration=duration,
            started_at=started_at,
            finished_at=finished_at,
            results=self._results,
            metrics=metrics,
        )

    def _scope_violation(self, task: Task) -> str | None:
        """Return a rejection reason if the task's target may not be interacted with."""
        if not task.target:
            return None
        if self.scope is None:
            return f"Target '{task.target}' rejected: no scope configured"
        decision = self.scope.check(task.target)
        if decision.allowed:
            return None
        detail = f": {decision.detail}" if decision.detail else ""
        return f"Target '{task.target}' is out of scope ({decision.reason.value}{detail})"

    async def _execute_task(self, task: Task) -> TaskResult:
        """Execute a task with concurrency semaphores, retry policy, and timeout handling."""
        violation = self._scope_violation(task)
        if violation is not None:
            logger.warning("Task '%s' not executed: %s", task.id, violation)
            result = TaskResult(task_id=task.id, state=TaskState.SKIPPED, error_message=violation)
            task.mark_finished(TaskState.SKIPPED, result)
            return result

        # Check cache if available to prevent redundant execution
        cache_key: str | None = None
        if self.cache is not None and task.command:
            cache_key = make_cache_key(
                tool=task.command[0],
                target=task.target,
                arguments=task.command[1:],
            )
            cached_res = self.cache.get(cache_key)
            if cached_res is not None:
                if self.profiler is not None:
                    self.profiler.record_cache_hit()
                res = TaskResult(
                    task_id=task.id,
                    state=cached_res.state,
                    command_result=cached_res.command_result,
                    output_data=cached_res.output_data,
                    error_message=cached_res.error_message,
                    attempts=1,
                    duration=0.001,
                )
                task.mark_finished(cached_res.state, res)
                return res

            if self.profiler is not None:
                self.profiler.record_cache_miss()

        resource_sem = self._get_resource_semaphore(task.resource_class)
        assert self._global_semaphore is not None

        # Acquire semaphores in fixed order: global first, then resource
        async with self._global_semaphore:
            async with resource_sem:
                task.mark_running()
                effective_timeout = (
                    task.timeout if task.timeout is not None else self.config.default_timeout
                )

                attempt = 0
                last_cmd_result: CommandResult | None = None
                last_error: str | None = None

                while True:
                    attempt += 1
                    task.attempts = attempt

                    if self.cancellation_token.is_cancelled:
                        result = TaskResult(
                            task_id=task.id,
                            state=TaskState.CANCELLED,
                            command_result=last_cmd_result,
                            error_message="Cancelled before attempt execution",
                            attempts=attempt,
                        )
                        task.mark_finished(TaskState.CANCELLED, result)
                        return result

                    def _finish(state: TaskState, res: TaskResult) -> TaskResult:
                        task.mark_finished(state, res)
                        if task.duration is not None:
                            res.duration = task.duration
                        if cache_key is not None and self.cache is not None and res.is_success:
                            self.cache.set(cache_key, res)
                        if self.profiler is not None:
                            tool_name = task.command[0] if task.command else task.type
                            self.profiler.record_task(task.id, res.duration, state.value, tool_name)
                        return res

                    # Execute custom action or command
                    if task.action is not None:
                        try:
                            result = await task.action(task, self.runner, self.cancellation_token)
                            return _finish(result.state, result)
                        except Exception as exc:
                            last_error = str(exc)
                            logger.error("Exception executing action for task '%s': %s", task.id, exc)
                            cmd_timed_out = False
                            exit_code = 1
                    elif task.command is not None:
                        cmd_res = await self.runner.run(
                            command=task.command,
                            timeout=effective_timeout,
                            cancellation_token=self.cancellation_token,
                        )
                        last_cmd_result = cmd_res
                        cmd_timed_out = cmd_res.timed_out
                        exit_code = cmd_res.exit_code
                        last_error = cmd_res.error

                        if cmd_res.cancelled:
                            result = TaskResult(
                                task_id=task.id,
                                state=TaskState.CANCELLED,
                                command_result=cmd_res,
                                error_message=cmd_res.error or "Command cancelled",
                                attempts=attempt,
                            )
                            return _finish(TaskState.CANCELLED, result)

                        if cmd_res.success:
                            result = TaskResult(
                                task_id=task.id,
                                state=TaskState.COMPLETED,
                                command_result=cmd_res,
                                attempts=attempt,
                            )
                            return _finish(TaskState.COMPLETED, result)
                    else:
                        result = TaskResult(
                            task_id=task.id,
                            state=TaskState.FAILED,
                            error_message="Task has neither command nor action specified",
                            attempts=attempt,
                        )
                        return _finish(TaskState.FAILED, result)

                    # If not successful, check retry policy
                    if task.retry_policy.should_retry(attempt, exit_code, cmd_timed_out):
                        backoff = task.retry_policy.backoff_factor * attempt
                        logger.info(
                            "Retrying task '%s' (attempt %d/%d, backoff=%.2fs)",
                            task.id,
                            attempt,
                            task.retry_policy.max_retries,
                            backoff,
                        )
                        if backoff > 0:
                            await asyncio.sleep(backoff)
                        continue

                    # Retries exhausted or failure is not retryable
                    final_state = TaskState.TIMEOUT if cmd_timed_out else TaskState.FAILED
                    result = TaskResult(
                        task_id=task.id,
                        state=final_state,
                        command_result=last_cmd_result,
                        error_message=last_error,
                        attempts=attempt,
                    )
                    return _finish(final_state, result)
