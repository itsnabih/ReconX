"""Resume engine for interrupted or partially completed scan sessions.

Strictly adheres to Section 25 of Implementation.md:
COMPLETED → skip
FAILED → retry according to policy
TIMEOUT → retry
CANCELLED → retry
RUNNING → recover safely
PENDING → execute

Never assume an interrupted process completed successfully.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from typing import Any

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig, SchedulerSummary
from reconx.core.task import Task, TaskResult, TaskState
from reconx.models.scan import ScanState, ScanStatus
from reconx.scope.validator import ScopeValidator

logger = logging.getLogger("reconx.session.resume")


@dataclass
class ResumePlan:
    """Plan detailing how tasks in a scan session will be resumed."""

    scan_id: str
    total_tasks: int
    skipped_tasks: list[Task] = field(default_factory=list)
    retried_tasks: list[Task] = field(default_factory=list)
    recovered_tasks: list[Task] = field(default_factory=list)
    pending_tasks: list[Task] = field(default_factory=list)
    unretryable_tasks: list[Task] = field(default_factory=list)
    executable_tasks: list[Task] = field(default_factory=list)
    satisfied_dependencies: dict[str, set[str]] = field(default_factory=dict)

    @property
    def can_resume(self) -> bool:
        """Return True if there are tasks to execute."""
        return len(self.executable_tasks) > 0

    @property
    def skipped_count(self) -> int:
        return len(self.skipped_tasks)

    @property
    def retried_count(self) -> int:
        return len(self.retried_tasks)

    @property
    def recovered_count(self) -> int:
        return len(self.recovered_tasks)

    @property
    def pending_count(self) -> int:
        return len(self.pending_tasks)

    @property
    def executable_count(self) -> int:
        return len(self.executable_tasks)

    def summary(self) -> dict[str, Any]:
        """Summary statistics of the resume plan."""
        return {
            "scan_id": self.scan_id,
            "total_tasks": self.total_tasks,
            "skipped": self.skipped_count,
            "retried": self.retried_count,
            "recovered": self.recovered_count,
            "pending": self.pending_count,
            "executable": self.executable_count,
            "unretryable": len(self.unretryable_tasks),
        }


class ResumeEngine:
    """Computes resume transitions, adjusts DAG dependencies, and prepares schedulers."""

    @classmethod
    def prepare_resume(
        cls,
        state: ScanState,
        force_retry_failed: bool = True,
        respect_max_retries: bool = False,
    ) -> ResumePlan:
        """Analyze a scan's tasks and build a ResumePlan conforming to Section 25.

        Args:
            state: The persisted ScanState to resume.
            force_retry_failed: If True, FAILED tasks are queued for retry regardless
                                of previous attempt count.
            respect_max_retries: If True and force_retry_failed is False, FAILED tasks
                                that exceeded max_retries will not be retried.

        Returns:
            A ResumePlan detailing skipped, retried, recovered, and executable tasks.
        """
        scan_id = state.scan.id
        total_tasks = len(state.tasks)

        skipped_tasks: list[Task] = []
        retried_tasks: list[Task] = []
        recovered_tasks: list[Task] = []
        pending_tasks: list[Task] = []
        unretryable_tasks: list[Task] = []
        satisfied_dependencies: dict[str, set[str]] = {}

        # 1. Identify completed tasks (which must never be rerun unnecessarily)
        completed_ids: set[str] = {
            t.id for t in state.tasks if t.state == TaskState.COMPLETED
        }

        candidate_executable: list[Task] = []

        # 2. Categorize each task according to Section 25 state transitions
        for task in state.tasks:
            current_state = task.state

            if current_state == TaskState.COMPLETED:
                # COMPLETED → skip
                skipped_tasks.append(task)

            elif current_state == TaskState.RUNNING:
                # RUNNING → recover safely
                # Interrupted mid-execution; reset transient running state
                task.state = TaskState.PENDING
                task.started_at = None
                task.finished_at = None
                task.duration = None
                task.result = None
                recovered_tasks.append(task)
                candidate_executable.append(task)

            elif current_state in (TaskState.TIMEOUT, TaskState.CANCELLED):
                # TIMEOUT / CANCELLED → retry
                task.state = TaskState.PENDING
                task.started_at = None
                task.finished_at = None
                task.duration = None
                task.result = None
                retried_tasks.append(task)
                candidate_executable.append(task)

            elif current_state == TaskState.FAILED:
                # FAILED → retry according to policy
                should_retry = True
                if respect_max_retries and not force_retry_failed:
                    if task.attempts > task.retry_policy.max_retries:
                        should_retry = False

                if should_retry:
                    task.state = TaskState.PENDING
                    task.started_at = None
                    task.finished_at = None
                    task.duration = None
                    task.result = None
                    retried_tasks.append(task)
                    candidate_executable.append(task)
                else:
                    unretryable_tasks.append(task)

            elif current_state in (TaskState.PENDING, TaskState.READY):
                # PENDING / READY → execute
                task.state = TaskState.PENDING
                pending_tasks.append(task)
                candidate_executable.append(task)

            elif current_state == TaskState.SKIPPED:
                # SKIPPED: previously skipped due to prerequisite failure/cancellation.
                # Now that prerequisite may be retried, reset to PENDING.
                task.state = TaskState.PENDING
                task.started_at = None
                task.finished_at = None
                task.duration = None
                task.result = None
                pending_tasks.append(task)
                candidate_executable.append(task)

            else:
                # Unknown/unexpected state: treat safely as PENDING
                task.state = TaskState.PENDING
                pending_tasks.append(task)
                candidate_executable.append(task)

        # 3. Resolve DAG dependencies:
        # Completed prerequisites are already satisfied, so remove them from
        # dependent tasks so the scheduler doesn't block waiting for them.
        candidate_ids = {t.id for t in candidate_executable}

        for task in candidate_executable:
            satisfied = {dep for dep in task.dependencies if dep in completed_ids}
            if satisfied:
                satisfied_dependencies[task.id] = satisfied
                task.dependencies = task.dependencies - satisfied

        # 4. Handle any tasks whose dependencies are unretryable or missing
        executable_tasks: list[Task] = []
        for task in candidate_executable:
            unmet_missing = {
                dep for dep in task.dependencies if dep not in candidate_ids
            }
            if unmet_missing:
                # Dependent cannot run because prerequisite will never run
                task.mark_finished(
                    TaskState.SKIPPED,
                    TaskResult(
                        task_id=task.id,
                        state=TaskState.SKIPPED,
                        error_message=(
                            f"Prerequisites {sorted(unmet_missing)} cannot be satisfied on resume"
                        ),
                    ),
                )
                unretryable_tasks.append(task)
            else:
                executable_tasks.append(task)

        return ResumePlan(
            scan_id=scan_id,
            total_tasks=total_tasks,
            skipped_tasks=skipped_tasks,
            retried_tasks=retried_tasks,
            recovered_tasks=recovered_tasks,
            pending_tasks=pending_tasks,
            unretryable_tasks=unretryable_tasks,
            executable_tasks=executable_tasks,
            satisfied_dependencies=satisfied_dependencies,
        )

    @classmethod
    def apply_resume(cls, state: ScanState, plan: ResumePlan) -> ScanState:
        """Update scan lifecycle status in ScanState for resumption."""
        if plan.can_resume:
            state.scan.status = ScanStatus.RUNNING
            state.scan.finished_at = None
            if state.scan.started_at is None:
                state.scan.started_at = datetime.now(timezone.utc)
        else:
            # Nothing left to run
            state.scan.status = ScanStatus.COMPLETED
            if state.scan.finished_at is None:
                state.scan.finished_at = datetime.now(timezone.utc)

        return state

    @classmethod
    def create_scheduler(
        cls,
        plan: ResumePlan,
        config: SchedulerConfig | None = None,
        runner: CommandRunner | None = None,
        cancellation_token: CancellationToken | None = None,
        scope: ScopeValidator | None = None,
    ) -> Scheduler:
        """Create and validate a Scheduler preloaded with executable resume tasks."""
        scheduler = Scheduler(
            runner=runner,
            config=config,
            cancellation_token=cancellation_token,
            scope=scope,
        )

        for task in plan.executable_tasks:
            scheduler.add_task(task)

        if plan.executable_tasks:
            scheduler.validate_graph()

        return scheduler

    @classmethod
    def merge_execution_summary(
        cls,
        state: ScanState,
        plan: ResumePlan,
        summary: SchedulerSummary,
    ) -> ScanState:
        """Merge scheduler results into the scan state and finalize scan status."""
        # Index all tasks in state by ID
        task_map = {t.id: t for t in state.tasks}

        for tid, result in summary.results.items():
            if tid in task_map:
                task = task_map[tid]
                task.mark_finished(result.state, result)

        # Check overall state: if all tasks are COMPLETED, scan is COMPLETED
        all_completed = all(t.state == TaskState.COMPLETED for t in state.tasks)
        any_failed = any(
            t.state in (TaskState.FAILED, TaskState.TIMEOUT) for t in state.tasks
        )
        any_cancelled = any(t.state == TaskState.CANCELLED for t in state.tasks)

        if all_completed:
            state.scan.status = ScanStatus.COMPLETED
            state.scan.finished_at = summary.finished_at
        elif any_cancelled:
            state.scan.status = ScanStatus.CANCELLED
            state.scan.finished_at = summary.finished_at
        elif any_failed:
            state.scan.status = ScanStatus.FAILED
            state.scan.finished_at = summary.finished_at
        else:
            state.scan.status = ScanStatus.COMPLETED
            state.scan.finished_at = summary.finished_at

        return state
