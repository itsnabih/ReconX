"""Unit tests for Scheduler, DAG validation, concurrency, and Phase 1 acceptance criteria."""

import asyncio
import sys
import time
import unittest

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import RetryPolicy, Task, TaskState


class TestScheduler(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.runner = CommandRunner(default_timeout=5.0)

    async def test_single_task_execution(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task = Task(
            id="task-single",
            type="dummy",
            command=[sys.executable, "-c", "print('reconx-single')"],
        )
        scheduler.add_task(task)

        summary = await scheduler.run()

        self.assertEqual(summary.total_tasks, 1)
        self.assertEqual(summary.completed, 1)
        self.assertEqual(summary.failed, 0)
        self.assertEqual(summary.skipped, 0)
        self.assertEqual(task.state, TaskState.COMPLETED)
        self.assertIsNotNone(task.result)
        self.assertIsNotNone(task.result.command_result)
        self.assertIn("reconx-single", task.result.command_result.stdout)
        self.assertIsNotNone(task.duration)
        self.assertGreater(task.duration, 0.0)
        self.assertEqual(task.result.duration, task.duration)

    async def test_dependency_order_execution(self) -> None:
        scheduler = Scheduler(runner=self.runner)

        # Using commands to verify sequence
        task_a = Task(
            id="task-a",
            type="step",
            command=[sys.executable, "-c", "import time; time.sleep(0.05); print('A')"],
        )
        task_b = Task(
            id="task-b",
            type="step",
            command=[sys.executable, "-c", "print('B')"],
            dependencies={"task-a"},
        )
        task_c = Task(
            id="task-c",
            type="step",
            command=[sys.executable, "-c", "print('C')"],
            dependencies={"task-b"},
        )

        scheduler.add_tasks([task_c, task_a, task_b])
        summary = await scheduler.run()

        self.assertEqual(summary.completed, 3)
        self.assertLess(task_a.finished_at, task_b.started_at)
        self.assertLess(task_b.finished_at, task_c.started_at)

    async def test_independent_tasks_run_concurrently(self) -> None:
        scheduler = Scheduler(
            runner=self.runner,
            config=SchedulerConfig(global_concurrency=10),
        )

        tasks = [
            Task(
                id=f"t-{i}",
                type="sleep",
                command=[sys.executable, "-c", "import time; time.sleep(0.1)"],
            )
            for i in range(4)
        ]
        scheduler.add_tasks(tasks)

        summary = await scheduler.run()

        self.assertEqual(summary.completed, 4)
        # Running 4 tasks of 0.1s concurrently should take significantly less than 0.35s
        self.assertLess(summary.duration, 0.35)

    async def test_resource_concurrency_bounded(self) -> None:
        config = SchedulerConfig(
            global_concurrency=10,
            resource_concurrency={"dns": 1},
        )
        scheduler = Scheduler(runner=self.runner, config=config)

        # 2 DNS tasks with concurrency 1 will be serialized
        tasks = [
            Task(
                id=f"dns-{i}",
                type="dns",
                resource_class="dns",
                command=[sys.executable, "-c", "import time; time.sleep(0.1)"],
            )
            for i in range(2)
        ]
        scheduler.add_tasks(tasks)

        summary = await scheduler.run()
        self.assertEqual(summary.completed, 2)
        # Serialized 2 * 0.1s => total duration >= 0.18s
        self.assertGreaterEqual(summary.duration, 0.18)

    async def test_failure_propagation_skips_dependents_and_preserves_independents(self) -> None:
        scheduler = Scheduler(runner=self.runner)

        # Task A will fail
        task_a = Task(
            id="task-fail",
            type="dummy",
            command=[sys.executable, "-c", "import sys; sys.exit(1)"],
        )
        # Task B depends on Task A -> should be SKIPPED
        task_b = Task(
            id="task-dependent",
            type="dummy",
            command=[sys.executable, "-c", "print('should not run')"],
            dependencies={"task-fail"},
        )
        # Task C depends on Task B -> should also be SKIPPED
        task_c = Task(
            id="task-sub-dependent",
            type="dummy",
            command=[sys.executable, "-c", "print('should not run either')"],
            dependencies={"task-dependent"},
        )
        # Task D is independent -> should COMPLETE
        task_d = Task(
            id="task-independent",
            type="dummy",
            command=[sys.executable, "-c", "print('independent')"],
        )

        scheduler.add_tasks([task_a, task_b, task_c, task_d])
        summary = await scheduler.run()

        self.assertEqual(summary.failed, 1)
        self.assertEqual(summary.skipped, 2)
        self.assertEqual(summary.completed, 1)

        self.assertEqual(task_a.state, TaskState.FAILED)
        self.assertEqual(task_b.state, TaskState.SKIPPED)
        self.assertEqual(task_c.state, TaskState.SKIPPED)
        self.assertEqual(task_d.state, TaskState.COMPLETED)

    async def test_task_timeout(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task = Task(
            id="task-timeout",
            type="dummy",
            command=[sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=0.1,
            retry_policy=RetryPolicy(max_retries=0),
        )
        scheduler.add_task(task)

        summary = await scheduler.run()

        self.assertEqual(summary.timed_out, 1)
        self.assertEqual(task.state, TaskState.TIMEOUT)
        self.assertTrue(task.result.command_result.timed_out)

    async def test_task_retry_on_failure(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task = Task(
            id="task-retry-exit",
            type="dummy",
            command=[sys.executable, "-c", "import sys; sys.exit(42)"],
            retry_policy=RetryPolicy(
                max_retries=2,
                backoff_factor=0.01,
                retryable_exit_codes=(42,),
            ),
        )
        scheduler.add_task(task)

        summary = await scheduler.run()

        self.assertEqual(summary.failed, 1)
        self.assertEqual(task.state, TaskState.FAILED)
        # 1 initial run + 2 retries = 3 attempts
        self.assertEqual(task.attempts, 3)

    async def test_task_retry_on_timeout(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task = Task(
            id="task-retry-timeout",
            type="dummy",
            command=[sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=0.1,
            retry_policy=RetryPolicy(
                max_retries=1,
                backoff_factor=0.01,
                retry_on_timeout=True,
            ),
        )
        scheduler.add_task(task)

        summary = await scheduler.run()

        self.assertEqual(summary.timed_out, 1)
        self.assertEqual(task.state, TaskState.TIMEOUT)
        self.assertEqual(task.attempts, 2)

    async def test_dag_cycle_detection(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task_a = Task(id="a", type="test", dependencies={"b"})
        task_b = Task(id="b", type="test", dependencies={"a"})

        scheduler.add_tasks([task_a, task_b])

        with self.assertRaises(ValueError) as ctx:
            await scheduler.run()
        self.assertIn("Cyclic dependency", str(ctx.exception))

    async def test_unknown_dependency_detection(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task_a = Task(id="a", type="test", dependencies={"nonexistent_task"})
        scheduler.add_task(task_a)

        with self.assertRaises(ValueError) as ctx:
            await scheduler.run()
        self.assertIn("unknown task", str(ctx.exception))

    async def test_duplicate_task_id_rejected(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        scheduler.add_task(Task(id="dup", type="test"))
        with self.assertRaises(ValueError):
            scheduler.add_task(Task(id="dup", type="test"))

    async def test_cancellation(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        task = Task(
            id="long-running",
            type="dummy",
            command=[sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=10.0,
        )
        scheduler.add_task(task)

        async def cancel_later():
            await asyncio.sleep(0.05)
            scheduler.cancel()

        asyncio.create_task(cancel_later())
        summary = await scheduler.run()

        self.assertEqual(summary.cancelled, 1)
        self.assertEqual(task.state, TaskState.CANCELLED)

    async def test_cancellation_with_active_and_pending_tasks(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        active_task = Task(
            id="active-task",
            type="dummy",
            command=[sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=10.0,
        )
        dependent_task = Task(
            id="dependent-task",
            type="dummy",
            command=[sys.executable, "-c", "print('should not run')"],
            dependencies={"active-task"},
        )
        independent_task = Task(
            id="independent-task",
            type="dummy",
            command=[sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=10.0,
        )

        scheduler.add_tasks([active_task, dependent_task, independent_task])

        async def cancel_later():
            await asyncio.sleep(0.05)
            scheduler.cancel()

        asyncio.create_task(cancel_later())
        summary = await scheduler.run()

        self.assertEqual(summary.total_tasks, 3)
        self.assertEqual(summary.cancelled, 2)
        self.assertEqual(summary.skipped, 1)
        self.assertIn("active-task", summary.results)
        self.assertIn("dependent-task", summary.results)
        self.assertIn("independent-task", summary.results)
        self.assertEqual(active_task.state, TaskState.CANCELLED)
        self.assertEqual(dependent_task.state, TaskState.SKIPPED)
        self.assertEqual(independent_task.state, TaskState.CANCELLED)

    async def test_phase1_acceptance_criteria(self) -> None:
        """Verify explicit Phase 1 acceptance criterion from implementation.md:
        
        'A dummy command can be scheduled, executed, timed out, retried, and recorded.'
        """
        scheduler = Scheduler(runner=self.runner)

        # 1. Scheduled & Executed dummy command
        normal_task = Task(
            id="accept-execute",
            type="dummy",
            command=[sys.executable, "-c", "print('acceptance_executed')"],
        )

        # 2. Timed out & Retried dummy command
        timeout_retry_task = Task(
            id="accept-timeout-retry",
            type="dummy",
            command=[sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=0.1,
            retry_policy=RetryPolicy(
                max_retries=1,
                backoff_factor=0.01,
                retry_on_timeout=True,
            ),
        )

        # 3. Failed & Retried dummy command
        fail_retry_task = Task(
            id="accept-fail-retry",
            type="dummy",
            command=[sys.executable, "-c", "import sys; sys.exit(77)"],
            retry_policy=RetryPolicy(
                max_retries=2,
                backoff_factor=0.01,
                retryable_exit_codes=(77,),
            ),
        )

        scheduler.add_tasks([normal_task, timeout_retry_task, fail_retry_task])
        summary = await scheduler.run()

        # Verify Scheduled & Executed
        self.assertEqual(normal_task.state, TaskState.COMPLETED)
        self.assertIn("acceptance_executed", normal_task.result.command_result.stdout)

        # Verify Timed Out & Retried (2 attempts, state TIMEOUT)
        self.assertEqual(timeout_retry_task.state, TaskState.TIMEOUT)
        self.assertEqual(timeout_retry_task.attempts, 2)
        self.assertTrue(timeout_retry_task.result.command_result.timed_out)

        # Verify Failed & Retried (3 attempts, state FAILED)
        self.assertEqual(fail_retry_task.state, TaskState.FAILED)
        self.assertEqual(fail_retry_task.attempts, 3)

        # Verify Recorded (timings, states, structured command results exist)
        for task in [normal_task, timeout_retry_task, fail_retry_task]:
            self.assertIsNotNone(task.queued_at)
            self.assertIsNotNone(task.started_at)
            self.assertIsNotNone(task.finished_at)
            self.assertIsNotNone(task.duration)
            self.assertIsNotNone(task.result)
            self.assertIn(task.id, summary.results)
            self.assertEqual(summary.results[task.id].duration, task.duration)
            self.assertGreater(summary.results[task.id].duration, 0.0)
