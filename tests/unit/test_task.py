"""Unit tests for Task, TaskState, RetryPolicy, and TaskResult."""

from datetime import datetime, timezone
import time
import unittest

from reconx.core.task import RetryPolicy, Task, TaskResult, TaskState


class TestTaskModel(unittest.TestCase):
    def test_task_initialization(self) -> None:
        task = Task(
            id="task-1",
            type="dns",
            target="example.com",
            command=["dig", "example.com"],
            dependencies={"init-task"},
            priority=10,
            timeout=15.0,
            resource_class="dns",
        )

        self.assertEqual(task.id, "task-1")
        self.assertEqual(task.type, "dns")
        self.assertEqual(task.target, "example.com")
        self.assertEqual(task.dependencies, {"init-task"})
        self.assertEqual(task.priority, 10)
        self.assertEqual(task.timeout, 15.0)
        self.assertEqual(task.resource_class, "dns")
        self.assertEqual(task.state, TaskState.PENDING)
        self.assertFalse(task.is_terminal)
        self.assertFalse(task.is_successful)

    def test_state_lifecycle_transitions(self) -> None:
        task = Task(id="t-lifecycle", type="test")
        self.assertEqual(task.state, TaskState.PENDING)

        task.mark_queued()
        self.assertEqual(task.state, TaskState.PENDING)
        self.assertIsNotNone(task.queued_at)

        task.mark_ready()
        self.assertEqual(task.state, TaskState.READY)

        task.mark_running()
        self.assertEqual(task.state, TaskState.RUNNING)
        self.assertIsNotNone(task.started_at)

        time.sleep(0.01)
        res = TaskResult(task_id=task.id, state=TaskState.COMPLETED)
        task.mark_finished(TaskState.COMPLETED, res)

        self.assertEqual(task.state, TaskState.COMPLETED)
        self.assertTrue(task.is_terminal)
        self.assertTrue(task.is_successful)
        self.assertIsNotNone(task.finished_at)
        self.assertGreater(task.duration, 0.0)

    def test_retry_policy_logic(self) -> None:
        # Default: 0 retries
        policy = RetryPolicy()
        self.assertFalse(policy.should_retry(attempt=1, exit_code=1, timed_out=False))

        # Max retries = 2, retry on timeout
        timeout_policy = RetryPolicy(max_retries=2, retry_on_timeout=True)
        self.assertTrue(timeout_policy.should_retry(attempt=1, exit_code=None, timed_out=True))
        self.assertTrue(timeout_policy.should_retry(attempt=2, exit_code=None, timed_out=True))
        self.assertFalse(timeout_policy.should_retry(attempt=3, exit_code=None, timed_out=True))

        # Retry on specific exit codes
        exit_code_policy = RetryPolicy(
            max_retries=2,
            retryable_exit_codes=(1, 111),
            retry_on_timeout=False,
        )
        self.assertTrue(exit_code_policy.should_retry(attempt=1, exit_code=1, timed_out=False))
        self.assertTrue(exit_code_policy.should_retry(attempt=1, exit_code=111, timed_out=False))
        self.assertFalse(exit_code_policy.should_retry(attempt=1, exit_code=2, timed_out=False))
        self.assertFalse(exit_code_policy.should_retry(attempt=1, exit_code=None, timed_out=True))
