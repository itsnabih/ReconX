"""Phase 2 acceptance: an out-of-scope target can never reach CommandRunner."""

import sys
import unittest
from collections.abc import Sequence

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler
from reconx.core.task import Task, TaskResult, TaskState
from reconx.scope import ScopeValidator


class RecordingRunner(CommandRunner):
    """Real runner that records every command it is asked to execute."""

    def __init__(self) -> None:
        super().__init__(default_timeout=5.0)
        self.calls: list[list[str]] = []

    async def run(self, command: Sequence[str], **kwargs) -> CommandResult:
        self.calls.append(list(command))
        return await super().run(command, **kwargs)


def echo_task(task_id: str, target: str, **kwargs) -> Task:
    return Task(
        id=task_id,
        type="dummy",
        target=target,
        command=[sys.executable, "-c", f"print({target!r})"],
        **kwargs,
    )


class TestSchedulerScopeEnforcement(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.runner = RecordingRunner()
        self.scope = ScopeValidator(
            allowed_domains=["example.com", "*.example.com"],
            allowed_ips=["192.0.2.0/24"],
            excluded_domains=["payment.example.com"],
            excluded_ips=["192.0.2.50"],
        )

    async def test_out_of_scope_targets_never_reach_runner(self) -> None:
        scheduler = Scheduler(runner=self.runner, scope=self.scope)
        rejected = {
            "out-domain": "evil.net",
            "out-ip": "198.51.100.7",
            "excluded-domain": "payment.example.com",
            "excluded-ip": "192.0.2.50",
            "injection": "example.com; id",
            "option": "-oX/tmp/x",
            "cidr": "192.0.2.0/24",
        }
        scheduler.add_tasks([echo_task(tid, target) for tid, target in rejected.items()])
        summary = await scheduler.run()

        self.assertEqual(self.runner.calls, [])
        self.assertEqual(summary.skipped, len(rejected))
        for tid in rejected:
            result = summary.results[tid]
            self.assertEqual(result.state, TaskState.SKIPPED)
            self.assertIn("out of scope", result.error_message or "")
            self.assertIsNone(result.command_result)

    async def test_in_scope_target_reaches_runner(self) -> None:
        scheduler = Scheduler(runner=self.runner, scope=self.scope)
        task = echo_task("in-scope", "www.example.com")
        scheduler.add_task(task)
        summary = await scheduler.run()

        self.assertEqual(summary.completed, 1)
        self.assertEqual(len(self.runner.calls), 1)
        self.assertIn("www.example.com", task.result.command_result.stdout)

    async def test_mixed_tasks_only_in_scope_execute(self) -> None:
        scheduler = Scheduler(runner=self.runner, scope=self.scope)
        scheduler.add_tasks([echo_task("ok", "192.0.2.10"), echo_task("bad", "evil.net")])
        summary = await scheduler.run()

        self.assertEqual(summary.completed, 1)
        self.assertEqual(summary.skipped, 1)
        self.assertEqual(len(self.runner.calls), 1)
        self.assertIn("192.0.2.10", self.runner.calls[0][-1])

    async def test_targeted_task_without_scope_is_rejected(self) -> None:
        scheduler = Scheduler(runner=self.runner)
        scheduler.add_task(echo_task("no-scope", "example.com"))
        summary = await scheduler.run()

        self.assertEqual(self.runner.calls, [])
        self.assertEqual(summary.skipped, 1)
        self.assertIn("no scope configured", summary.results["no-scope"].error_message or "")

    async def test_dependents_of_rejected_task_are_skipped(self) -> None:
        scheduler = Scheduler(runner=self.runner, scope=self.scope)
        scheduler.add_tasks([
            echo_task("parent", "evil.net"),
            echo_task("child", "www.example.com", dependencies={"parent"}),
        ])
        summary = await scheduler.run()

        self.assertEqual(self.runner.calls, [])
        self.assertEqual(summary.skipped, 2)
        self.assertIn("Prerequisite 'parent'", summary.results["child"].error_message or "")

    async def test_action_task_with_out_of_scope_target_is_not_invoked(self) -> None:
        invoked = False

        async def action(task: Task, runner: CommandRunner, token: CancellationToken) -> TaskResult:
            nonlocal invoked
            invoked = True
            return TaskResult(task_id=task.id, state=TaskState.COMPLETED)

        scheduler = Scheduler(runner=self.runner, scope=self.scope)
        scheduler.add_task(Task(id="action", type="dummy", target="evil.net", action=action))
        summary = await scheduler.run()

        self.assertFalse(invoked)
        self.assertEqual(summary.results["action"].state, TaskState.SKIPPED)
