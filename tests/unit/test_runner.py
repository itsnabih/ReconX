"""Unit tests for CommandRunner and CommandResult."""

import asyncio
import sys
import unittest

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner


class TestCommandRunner(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.runner = CommandRunner(default_timeout=5.0)

    def test_tool_availability(self) -> None:
        self.assertTrue(CommandRunner.is_available("python3"))
        self.assertFalse(CommandRunner.is_available("nonexistent_binary_xyz_456"))

    def test_resolve_executable(self) -> None:
        path = CommandRunner.resolve_executable("python3")
        self.assertIsNotNone(path)
        self.assertIsNone(CommandRunner.resolve_executable("nonexistent_binary_xyz_456"))

    async def test_empty_command_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            await self.runner.run([])

    async def test_successful_command(self) -> None:
        cmd = [sys.executable, "-c", "print('hello from reconx')"]
        result = await self.runner.run(cmd)

        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello from reconx", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertFalse(result.timed_out)
        self.assertFalse(result.cancelled)
        self.assertGreater(result.duration, 0.0)

    async def test_nonzero_exit_code(self) -> None:
        cmd = [sys.executable, "-c", "import sys; sys.stderr.write('fatal error'); sys.exit(42)"]
        result = await self.runner.run(cmd)

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 42)
        self.assertIn("fatal error", result.stderr)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.cancelled)

    async def test_timeout_enforcement(self) -> None:
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
        result = await self.runner.run(cmd, timeout=0.2)

        self.assertFalse(result.success)
        self.assertTrue(result.timed_out)
        self.assertIn("timed out", (result.error or "").lower())
        self.assertGreaterEqual(result.duration, 0.15)


    async def test_pre_cancelled_execution(self) -> None:
        token = CancellationToken()
        token.cancel()

        cmd = [sys.executable, "-c", "print('should not execute')"]
        result = await self.runner.run(cmd, cancellation_token=token)

        self.assertFalse(result.success)
        self.assertTrue(result.cancelled)
        self.assertIsNone(result.exit_code)

    async def test_cancellation_during_execution(self) -> None:
        token = CancellationToken()

        async def cancel_later() -> None:
            await asyncio.sleep(0.1)
            token.cancel()

        asyncio.create_task(cancel_later())

        cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
        result = await self.runner.run(cmd, timeout=5.0, cancellation_token=token)

        self.assertFalse(result.success)
        self.assertTrue(result.cancelled)

    async def test_missing_executable(self) -> None:
        cmd = ["nonexistent_tool_12345", "--arg"]
        result = await self.runner.run(cmd)

        self.assertFalse(result.success)
        self.assertIsNone(result.exit_code)
        self.assertIn("not found in PATH", result.error or "")

    async def test_output_capping(self) -> None:
        runner = CommandRunner(max_output_bytes=100)
        cmd = [sys.executable, "-c", "print('A' * 500)"]
        result = await runner.run(cmd)

        self.assertTrue(result.success)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 100)
