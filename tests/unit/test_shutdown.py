"""Unit tests for Graceful Shutdown Handler (Phase 14 / Section 11/30)."""

from __future__ import annotations

import asyncio
import signal
import unittest

from reconx.core.cancellation import CancellationToken
from reconx.core.shutdown import GracefulShutdownHandler


class TestGracefulShutdownHandler(unittest.IsolatedAsyncioTestCase):
    """Tests for GracefulShutdownHandler."""

    async def test_trigger_shutdown_cancels_token_and_runs_callbacks(self) -> None:
        token = CancellationToken()
        callback_called = False

        def on_shutdown() -> None:
            nonlocal callback_called
            callback_called = True

        handler = GracefulShutdownHandler(cancellation_token=token, on_shutdown=on_shutdown)
        assert token.is_cancelled is False
        assert handler.is_shutting_down is False

        handler.trigger_shutdown(sig=signal.SIGINT)

        assert token.is_cancelled is True
        assert handler.is_shutting_down is True
        assert handler.signal_received == signal.SIGINT
        assert callback_called is True

    async def test_shutdown_handler_async_context_manager(self) -> None:
        token = CancellationToken()
        executed_inside = False

        async with GracefulShutdownHandler(cancellation_token=token) as handler:
            assert handler._registered is True
            executed_inside = True

        assert executed_inside is True
        assert handler._registered is False

    async def test_multiple_callbacks_and_idempotence(self) -> None:
        token = CancellationToken()
        calls: list[int] = []

        handler = GracefulShutdownHandler(cancellation_token=token)
        handler.add_callback(lambda: calls.append(1))
        handler.add_callback(lambda: calls.append(2))

        # First trigger
        handler.trigger_shutdown()
        assert calls == [1, 2]

        # Second trigger should be ignored (idempotent)
        handler.trigger_shutdown()
        assert calls == [1, 2]
