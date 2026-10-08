"""Graceful shutdown and signal handling engine (Phase 14).

Strictly adheres to Phase 14 & Section 11/30 of Implementation.md:
- Graceful shutdown upon SIGINT (Ctrl+C) and SIGTERM
- Interruption management preventing zombie subprocesses
- State checkpointing callback support before process exit
- Safe restoration of system signal handlers
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import logging
import signal
from typing import Any

from reconx.core.cancellation import CancellationToken

logger = logging.getLogger("reconx.core.shutdown")


class GracefulShutdownHandler:
    """Manages cooperative process shutdown and signal handling during scans."""

    def __init__(
        self,
        cancellation_token: CancellationToken | None = None,
        on_shutdown: Callable[[], Any] | None = None,
    ) -> None:
        self.cancellation_token = cancellation_token or CancellationToken()
        self._on_shutdown_callbacks: list[Callable[[], Any]] = []
        if on_shutdown is not None:
            self._on_shutdown_callbacks.append(on_shutdown)

        self.is_shutting_down: bool = False
        self.signal_received: int | None = None
        self._registered: bool = False
        self._previous_handlers: dict[int, Any] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def add_callback(self, callback: Callable[[], Any]) -> None:
        """Register a callback to run when shutdown is triggered."""
        self._on_shutdown_callbacks.append(callback)

    def trigger_shutdown(self, sig: int | None = None) -> None:
        """Programmatically trigger graceful shutdown."""
        if self.is_shutting_down:
            return

        self.is_shutting_down = True
        self.signal_received = sig
        sig_name = signal.Signals(sig).name if sig else "MANUAL"
        logger.warning(
            "Graceful shutdown initiated (signal: %s). Cancelling active tasks...", sig_name
        )

        # 1. Trigger cooperative cancellation
        self.cancellation_token.cancel()

        # 2. Execute registered shutdown callbacks
        for callback in self._on_shutdown_callbacks:
            try:
                res = callback()
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception as exc:
                logger.error("Error executing shutdown callback: %s", exc)

    def register(self) -> None:
        """Attach signal handlers to current event loop or process."""
        if self._registered:
            return

        signals_to_handle = (signal.SIGINT, signal.SIGTERM)

        try:
            self._loop = asyncio.get_running_loop()
            for sig in signals_to_handle:
                # Use loop signal handler for async loops
                try:
                    self._loop.add_signal_handler(sig, self._handle_signal, sig)
                except (NotImplementedError, RuntimeError):
                    # Fallback for environments where add_signal_handler is not implemented
                    self._register_standard_signal(sig)
        except RuntimeError:
            # No running event loop, use standard signal module
            for sig in signals_to_handle:
                self._register_standard_signal(sig)

        self._registered = True

    def _register_standard_signal(self, sig: int) -> None:
        try:
            prev = signal.signal(sig, lambda s, f: self.trigger_shutdown(s))
            self._previous_handlers[sig] = prev
        except (ValueError, AttributeError):
            pass

    def _handle_signal(self, sig: int) -> None:
        self.trigger_shutdown(sig)

    def restore(self) -> None:
        """Restore original signal handlers."""
        if not self._registered:
            return

        signals_to_handle = (signal.SIGINT, signal.SIGTERM)

        if self._loop and not self._loop.is_closed():
            for sig in signals_to_handle:
                try:
                    self._loop.remove_signal_handler(sig)
                except (NotImplementedError, RuntimeError):
                    pass

        for sig, prev in self._previous_handlers.items():
            try:
                signal.signal(sig, prev)
            except (ValueError, AttributeError):
                pass

        self._previous_handlers.clear()
        self._registered = False

    async def __aenter__(self) -> GracefulShutdownHandler:
        self.register()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.restore()

    def __enter__(self) -> GracefulShutdownHandler:
        self.register()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.restore()
