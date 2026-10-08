"""Cancellation tokens and listener mechanisms for cooperative cancellation."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

logger = logging.getLogger(__name__)

class CancellationToken:
    """Manages cooperative cancellation for asynchronous tasks, scheduler, and processes."""

    def __init__(self, parent: CancellationToken | None = None) -> None:
        self._is_cancelled: bool = False
        self._callbacks: list[Callable[[], None]] = []
        self._parent: CancellationToken | None = parent
        if parent is not None:
            parent.register_callback(self.cancel)

    @property
    def is_cancelled(self) -> bool:
        """Return True if this token or its parent has been cancelled."""
        return self._is_cancelled or (self._parent is not None and self._parent.is_cancelled)

    def cancel(self) -> None:
        """Trigger cancellation and invoke all registered callbacks."""
        if self._is_cancelled:
            return
        self._is_cancelled = True
        for callback in list(self._callbacks):
            try:
                callback()
            except Exception as exc:
                # Callbacks must not prevent other callbacks from executing
                logger.error("Error in cancellation callback: %s", exc)

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to be called upon cancellation.
        
        If already cancelled, invokes callback immediately.
        """
        if self.is_cancelled:
            try:
                callback()
            except Exception as exc:
                logger.error("Error in immediate cancellation callback: %s", exc)
            return
        self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[], None]) -> None:
        """Remove a previously registered callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def raise_if_cancelled(self) -> None:
        """Raise asyncio.CancelledError if cancellation has been requested."""
        if self.is_cancelled:
            raise asyncio.CancelledError("Operation was cancelled via CancellationToken")

    def create_child(self) -> CancellationToken:
        """Create a child token that cancels whenever this token is cancelled."""
        return CancellationToken(parent=self)
