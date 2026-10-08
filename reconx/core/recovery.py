"""Error recovery taxonomy and fault tolerance engine (Phase 14).

Strictly adheres to Section 30 of Implementation.md:
- A failed tool must not terminate the entire scan
- Error classification into transient vs degraded vs critical
- Safe recovery of failed tasks with structured error capture
- State checkpointing to guard against mid-execution crashes
"""

from __future__ import annotations

from enum import Enum
import logging
from typing import TYPE_CHECKING, Any

from reconx.core.task import Task, TaskResult, TaskState

if TYPE_CHECKING:
    from reconx.models.scan import ScanState
    from reconx.session.manager import ScanSessionManager

logger = logging.getLogger("reconx.core.recovery")


class ReconXError(Exception):
    """Base exception for all ReconX operational errors."""


class SecurityError(ReconXError):
    """Scope violation, unauthorized target, or injection attempt."""


class ToolExecutionError(ReconXError):
    """External tool binary crashed, exited with unexpected code, or not available."""


class ParserError(ReconXError):
    """Malformed or corrupt output from external tool that failed parsing."""


class DatabaseError(ReconXError):
    """SQLite transaction failure, constraint violation, or persistence error."""


class NetworkTimeoutError(ReconXError):
    """External network or tool probe exceeded designated timeout."""


class ErrorSeverity(str, Enum):
    """Classification of operational failure severity."""

    TRANSIENT = "TRANSIENT"  # Can be retried (e.g. temporary network blip)
    DEGRADED = "DEGRADED"    # Tool failed, but independent tasks can continue (Section 30)
    CRITICAL = "CRITICAL"    # System or security failure requiring scan abortion


class RecoveryAction(str, Enum):
    """Designated recovery action per Section 30."""

    RETRY = "RETRY"
    SKIP_DEPENDENTS = "SKIP_DEPENDENTS"
    FALLBACK = "FALLBACK"
    ABORT = "ABORT"


class ErrorRecoveryEngine:
    """Classifies errors and guides graceful degradation during scan runs."""

    @classmethod
    def classify_error(cls, exc: Exception) -> tuple[ErrorSeverity, RecoveryAction]:
        """Classify an exception and determine the appropriate recovery action."""
        if isinstance(exc, SecurityError):
            return ErrorSeverity.CRITICAL, RecoveryAction.ABORT

        if isinstance(exc, (TimeoutError, NetworkTimeoutError)):
            return ErrorSeverity.TRANSIENT, RecoveryAction.RETRY

        if isinstance(exc, (ToolExecutionError, ParserError)):
            # Per Section 30: tool failure degrades pipeline; skip dependent tasks but continue scan
            return ErrorSeverity.DEGRADED, RecoveryAction.SKIP_DEPENDENTS

        if isinstance(exc, DatabaseError):
            return ErrorSeverity.CRITICAL, RecoveryAction.ABORT

        # Generic / unexpected exception
        return ErrorSeverity.DEGRADED, RecoveryAction.SKIP_DEPENDENTS

    @classmethod
    def safely_recover_task(cls, task: Task, exc: Exception) -> TaskResult:
        """Handle an uncaught task exception and construct a safe TaskResult."""
        severity, action = cls.classify_error(exc)
        err_msg = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "Task '%s' encountered %s error: %s. Action: %s",
            task.id,
            severity.value,
            err_msg,
            action.value,
        )

        state = TaskState.TIMEOUT if isinstance(exc, (TimeoutError, NetworkTimeoutError)) else TaskState.FAILED
        result = TaskResult(
            task_id=task.id,
            state=state,
            error_message=err_msg,
            attempts=task.attempts,
        )
        task.mark_finished(state, result)
        return result

    @classmethod
    def checkpoint_scan_state(
        cls,
        manager: ScanSessionManager,
        state: ScanState,
    ) -> bool:
        """Safely checkpoint current scan state into the SQLite session database.

        Returns True if checkpoint was saved successfully, False otherwise.
        """
        try:
            manager.save_session(state)
            logger.debug("Successfully checkpointed scan '%s' to database", state.scan.id)
            return True
        except Exception as exc:
            logger.error("Failed to checkpoint scan '%s': %s", state.scan.id, exc)
            return False
