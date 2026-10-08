"""Unit tests for Error Recovery and Taxonomy (Phase 14 / Section 30)."""

from __future__ import annotations

from pathlib import Path
import unittest

from reconx.core.recovery import (
    DatabaseError,
    ErrorRecoveryEngine,
    ErrorSeverity,
    NetworkTimeoutError,
    ParserError,
    ReconXError,
    RecoveryAction,
    SecurityError,
    ToolExecutionError,
)
from reconx.core.task import Task, TaskState
from reconx.session.manager import ScanSessionManager


class TestErrorRecoveryEngine(unittest.TestCase):
    """Tests for exception classification and recovery decisions."""

    def test_exception_hierarchy(self) -> None:
        assert issubclass(SecurityError, ReconXError)
        assert issubclass(ToolExecutionError, ReconXError)
        assert issubclass(ParserError, ReconXError)
        assert issubclass(DatabaseError, ReconXError)
        assert issubclass(NetworkTimeoutError, ReconXError)

    def test_classify_error_rules(self) -> None:
        # Security violation -> Critical / Abort
        sev, act = ErrorRecoveryEngine.classify_error(SecurityError("Out of scope"))
        assert sev == ErrorSeverity.CRITICAL
        assert act == RecoveryAction.ABORT

        # Network timeout -> Transient / Retry
        sev, act = ErrorRecoveryEngine.classify_error(NetworkTimeoutError("Port probe timed out"))
        assert sev == ErrorSeverity.TRANSIENT
        assert act == RecoveryAction.RETRY

        # Tool failure -> Degraded / Skip Dependents (Section 30)
        sev, act = ErrorRecoveryEngine.classify_error(ToolExecutionError("Nmap exited with code 1"))
        assert sev == ErrorSeverity.DEGRADED
        assert act == RecoveryAction.SKIP_DEPENDENTS

        # Parser failure -> Degraded / Skip Dependents
        sev, act = ErrorRecoveryEngine.classify_error(ParserError("XML corrupted"))
        assert sev == ErrorSeverity.DEGRADED
        assert act == RecoveryAction.SKIP_DEPENDENTS

    def test_safely_recover_task(self) -> None:
        task = Task(id="task_fail", type="nmap", target="192.168.1.1")
        exc = ToolExecutionError("Process terminated by signal")

        res = ErrorRecoveryEngine.safely_recover_task(task, exc)
        assert res.state == TaskState.FAILED
        assert task.state == TaskState.FAILED
        assert "ToolExecutionError" in (res.error_message or "")
        assert task.is_terminal is True

    def test_checkpoint_scan_state(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_checkpoint.db"
            manager = ScanSessionManager(db_path)

            state = manager.create_session(targets=["example.com"])
            state.tasks.append(Task(id="t1", type="dns", target="example.com"))

            success = ErrorRecoveryEngine.checkpoint_scan_state(manager, state)
            assert success is True

            loaded = manager.load_session(state.scan.id)
            assert loaded is not None
            assert len(loaded.tasks) == 1
