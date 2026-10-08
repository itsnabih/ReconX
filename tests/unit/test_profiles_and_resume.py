"""Unit tests for Scan Profiles, Persistent Sessions, and Resume Engine (Phase 12)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import pytest

from reconx.config.profiles import (
    ProfileLoader,
    ScanProfile,
    load_profile,
)
from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import RetryPolicy, Task, TaskResult, TaskState
from reconx.models.scan import Scan, ScanState, ScanStatus
from reconx.scope.models import ScopePolicy
from reconx.session.manager import ScanSessionManager
from reconx.session.resume import ResumeEngine, ResumePlan
from reconx.storage.repository import ScanNotFoundError


class DummyRunner(CommandRunner):
    """Deterministic command runner for testing resumption without external processes."""

    def __init__(self, outcomes: dict[str, tuple[int, str, str]] | None = None) -> None:
        super().__init__()
        self.outcomes = outcomes or {}
        self.executed_commands: list[list[str]] = []

    async def run(
        self,
        command: list[str],
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        self.executed_commands.append(list(command))
        cmd_key = " ".join(command)
        exit_code, stdout, stderr = self.outcomes.get(cmd_key, (0, "ok", ""))
        return CommandResult(
            command=list(command),
            executable=command[0],
            arguments=list(command[1:]),
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            duration=0.01,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            cancelled=False,
        )


# =============================================================================
# 1. PROFILE TESTS
# =============================================================================

class TestScanProfiles:
    """Tests for Profile definitions, YAML loading, and priority hierarchy."""

    def test_default_profile_attributes(self) -> None:
        profile = ProfileLoader.get_default_profile()
        assert profile.name == "default"
        assert profile.mode == "active"
        assert profile.is_module_enabled("dns") is True
        assert profile.is_module_enabled("network") is True
        assert profile.is_module_enabled("http") is True
        assert profile.is_module_enabled("nikto") is False
        assert profile.get_concurrency("global") == 10
        assert profile.get_timeout("default") == 30.0

    def test_builtin_profiles_discovery(self) -> None:
        available = ProfileLoader.list_available_profiles()
        assert "quick" in available
        assert "passive" in available
        assert "network" in available
        assert "web" in available
        assert "full" in available

    def test_load_all_builtin_profiles(self) -> None:
        for name in ("quick", "passive", "network", "web", "full"):
            profile = load_profile(name)
            assert profile.name == name
            assert profile.mode in ("safe", "passive", "active")
            assert isinstance(profile.modules, dict)
            assert isinstance(profile.concurrency, dict)
            assert isinstance(profile.timeouts, dict)

    def test_quick_profile_characteristics(self) -> None:
        quick = load_profile("quick")
        assert quick.is_module_enabled("dns") is True
        assert quick.is_module_enabled("network") is True
        assert quick.is_module_enabled("nikto") is False
        assert quick.get_concurrency("global") == 15
        assert quick.get_timeout("default") == 10.0

    def test_passive_profile_characteristics(self) -> None:
        passive = load_profile("passive")
        assert passive.mode == "passive"
        assert passive.is_module_enabled("dns") is True
        assert passive.is_module_enabled("network") is False
        assert passive.is_module_enabled("http") is False

    def test_web_profile_characteristics(self) -> None:
        web = load_profile("web")
        assert web.is_module_enabled("dns") is True
        assert web.is_module_enabled("network") is False
        assert web.is_module_enabled("http") is True
        assert web.is_module_enabled("tls") is True
        assert web.is_module_enabled("directory") is True
        assert web.is_module_enabled("nikto") is True
        assert web.is_module_enabled("sqlmap") is False
        assert web.get_concurrency("global") == 12

    def test_full_profile_characteristics(self) -> None:
        full = load_profile("full")
        assert full.is_module_enabled("dns") is True
        assert full.is_module_enabled("network") is True
        assert full.is_module_enabled("http") is True
        assert full.is_module_enabled("nikto") is True
        assert full.is_module_enabled("sqlmap") is True
        assert full.get_concurrency("global") == 20

    def test_priority_hierarchy_defaults_to_profile_to_cli(self) -> None:
        """Verify: defaults -> profile -> CLI arguments."""
        # 1. Defaults: nikto is False, concurrency global is 10
        default_prof = load_profile("default")
        assert default_prof.is_module_enabled("nikto") is False
        assert default_prof.get_concurrency("global") == 10

        # 2. Profile "web": nikto is True, concurrency global is 12
        web_prof = load_profile("web")
        assert web_prof.is_module_enabled("nikto") is True
        assert web_prof.get_concurrency("global") == 12

        # 3. CLI arguments override: disable nikto, change concurrency to 5
        cli_overrides = {
            "disable_modules": ["nikto"],
            "concurrency": 5,
            "mode": "safe",
        }
        res_prof = load_profile("web", cli_overrides=cli_overrides)
        assert res_prof.is_module_enabled("nikto") is False
        assert res_prof.get_concurrency("global") == 5
        assert res_prof.mode == "safe"
        # Non-overridden values remain intact from profile
        assert res_prof.is_module_enabled("directory") is True
        assert res_prof.is_module_enabled("http") is True

    def test_cli_overrides_enable_modules(self) -> None:
        profile = load_profile("passive", cli_overrides={"enable_modules": ["http", "tls"]})
        assert profile.is_module_enabled("http") is True
        assert profile.is_module_enabled("tls") is True
        assert profile.is_module_enabled("network") is False

    def test_cli_overrides_timeouts(self) -> None:
        profile = load_profile("quick", cli_overrides={"timeout": 45.0})
        assert profile.get_timeout("default") == 45.0

    def test_custom_yaml_file_loading(self, tmp_path: Path) -> None:
        yaml_content = """
name: custom-sec
mode: active
modules:
  dns: true
  network: false
  http: true
concurrency:
  global: 7
timeouts:
  default: 25.0
"""
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        profile = ProfileLoader.load(str(yaml_file))
        assert profile.name == "custom-sec"
        assert profile.get_concurrency("global") == 7
        assert profile.get_timeout("default") == 25.0
        assert profile.is_module_enabled("http") is True

    def test_invalid_profile_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid profile mode"):
            ScanProfile(name="bad", mode="destructive")

    def test_invalid_concurrency_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a positive integer"):
            ScanProfile(name="bad", concurrency={"global": 0})

    def test_nonexistent_profile_raises(self) -> None:
        with pytest.raises(ValueError, match="Profile 'unknown_xyz' not found"):
            load_profile("unknown_xyz")

    def test_to_scheduler_config_conversion(self) -> None:
        profile = load_profile("web")
        sched_config = profile.to_scheduler_config()
        assert sched_config.global_concurrency == 12
        assert sched_config.resource_concurrency["http"] == 10
        assert sched_config.default_timeout == 30.0


# =============================================================================
# 2. PERSISTENT SCAN SESSIONS TESTS
# =============================================================================

class TestScanSessionManager:
    """Tests for ScanSessionManager persistent sessions backed by SQLite."""

    @pytest.fixture
    def session_mgr(self, tmp_path: Path) -> ScanSessionManager:
        db_path = tmp_path / "reconx_test.db"
        return ScanSessionManager(db_path)

    def test_create_and_load_session(self, session_mgr: ScanSessionManager) -> None:
        scope = ScopePolicy(allowed_domains=("example.com",))
        state = session_mgr.create_session(
            targets=["example.com"],
            scope=scope,
            scan_id="scan-20261008-test01",
        )
        assert state.scan.id == "scan-20261008-test01"
        assert state.scan.status == ScanStatus.PENDING

        loaded = session_mgr.load_session("scan-20261008-test01")
        assert loaded.scan.id == "scan-20261008-test01"
        assert loaded.scan.targets == ("example.com",)
        assert loaded.scan.status == ScanStatus.PENDING

    def test_list_sessions(self, session_mgr: ScanSessionManager) -> None:
        session_mgr.create_session(["alpha.com"], scan_id="scan-1")
        session_mgr.create_session(["beta.com"], scan_id="scan-2")

        sessions = session_mgr.list_sessions()
        assert len(sessions) == 2
        ids = [s["id"] for s in sessions]
        assert "scan-1" in ids
        assert "scan-2" in ids

    def test_session_exists_and_delete(self, session_mgr: ScanSessionManager) -> None:
        session_mgr.create_session(["example.com"], scan_id="scan-del")
        assert session_mgr.session_exists("scan-del") is True

        deleted = session_mgr.delete_session("scan-del")
        assert deleted is True
        assert session_mgr.session_exists("scan-del") is False

    def test_load_nonexistent_session_raises(self, session_mgr: ScanSessionManager) -> None:
        with pytest.raises(ScanNotFoundError):
            session_mgr.load_session("nonexistent-id")


# =============================================================================
# 3. RESUME LOGIC TESTS
# =============================================================================

class TestResumeLogic:
    """Tests for Section 25 state transitions and DAG reconstruction."""

    def test_section_25_state_transitions(self) -> None:
        """Verify all six transitions:
        COMPLETED → skip
        FAILED → retry according to policy
        TIMEOUT → retry
        CANCELLED → retry
        RUNNING → recover safely
        PENDING → execute
        """
        scan = Scan(id="scan-resume-test", targets=["example.com"], scope=ScopePolicy(allowed_domains=("example.com",)))

        task_completed = Task(id="t_completed", type="dns", command=["echo", "done"], state=TaskState.COMPLETED)
        task_completed.mark_finished(TaskState.COMPLETED, TaskResult(task_id="t_completed", state=TaskState.COMPLETED))

        task_running = Task(id="t_running", type="http", command=["echo", "running"], state=TaskState.RUNNING)
        task_running.mark_running()

        task_failed = Task(
            id="t_failed",
            type="net",
            command=["echo", "failed"],
            state=TaskState.FAILED,
            attempts=1,
            retry_policy=RetryPolicy(max_retries=2),
        )
        task_failed.mark_finished(TaskState.FAILED, TaskResult(task_id="t_failed", state=TaskState.FAILED))

        task_timeout = Task(id="t_timeout", type="ssl", command=["echo", "timeout"], state=TaskState.TIMEOUT)
        task_timeout.mark_finished(TaskState.TIMEOUT, TaskResult(task_id="t_timeout", state=TaskState.TIMEOUT))

        task_cancelled = Task(id="t_cancelled", type="dir", command=["echo", "cancel"], state=TaskState.CANCELLED)
        task_cancelled.mark_finished(TaskState.CANCELLED, TaskResult(task_id="t_cancelled", state=TaskState.CANCELLED))

        task_pending = Task(id="t_pending", type="vuln", command=["echo", "pending"], state=TaskState.PENDING)

        state = ScanState(
            scan=scan,
            tasks=[
                task_completed,
                task_running,
                task_failed,
                task_timeout,
                task_cancelled,
                task_pending,
            ],
        )

        plan = ResumeEngine.prepare_resume(state)

        # 1. COMPLETED → skip
        assert task_completed in plan.skipped_tasks
        assert task_completed not in plan.executable_tasks

        # 2. RUNNING → recover safely (reset to PENDING)
        assert task_running in plan.recovered_tasks
        assert task_running in plan.executable_tasks
        assert task_running.state == TaskState.PENDING
        assert task_running.started_at is None
        assert task_running.result is None

        # 3. FAILED, TIMEOUT, CANCELLED → retry
        assert task_failed in plan.retried_tasks
        assert task_failed.state == TaskState.PENDING
        assert task_timeout in plan.retried_tasks
        assert task_timeout.state == TaskState.PENDING
        assert task_cancelled in plan.retried_tasks
        assert task_cancelled.state == TaskState.PENDING

        # 4. PENDING → execute
        assert task_pending in plan.pending_tasks
        assert task_pending in plan.executable_tasks

        # Total executable: running (1) + failed (1) + timeout (1) + cancelled (1) + pending (1) = 5
        assert len(plan.executable_tasks) == 5
        assert len(plan.skipped_tasks) == 1

    def test_failed_task_unretryable_when_max_retries_exceeded(self) -> None:
        """When respect_max_retries is enabled, tasks that exhausted retries remain unretryable."""
        scan = Scan(id="scan-retries", targets=["example.com"], scope=ScopePolicy(allowed_domains=("example.com",)))
        exhausted_task = Task(
            id="t_exhausted",
            type="net",
            command=["echo", "fail"],
            state=TaskState.FAILED,
            attempts=3,
            retry_policy=RetryPolicy(max_retries=2),
        )
        state = ScanState(scan=scan, tasks=[exhausted_task])

        plan = ResumeEngine.prepare_resume(
            state, force_retry_failed=False, respect_max_retries=True
        )
        assert len(plan.unretryable_tasks) == 1
        assert exhausted_task in plan.unretryable_tasks
        assert len(plan.executable_tasks) == 0

    def test_dag_prerequisites_satisfied_on_resume(self) -> None:
        """When task B depends on completed task A, task A is stripped from dependencies."""
        scan = Scan(id="scan-dag", targets=["example.com"], scope=ScopePolicy(allowed_domains=("example.com",)))

        task_a = Task(id="task_a", type="dns", command=["echo", "A"], state=TaskState.COMPLETED)
        task_b = Task(id="task_b", type="http", command=["echo", "B"], dependencies={"task_a"}, state=TaskState.PENDING)
        task_c = Task(id="task_c", type="nikto", command=["echo", "C"], dependencies={"task_b"}, state=TaskState.PENDING)

        state = ScanState(scan=scan, tasks=[task_a, task_b, task_c])

        plan = ResumeEngine.prepare_resume(state)

        # task_a is skipped
        assert task_a in plan.skipped_tasks

        # task_b had task_a as dependency; now task_a is stripped because it was COMPLETED
        assert "task_a" in plan.satisfied_dependencies["task_b"]
        assert task_b.dependencies == set()

        # task_c still depends on task_b because task_b is pending
        assert task_c.dependencies == {"task_b"}

        # Graph is valid and can be instantiated into Scheduler
        scheduler = ResumeEngine.create_scheduler(plan)
        assert len(scheduler._tasks) == 2
        assert "task_b" in scheduler._tasks
        assert "task_c" in scheduler._tasks


# =============================================================================
# 4. ACCEPTANCE CRITERIA TEST
# =============================================================================

class TestPhase12AcceptanceCriteria(unittest.IsolatedAsyncioTestCase):
    """Acceptance: An interrupted scan can continue without unnecessarily repeating completed tasks."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "acceptance_scan.db"

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_interrupted_scan_resumes_without_repeating_completed_tasks(self) -> None:
        session_mgr = ScanSessionManager(self.db_path)

        # 1. Setup scan session with 3 tasks in a pipeline:
        # Task 1 (DNS discovery) -> Task 2 (HTTP probe, depends on 1) -> Task 3 (Dir enum, depends on 2)
        scope = ScopePolicy(allowed_domains=("example.com",))
        state = session_mgr.create_session(
            targets=["example.com"],
            scope=scope,
            scan_id="scan-acceptance-01",
        )

        t1 = Task(id="t1_dns", type="dns", command=["resolve", "example.com"])
        t2 = Task(id="t2_http", type="http", command=["probe", "example.com"], dependencies={"t1_dns"})
        t3 = Task(id="t3_dir", type="dir", command=["enum", "example.com"], dependencies={"t2_http"})
        state.tasks = [t1, t2, t3]

        # 2. Simulate initial run where:
        # - t1 finishes successfully (COMPLETED)
        # - t2 was RUNNING when the process was interrupted (e.g. SIGINT / power loss)
        # - t3 was still PENDING
        t1.mark_running()
        t1.mark_finished(
            TaskState.COMPLETED,
            TaskResult(
                task_id="t1_dns",
                state=TaskState.COMPLETED,
                command_result=CommandResult(
                    command=t1.command or [],
                    executable="resolve",
                    arguments=["example.com"],
                    started_at=datetime.now(timezone.utc),
                    finished_at=datetime.now(timezone.utc),
                    duration=0.5,
                    exit_code=0,
                    stdout="93.184.216.34",
                    stderr="",
                    timed_out=False,
                    cancelled=False,
                ),
            ),
        )

        t2.mark_running()  # Interrupted mid-run!
        state.scan.status = ScanStatus.RUNNING

        # Save snapshot of interrupted state to SQLite database
        session_mgr.save_session(state)

        # 3. Simulate process reload & resume:
        # Load the interrupted scan session from database
        reloaded_state = session_mgr.load_session("scan-acceptance-01")
        assert len(reloaded_state.tasks) == 3
        assert reloaded_state.tasks[0].state == TaskState.COMPLETED
        assert reloaded_state.tasks[1].state == TaskState.RUNNING
        assert reloaded_state.tasks[2].state == TaskState.PENDING

        # Prepare ResumePlan
        plan = ResumeEngine.prepare_resume(reloaded_state)
        assert plan.can_resume is True
        assert len(plan.skipped_tasks) == 1
        assert plan.skipped_tasks[0].id == "t1_dns"

        assert len(plan.recovered_tasks) == 1
        assert plan.recovered_tasks[0].id == "t2_http"

        assert len(plan.executable_tasks) == 2
        executable_ids = {t.id for t in plan.executable_tasks}
        assert executable_ids == {"t2_http", "t3_dir"}

        # Prerequisite t1_dns was stripped from t2_http because t1_dns is already COMPLETED
        assert plan.executable_tasks[0].dependencies == set()
        # t3_dir still properly waits for t2_http
        assert plan.executable_tasks[1].dependencies == {"t2_http"}

        # 4. Execute the resumed scan using DummyRunner
        runner = DummyRunner({
            "probe example.com": (0, "HTTP 200 OK", ""),
            "enum example.com": (0, "Found /admin, /login", ""),
        })

        scheduler = ResumeEngine.create_scheduler(plan, runner=runner)
        ResumeEngine.apply_resume(reloaded_state, plan)
        assert reloaded_state.scan.status == ScanStatus.RUNNING

        summary = await scheduler.run()

        # 5. Verify results:
        assert summary.completed == 2
        assert summary.failed == 0

        # CRITICAL VERIFICATION:
        # Task 1 was NEVER executed in the resumed run!
        executed_cmds = [" ".join(cmd) for cmd in runner.executed_commands]
        assert "resolve example.com" not in executed_cmds
        assert "probe example.com" in executed_cmds
        assert "enum example.com" in executed_cmds

        # Merge results and save final scan state
        final_state = ResumeEngine.merge_execution_summary(reloaded_state, plan, summary)
        session_mgr.save_session(final_state)

        # 6. Verify final database state:
        persisted_final = session_mgr.load_session("scan-acceptance-01")
        assert persisted_final.scan.status == ScanStatus.COMPLETED
        assert all(t.state == TaskState.COMPLETED for t in persisted_final.tasks)
        assert len(persisted_final.tasks) == 3
