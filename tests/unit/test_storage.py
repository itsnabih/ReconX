"""Phase 3 acceptance: a complete scan state can be persisted and reloaded."""

import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from reconx.core.runner import CommandRunner
from reconx.core.scheduler import Scheduler
from reconx.core.task import RetryPolicy, Task, TaskResult, TaskState
from reconx.models import (
    Asset,
    AssetKind,
    AssetOrigin,
    Evidence,
    Finding,
    Observation,
    Scan,
    ScanState,
    ScanStatus,
    Severity,
)
from reconx.scope import ScopePolicy
from reconx.storage import SCHEMA_VERSION, ScanNotFoundError, ScanRepository, open_database

POLICY = ScopePolicy(
    allowed_domains=("example.com", "*.example.com"),
    allowed_ips=("192.0.2.0/24",),
    excluded_domains=("payment.example.com",),
    excluded_ips=("192.0.2.50",),
)


async def executed_tasks() -> list[Task]:
    """Run real tasks through the scheduler so persisted results come from CommandRunner."""
    ok = Task(
        id="dns", type="dummy", target="www.example.com",
        command=[sys.executable, "-c", "print('93.184.216.34')"],
        priority=5, timeout=10.0, resource_class="dns",
        retry_policy=RetryPolicy(max_retries=1, backoff_factor=0.0, retryable_exit_codes=(2, 3)),
    )
    failing = Task(
        id="fail", type="dummy", target="192.0.2.10",
        command=[sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(4)"],
    )
    dependent = Task(
        id="child", type="dummy", target="www.example.com",
        command=[sys.executable, "-c", "print('never')"], dependencies={"fail"},
    )
    out_of_scope = Task(id="evil", type="dummy", target="evil.net", command=["true"])
    scheduler = Scheduler(runner=CommandRunner(default_timeout=10.0), scope=POLICY.validator())
    tasks = [ok, failing, dependent, out_of_scope]
    scheduler.add_tasks(tasks)
    await scheduler.run()
    return tasks


def build_state(tasks: list[Task]) -> ScanState:
    started = datetime(2026, 10, 5, 9, 42, 11, 123456, tzinfo=timezone.utc)
    scan = Scan(
        targets=("www.example.com", "192.0.2.10"), scope=POLICY, status=ScanStatus.COMPLETED,
        started_at=started, finished_at=datetime.now(timezone.utc),
    )
    domain = Asset(AssetKind.DOMAIN, "www.example.com", AssetOrigin.USER_PROVIDED, in_scope=True)
    ip = Asset(AssetKind.IP, "93.184.216.34", AssetOrigin.DISCOVERED, in_scope=False)
    dns_result = tasks[0].result.command_result
    evidence = Evidence(
        tool="python", target="www.example.com", command=dns_result.command, tool_version="3.x",
        exit_code=dns_result.exit_code, stdout=dns_result.stdout, stderr=dns_result.stderr,
        parsed={"records": [{"type": "A", "value": "93.184.216.34", "ttl": 300}]},
        raw_reference="raw/dns.txt", task_id="dns", captured_at=dns_result.finished_at,
    )
    observation = Observation(
        type="dns_a", asset_id=domain.id, source="python",
        data={"value": "93.184.216.34", "nested": {"ok": True, "n": None, "list": [1, 2.5, "x"]}},
        task_id="dns",
    )
    unlinked = Observation(type="host", asset_id=ip.id, source="python")
    finding = Finding(
        finding_type="test_finding", title="Test finding", asset_id=domain.id,
        severity=Severity.HIGH, confidence=0.42, description="ü unicode ✓",
        endpoint="https://www.example.com/", observation_ids=(observation.id, unlinked.id),
        evidence_ids=(evidence.id,),
    )
    return ScanState(
        scan=scan, tasks=tasks, assets=[domain, ip], observations=[observation, unlinked],
        evidence=[evidence], findings=[finding],
    )


class TestScanPersistence(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "reconx.db"
        self.conn = open_database(self.path)
        self.repo = ScanRepository(self.conn)
        self.state = build_state(await executed_tasks())

    async def asyncTearDown(self) -> None:
        self.conn.close()
        self.tmp.cleanup()

    def reopen(self) -> ScanRepository:
        self.conn.close()
        self.conn = open_database(self.path)
        return ScanRepository(self.conn)

    async def test_complete_state_round_trips_across_connections(self) -> None:
        states = {t.id: t.state for t in self.state.tasks}
        self.assertEqual(
            states,
            {"dns": TaskState.COMPLETED, "fail": TaskState.FAILED,
             "child": TaskState.SKIPPED, "evil": TaskState.SKIPPED},
        )

        self.repo.save(self.state)
        loaded = self.reopen().load(self.state.scan.id)

        self.assertEqual(loaded, self.state)
        dns = loaded.tasks[0]
        self.assertIsNotNone(dns.result.command_result)
        self.assertIn("93.184.216.34", dns.result.command_result.stdout)
        self.assertEqual(dns.dependencies, set())
        self.assertEqual(loaded.tasks[2].dependencies, {"fail"})
        self.assertEqual(loaded.tasks[1].result.command_result.exit_code, 4)
        self.assertIsNone(loaded.tasks[3].result.command_result)
        self.assertEqual(loaded.scan.scope.validator().check("evil.net").allowed, False)

    async def test_resave_replaces_snapshot_without_duplicates(self) -> None:
        self.repo.save(self.state)
        self.state.scan.status = ScanStatus.CANCELLED
        self.state.observations.pop()
        self.state.findings[0].observation_ids = (self.state.observations[0].id,)
        self.state.tasks[0].result.output_data = {"records": 1}
        self.repo.save(self.state)

        loaded = self.repo.load(self.state.scan.id)
        self.assertEqual(loaded, self.state)
        self.assertEqual(len(loaded.observations), 1)
        count = self.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        self.assertEqual(count, len(self.state.tasks))

    async def test_scans_are_isolated(self) -> None:
        other = Scan(targets=("example.com",), scope=POLICY)
        same_ids = [Task(id="dns", type="dummy", target="example.com", command=["true"])]
        self.repo.save(self.state)
        self.repo.save(ScanState(scan=other, tasks=same_ids))

        self.assertEqual(self.repo.load(self.state.scan.id), self.state)
        self.assertEqual(self.repo.load(other.id).tasks, same_ids)

    async def test_unknown_scan_raises(self) -> None:
        with self.assertRaises(ScanNotFoundError):
            self.repo.load("scan-missing")

    async def test_dangling_reference_rolls_back_and_keeps_previous_state(self) -> None:
        self.repo.save(self.state)
        self.state.observations.append(Observation(type="x", asset_id="no-such-asset", source="t"))
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.save(self.state)
        self.state.observations.pop()
        self.assertEqual(self.repo.load(self.state.scan.id), self.state)

    async def test_unknown_dependency_rejected(self) -> None:
        state = ScanState(
            scan=Scan(targets=("example.com",), scope=POLICY),
            tasks=[Task(id="a", type="dummy", target="example.com", dependencies={"missing"})],
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.save(state)
        with self.assertRaises(ScanNotFoundError):
            self.repo.load(state.scan.id)

    async def test_duplicate_asset_rejected(self) -> None:
        self.state.assets.append(
            Asset(AssetKind.DOMAIN, "www.example.com", AssetOrigin.DISCOVERED, in_scope=True)
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.save(self.state)

    async def test_non_json_data_rejected_before_write(self) -> None:
        for bad in ({"when": datetime.now()}, {"x": float("nan")}):
            with self.subTest(bad=bad):
                self.state.observations[0].data = bad
                with self.assertRaises(ValueError):
                    self.repo.save(self.state)
                self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
                self.assertFalse(self.conn.in_transaction)

    async def test_task_with_callable_action_rejected(self) -> None:
        async def action(task, runner, token) -> TaskResult:
            return TaskResult(task_id=task.id, state=TaskState.COMPLETED)

        self.state.tasks.append(Task(id="act", type="dummy", target="example.com", action=action))
        with self.assertRaises(ValueError):
            self.repo.save(self.state)


class TestDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "reconx.db"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_new_database_is_private(self) -> None:
        open_database(self.path).close()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_migrations_are_idempotent(self) -> None:
        open_database(self.path).close()
        conn = open_database(self.path)
        try:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        finally:
            conn.close()

    def test_newer_schema_refused(self) -> None:
        conn = sqlite3.connect(self.path)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        conn.close()
        with self.assertRaises(RuntimeError):
            open_database(self.path)

    def test_missing_directory_fails(self) -> None:
        with self.assertRaises(FileNotFoundError):
            open_database(Path(self.tmp.name) / "missing" / "reconx.db")

    def test_in_memory_database(self) -> None:
        conn = open_database(":memory:")
        try:
            state = ScanState(scan=Scan(targets=("example.com",), scope=POLICY))
            repo = ScanRepository(conn)
            repo.save(state)
            self.assertEqual(repo.load(state.scan.id), state)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
