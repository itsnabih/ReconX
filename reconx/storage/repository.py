"""Persist and reload complete scan state."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json
import sqlite3
from typing import Any

from reconx.core.runner import CommandResult
from reconx.core.task import RetryPolicy, Task, TaskResult, TaskState
from reconx.models.asset import Asset
from reconx.models.evidence import Evidence
from reconx.models.finding import Finding
from reconx.models.observation import Observation
from reconx.models.scan import Scan, ScanState
from reconx.scope.models import ScopePolicy
from reconx.storage.database import transaction


class ScanNotFoundError(LookupError):
    """Raised when a scan ID does not exist in the database."""


def _ts(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def _json(value: Any, what: str) -> str:
    try:
        return json.dumps(value, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{what} is not JSON-serializable: {exc}") from exc


def _insert(table: str, columns: tuple[str, ...]) -> str:
    return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})"


_SCAN_COLS = ("id", "status", "reconx_version", "targets", "scope", "created_at", "started_at", "finished_at")
_TASK_COLS = (
    "scan_id", "id", "type", "target", "command", "priority", "timeout", "max_retries",
    "backoff_factor", "retry_on_timeout", "retryable_exit_codes", "resource_class", "state",
    "queued_at", "started_at", "finished_at", "duration", "attempts",
)
_DEP_COLS = ("scan_id", "task_id", "depends_on")
_RESULT_COLS = ("scan_id", "task_id", "state", "error_message", "attempts", "duration", "output_data")
_EXEC_COLS = (
    "scan_id", "task_id", "command", "executable", "arguments", "started_at", "finished_at",
    "duration", "exit_code", "stdout", "stderr", "timed_out", "cancelled", "error",
)
_ASSET_COLS = ("scan_id", "id", "kind", "value", "origin", "in_scope", "discovered_at")
_OBS_COLS = ("scan_id", "id", "type", "asset_id", "source", "data", "task_id", "observed_at")
_EVIDENCE_COLS = (
    "scan_id", "id", "task_id", "tool", "tool_version", "command", "target", "exit_code",
    "stdout", "stderr", "timed_out", "parsed", "raw_reference", "captured_at",
)
_FINDING_COLS = (
    "scan_id", "id", "finding_type", "title", "description", "asset_id", "endpoint",
    "severity", "confidence", "created_at",
)
_FINDING_OBS_COLS = ("scan_id", "finding_id", "observation_id")
_FINDING_EV_COLS = ("scan_id", "finding_id", "evidence_id")


class ScanRepository:
    """Stores a ScanState as one atomic snapshot and rebuilds it on load."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, state: ScanState) -> None:
        """Replace the stored state of `state.scan.id` with `state` in a single transaction.

        Serialization errors are raised before the database is touched; integrity errors
        (e.g. references to unknown assets or tasks) roll back, leaving the prior state intact.
        """
        rows = _serialize(state)
        with transaction(self._conn):
            self._conn.execute("DELETE FROM scans WHERE id = ?", (state.scan.id,))
            for sql, params in rows:
                if params:
                    self._conn.executemany(sql, params)

    def load(self, scan_id: str) -> ScanState:
        """Rebuild the full ScanState; raises ScanNotFoundError if the scan does not exist."""
        conn = self._conn
        row = conn.execute(
            f"SELECT {', '.join(_SCAN_COLS)} FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise ScanNotFoundError(f"scan {scan_id!r} not found")
        scan = dict(zip(_SCAN_COLS, row))
        scan_model = Scan(
            id=scan["id"],
            status=scan["status"],
            reconx_version=scan["reconx_version"],
            targets=tuple(json.loads(scan["targets"])),
            scope=ScopePolicy(**json.loads(scan["scope"])),
            created_at=_dt(scan["created_at"]),
            started_at=_dt(scan["started_at"]),
            finished_at=_dt(scan["finished_at"]),
        )

        def select(table: str, columns: tuple[str, ...]) -> list[dict[str, Any]]:
            cursor = conn.execute(
                f"SELECT {', '.join(columns)} FROM {table} WHERE scan_id = ? ORDER BY rowid",
                (scan_id,),
            )
            return [dict(zip(columns, values)) for values in cursor]

        dependencies: dict[str, set[str]] = {}
        for dep in select("task_dependencies", _DEP_COLS):
            dependencies.setdefault(dep["task_id"], set()).add(dep["depends_on"])
        executions = {e["task_id"]: _command_result(e) for e in select("command_executions", _EXEC_COLS)}
        results = {
            r["task_id"]: TaskResult(
                task_id=r["task_id"],
                state=TaskState(r["state"]),
                command_result=executions.get(r["task_id"]),
                output_data=json.loads(r["output_data"]) if r["output_data"] is not None else None,
                error_message=r["error_message"],
                attempts=r["attempts"],
                duration=r["duration"],
            )
            for r in select("task_results", _RESULT_COLS)
        }
        tasks = [_task(t, dependencies.get(t["id"], set()), results.get(t["id"])) for t in select("tasks", _TASK_COLS)]

        assets = [
            Asset(
                id=a["id"], kind=a["kind"], value=a["value"], origin=a["origin"],
                in_scope=bool(a["in_scope"]), discovered_at=_dt(a["discovered_at"]),
            )
            for a in select("assets", _ASSET_COLS)
        ]
        observations = [
            Observation(
                id=o["id"], type=o["type"], asset_id=o["asset_id"], source=o["source"],
                data=json.loads(o["data"]), task_id=o["task_id"], observed_at=_dt(o["observed_at"]),
            )
            for o in select("observations", _OBS_COLS)
        ]
        evidence = [
            Evidence(
                id=e["id"], task_id=e["task_id"], tool=e["tool"], tool_version=e["tool_version"],
                command=tuple(json.loads(e["command"])), target=e["target"], exit_code=e["exit_code"],
                stdout=e["stdout"], stderr=e["stderr"], timed_out=bool(e["timed_out"]),
                parsed=json.loads(e["parsed"]), raw_reference=e["raw_reference"],
                captured_at=_dt(e["captured_at"]),
            )
            for e in select("evidence", _EVIDENCE_COLS)
        ]
        linked_observations: dict[str, list[str]] = {}
        for link in select("finding_observations", _FINDING_OBS_COLS):
            linked_observations.setdefault(link["finding_id"], []).append(link["observation_id"])
        linked_evidence: dict[str, list[str]] = {}
        for link in select("finding_evidence", _FINDING_EV_COLS):
            linked_evidence.setdefault(link["finding_id"], []).append(link["evidence_id"])
        findings = [
            Finding(
                id=f["id"], finding_type=f["finding_type"], title=f["title"],
                description=f["description"], asset_id=f["asset_id"], endpoint=f["endpoint"],
                severity=f["severity"], confidence=f["confidence"],
                observation_ids=tuple(linked_observations.get(f["id"], ())),
                evidence_ids=tuple(linked_evidence.get(f["id"], ())),
                created_at=_dt(f["created_at"]),
            )
            for f in select("findings", _FINDING_COLS)
        ]
        return ScanState(scan_model, tasks, assets, observations, evidence, findings)

    def list_scans(self) -> list[dict[str, Any]]:
        """Return summary list of all saved scans ordered by creation date descending."""
        cursor = self._conn.execute(
            "SELECT id, status, targets, reconx_version, created_at, started_at, finished_at FROM scans ORDER BY created_at DESC"
        )
        results: list[dict[str, Any]] = []
        for row in cursor:
            results.append({
                "id": row[0],
                "status": row[1],
                "targets": list(json.loads(row[2])),
                "reconx_version": row[3],
                "created_at": row[4],
                "started_at": row[5],
                "finished_at": row[6],
            })
        return results


def _serialize(state: ScanState) -> list[tuple[str, list[tuple[Any, ...]]]]:
    """Build every INSERT for the snapshot, in foreign-key order."""
    scan = state.scan
    sid = scan.id
    scan_row = (
        sid, scan.status.value, scan.reconx_version, _json(list(scan.targets), "scan targets"),
        _json(asdict(scan.scope), "scan scope"), _ts(scan.created_at), _ts(scan.started_at),
        _ts(scan.finished_at),
    )

    task_rows, dep_rows, result_rows, exec_rows = [], [], [], []
    for task in state.tasks:
        if task.action is not None:
            raise ValueError(f"task {task.id!r} has a callable action, which cannot be persisted")
        policy = task.retry_policy
        task_rows.append((
            sid, task.id, task.type, task.target,
            _json(task.command, f"task {task.id!r} command") if task.command is not None else None,
            task.priority, task.timeout, policy.max_retries, policy.backoff_factor,
            int(policy.retry_on_timeout), _json(list(policy.retryable_exit_codes), "retryable_exit_codes"),
            task.resource_class, task.state.value, _ts(task.queued_at), _ts(task.started_at),
            _ts(task.finished_at), task.duration, task.attempts,
        ))
        dep_rows.extend((sid, task.id, dep) for dep in sorted(task.dependencies))
        result = task.result
        if result is None:
            continue
        output = (
            _json(result.output_data, f"task {task.id!r} output_data")
            if result.output_data is not None else None
        )
        result_rows.append((
            sid, task.id, result.state.value, result.error_message, result.attempts,
            result.duration, output,
        ))
        cmd = result.command_result
        if cmd is not None:
            exec_rows.append((
                sid, task.id, _json(cmd.command, "command"), cmd.executable,
                _json(cmd.arguments, "arguments"), _ts(cmd.started_at), _ts(cmd.finished_at),
                cmd.duration, cmd.exit_code, cmd.stdout, cmd.stderr, int(cmd.timed_out),
                int(cmd.cancelled), cmd.error,
            ))

    asset_rows = [
        (sid, a.id, a.kind.value, a.value, a.origin.value, int(a.in_scope), _ts(a.discovered_at))
        for a in state.assets
    ]
    obs_rows = [
        (sid, o.id, o.type, o.asset_id, o.source, _json(o.data, f"observation {o.id!r} data"),
         o.task_id, _ts(o.observed_at))
        for o in state.observations
    ]
    ev_rows = [
        (sid, e.id, e.task_id, e.tool, e.tool_version, _json(list(e.command), "evidence command"),
         e.target, e.exit_code, e.stdout, e.stderr, int(e.timed_out),
         _json(e.parsed, f"evidence {e.id!r} parsed"), e.raw_reference, _ts(e.captured_at))
        for e in state.evidence
    ]
    finding_rows, finding_obs_rows, finding_ev_rows = [], [], []
    for f in state.findings:
        finding_rows.append((
            sid, f.id, f.finding_type, f.title, f.description, f.asset_id, f.endpoint,
            f.severity.value, f.confidence, _ts(f.created_at),
        ))
        finding_obs_rows.extend((sid, f.id, oid) for oid in f.observation_ids)
        finding_ev_rows.extend((sid, f.id, eid) for eid in f.evidence_ids)

    return [
        (_insert("scans", _SCAN_COLS), [scan_row]),
        (_insert("tasks", _TASK_COLS), task_rows),
        (_insert("task_dependencies", _DEP_COLS), dep_rows),
        (_insert("task_results", _RESULT_COLS), result_rows),
        (_insert("command_executions", _EXEC_COLS), exec_rows),
        (_insert("assets", _ASSET_COLS), asset_rows),
        (_insert("observations", _OBS_COLS), obs_rows),
        (_insert("evidence", _EVIDENCE_COLS), ev_rows),
        (_insert("findings", _FINDING_COLS), finding_rows),
        (_insert("finding_observations", _FINDING_OBS_COLS), finding_obs_rows),
        (_insert("finding_evidence", _FINDING_EV_COLS), finding_ev_rows),
    ]


def _command_result(row: dict[str, Any]) -> CommandResult:
    return CommandResult(
        command=json.loads(row["command"]),
        executable=row["executable"],
        arguments=json.loads(row["arguments"]),
        started_at=_dt(row["started_at"]),
        finished_at=_dt(row["finished_at"]),
        duration=row["duration"],
        exit_code=row["exit_code"],
        stdout=row["stdout"],
        stderr=row["stderr"],
        timed_out=bool(row["timed_out"]),
        cancelled=bool(row["cancelled"]),
        error=row["error"],
    )


def _task(row: dict[str, Any], dependencies: set[str], result: TaskResult | None) -> Task:
    return Task(
        id=row["id"],
        type=row["type"],
        target=row["target"],
        command=json.loads(row["command"]) if row["command"] is not None else None,
        dependencies=dependencies,
        priority=row["priority"],
        timeout=row["timeout"],
        retry_policy=RetryPolicy(
            max_retries=row["max_retries"],
            backoff_factor=row["backoff_factor"],
            retry_on_timeout=bool(row["retry_on_timeout"]),
            retryable_exit_codes=tuple(json.loads(row["retryable_exit_codes"])),
        ),
        resource_class=row["resource_class"],
        state=TaskState(row["state"]),
        queued_at=_dt(row["queued_at"]),
        started_at=_dt(row["started_at"]),
        finished_at=_dt(row["finished_at"]),
        duration=row["duration"],
        attempts=row["attempts"],
        result=result,
    )
