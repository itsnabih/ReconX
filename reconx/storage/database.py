"""SQLite connection setup, transactions, and versioned schema migrations."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
import sqlite3

# Every table is keyed by (scan_id, id) so entity IDs only need to be unique within a scan.
# Indexes on foreign-key child columns keep FK checks and ON DELETE CASCADE from scanning tables.
_SCHEMA_V1 = (
    """
    CREATE TABLE scans (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        reconx_version TEXT NOT NULL,
        targets TEXT NOT NULL,
        scope TEXT NOT NULL,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    ) STRICT
    """,
    """
    CREATE TABLE tasks (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        type TEXT NOT NULL,
        target TEXT NOT NULL,
        command TEXT,
        priority INTEGER NOT NULL,
        timeout REAL,
        max_retries INTEGER NOT NULL,
        backoff_factor REAL NOT NULL,
        retry_on_timeout INTEGER NOT NULL CHECK (retry_on_timeout IN (0, 1)),
        retryable_exit_codes TEXT NOT NULL,
        resource_class TEXT NOT NULL,
        state TEXT NOT NULL,
        queued_at TEXT,
        started_at TEXT,
        finished_at TEXT,
        duration REAL,
        attempts INTEGER NOT NULL,
        PRIMARY KEY (scan_id, id)
    ) STRICT
    """,
    """
    CREATE TABLE task_dependencies (
        scan_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        depends_on TEXT NOT NULL,
        PRIMARY KEY (scan_id, task_id, depends_on),
        FOREIGN KEY (scan_id, task_id) REFERENCES tasks(scan_id, id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id, depends_on) REFERENCES tasks(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    "CREATE INDEX idx_task_dependencies_depends_on ON task_dependencies(scan_id, depends_on)",
    """
    CREATE TABLE task_results (
        scan_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        state TEXT NOT NULL,
        error_message TEXT,
        attempts INTEGER NOT NULL,
        duration REAL NOT NULL,
        output_data TEXT,
        PRIMARY KEY (scan_id, task_id),
        FOREIGN KEY (scan_id, task_id) REFERENCES tasks(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    """
    CREATE TABLE command_executions (
        scan_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        command TEXT NOT NULL,
        executable TEXT NOT NULL,
        arguments TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        duration REAL NOT NULL,
        exit_code INTEGER,
        stdout TEXT NOT NULL,
        stderr TEXT NOT NULL,
        timed_out INTEGER NOT NULL CHECK (timed_out IN (0, 1)),
        cancelled INTEGER NOT NULL CHECK (cancelled IN (0, 1)),
        error TEXT,
        PRIMARY KEY (scan_id, task_id),
        FOREIGN KEY (scan_id, task_id) REFERENCES task_results(scan_id, task_id) ON DELETE CASCADE
    ) STRICT
    """,
    """
    CREATE TABLE assets (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        origin TEXT NOT NULL,
        in_scope INTEGER NOT NULL CHECK (in_scope IN (0, 1)),
        discovered_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, id),
        UNIQUE (scan_id, kind, value)
    ) STRICT
    """,
    """
    CREATE TABLE observations (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        type TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        source TEXT NOT NULL,
        data TEXT NOT NULL,
        task_id TEXT,
        observed_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, id),
        FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id, task_id) REFERENCES tasks(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    "CREATE INDEX idx_observations_asset ON observations(scan_id, asset_id)",
    "CREATE INDEX idx_observations_task ON observations(scan_id, task_id)",
    """
    CREATE TABLE evidence (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        task_id TEXT,
        tool TEXT NOT NULL,
        tool_version TEXT,
        command TEXT NOT NULL,
        target TEXT NOT NULL,
        exit_code INTEGER,
        stdout TEXT NOT NULL,
        stderr TEXT NOT NULL,
        timed_out INTEGER NOT NULL CHECK (timed_out IN (0, 1)),
        parsed TEXT NOT NULL,
        raw_reference TEXT,
        captured_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, id),
        FOREIGN KEY (scan_id, task_id) REFERENCES tasks(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    "CREATE INDEX idx_evidence_task ON evidence(scan_id, task_id)",
    """
    CREATE TABLE findings (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        endpoint TEXT,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
        created_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, id),
        FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    "CREATE INDEX idx_findings_asset ON findings(scan_id, asset_id)",
    """
    CREATE TABLE finding_observations (
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        observation_id TEXT NOT NULL,
        PRIMARY KEY (scan_id, finding_id, observation_id),
        FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id, observation_id) REFERENCES observations(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    "CREATE INDEX idx_finding_observations_obs ON finding_observations(scan_id, observation_id)",
    """
    CREATE TABLE finding_evidence (
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        PRIMARY KEY (scan_id, finding_id, evidence_id),
        FOREIGN KEY (scan_id, finding_id) REFERENCES findings(scan_id, id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id, evidence_id) REFERENCES evidence(scan_id, id) ON DELETE CASCADE
    ) STRICT
    """,
    "CREATE INDEX idx_finding_evidence_ev ON finding_evidence(scan_id, evidence_id)",
)

# Index N holds the statements that upgrade the schema from version N to N + 1.
MIGRATIONS: tuple[tuple[str, ...], ...] = (_SCHEMA_V1,)
SCHEMA_VERSION = len(MIGRATIONS)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """Run a block atomically; rolls back and re-raises on any error."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def open_database(path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open (creating if needed) a ReconX database and bring its schema up to date.

    New database files are created with owner-only (0600) permissions because they hold
    raw tool output. Pass ":memory:" for a transient database.
    """
    location = os.fspath(path)
    in_memory = location == ":memory:"
    if not in_memory:
        _create_private_file(location)

    conn = sqlite3.connect(location, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        if conn.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise RuntimeError("SQLite build does not enforce foreign keys")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -32000")
        if not in_memory:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        _migrate(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def _create_private_file(location: str) -> None:
    try:
        fd = os.open(location, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    os.close(fd)


def _migrate(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} is newer than supported version {SCHEMA_VERSION}"
        )
    for version in range(current, SCHEMA_VERSION):
        with transaction(conn):
            for statement in MIGRATIONS[version]:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {version + 1}")
