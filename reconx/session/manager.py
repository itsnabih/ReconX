"""Scan session management with persistent SQLite storage."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import sqlite3
from typing import Any

from reconx.models.scan import Scan, ScanState, ScanStatus, new_scan_id
from reconx.scope.models import ScopePolicy
from reconx.storage.database import open_database, transaction
from reconx.storage.repository import ScanNotFoundError, ScanRepository


class ScanSessionManager:
    """Manages creation, retrieval, listing, and lifecycle of scan sessions."""

    def __init__(
        self,
        target: ScanRepository | sqlite3.Connection | str | Path,
    ) -> None:
        """Initialize session manager.

        Args:
            target: Existing ScanRepository, sqlite3.Connection, or filesystem path to database.
        """
        if isinstance(target, ScanRepository):
            self._repository = target
            self._conn = target._conn
        elif isinstance(target, sqlite3.Connection):
            self._conn = target
            self._repository = ScanRepository(target)
        else:
            self._conn = open_database(target)
            self._repository = ScanRepository(self._conn)

    @property
    def repository(self) -> ScanRepository:
        """Return the underlying ScanRepository."""
        return self._repository

    @property
    def connection(self) -> sqlite3.Connection:
        """Return the underlying sqlite3 connection."""
        return self._conn

    def create_session(
        self,
        targets: Sequence[str],
        scope: ScopePolicy | None = None,
        scan_id: str | None = None,
    ) -> ScanState:
        """Create and persist a new scan session in PENDING status.

        Args:
            targets: Target domains, hostnames, or IP addresses.
            scope: Scope policy for target filtering (defaults to allow_all).
            scan_id: Optional explicit scan ID; auto-generates if not provided.

        Returns:
            Initial ScanState persisted in the database.
        """
        sid = scan_id or new_scan_id()
        policy = scope if scope is not None else ScopePolicy(allowed_domains=tuple(targets))
        scan = Scan(
            id=sid,
            targets=tuple(targets),
            scope=policy,
            status=ScanStatus.PENDING,
        )
        state = ScanState(scan=scan)
        self._repository.save(state)
        return state

    def save_session(self, state: ScanState) -> None:
        """Persist updated snapshot of the scan session."""
        self._repository.save(state)

    def load_session(self, scan_id: str) -> ScanState:
        """Load scan state by ID. Raises ScanNotFoundError if not found."""
        return self._repository.load(scan_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all scan sessions stored in the database ordered by creation date."""
        return self._repository.list_scans()

    def session_exists(self, scan_id: str) -> bool:
        """Check if a scan session exists."""
        row = self._conn.execute(
            "SELECT 1 FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return row is not None

    def delete_session(self, scan_id: str) -> bool:
        """Delete a scan session and all cascaded data. Returns True if deleted."""
        with transaction(self._conn):
            cursor = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0
