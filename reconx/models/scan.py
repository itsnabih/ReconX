"""Scan identity and the aggregate scan state that is persisted and reloaded."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import secrets

from reconx import __version__
from reconx.core.task import Task
from reconx.models.asset import Asset
from reconx.models.evidence import Evidence
from reconx.models.finding import Finding
from reconx.models.observation import Observation
from reconx.scope.models import ScopePolicy


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


def new_scan_id(now: datetime | None = None) -> str:
    """Return a unique scan ID such as 'scan-20261005-094211-a82f'."""
    moment = now or datetime.now(timezone.utc)
    return f"scan-{moment:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"


@dataclass
class Scan:
    """One scan run: its targets, authorized scope, and lifecycle status."""

    targets: tuple[str, ...]
    scope: ScopePolicy
    id: str = field(default_factory=new_scan_id)
    status: ScanStatus = ScanStatus.PENDING
    reconx_version: str = __version__
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("scan id must not be empty")
        if isinstance(self.targets, str):
            raise TypeError("targets must be a sequence of strings, not a string")
        self.targets = tuple(self.targets)
        if not self.targets or not all(self.targets):
            raise ValueError("scan requires at least one non-empty target")
        self.status = ScanStatus(self.status)
        self.scope.validator()


@dataclass
class ScanState:
    """Everything recorded for a scan; the unit of persistence."""

    scan: Scan
    tasks: list[Task] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
