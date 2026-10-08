"""Findings: security conclusions linked to the observations and evidence behind them."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import math
import uuid


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """A finding; confidence (0.0-1.0) is independent of severity."""

    finding_type: str
    title: str
    asset_id: str
    severity: Severity
    confidence: float
    description: str = ""
    endpoint: str | None = None
    observation_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.finding_type or not self.title or not self.asset_id:
            raise ValueError("finding requires finding_type, title and asset_id")
        self.severity = Severity(self.severity)
        if not (math.isfinite(self.confidence) and 0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence!r}")
        self.observation_ids = tuple(self.observation_ids)
        self.evidence_ids = tuple(self.evidence_ids)
        for name, ids in (("observation_ids", self.observation_ids), ("evidence_ids", self.evidence_ids)):
            if len(set(ids)) != len(ids):
                raise ValueError(f"{name} contains duplicates")

