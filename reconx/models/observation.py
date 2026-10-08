"""Observations: normalized facts detected by a tool, not security conclusions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class Observation:
    """A normalized fact (e.g. 'open_port', 'dns_a') about one asset.

    `data` must be JSON-serializable; it is validated when persisted.
    """

    type: str
    asset_id: str
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    task_id: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.type or not self.asset_id or not self.source:
            raise ValueError("observation requires type, asset_id and source")
