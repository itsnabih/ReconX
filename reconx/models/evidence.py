"""Evidence: the tool execution data that supports observations and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class Evidence:
    """Provenance of a result: tool, version, command, exit status and relevant output.

    `parsed` must be JSON-serializable; it is validated when persisted.
    """

    tool: str
    target: str
    command: tuple[str, ...] = ()
    tool_version: str | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    parsed: dict[str, Any] = field(default_factory=dict)
    raw_reference: str | None = None
    task_id: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.tool or not self.target:
            raise ValueError("evidence requires tool and target")
        if isinstance(self.command, str):
            raise TypeError("command must be an argument sequence, not a string")
        self.command = tuple(self.command)

