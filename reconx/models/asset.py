"""Assets: hosts known to a scan, distinguishing user-provided from discovered."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import uuid


class AssetKind(str, Enum):
    DOMAIN = "DOMAIN"
    IP = "IP"


class AssetOrigin(str, Enum):
    USER_PROVIDED = "USER_PROVIDED"
    DISCOVERED = "DISCOVERED"


@dataclass
class Asset:
    """A host and the scope decision recorded for it when it became known."""

    kind: AssetKind
    value: str
    origin: AssetOrigin
    in_scope: bool
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self.kind = AssetKind(self.kind)
        self.origin = AssetOrigin(self.origin)
        if not self.value:
            raise ValueError("asset value must not be empty")
        if self.kind is AssetKind.IP:
            self.value = str(ipaddress.ip_address(self.value))