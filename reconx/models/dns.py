"""Normalized data models for DNS queries and WHOIS data."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reconx.models.observation import Observation


class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"


@dataclass(frozen=True)
class DNSRecord:
    """Normalized DNS resource record produced identically across tools."""

    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None

    def __post_init__(self) -> None:
        clean_name = self.name.strip().lower()
        if clean_name.endswith(".") and len(clean_name) > 1:
            clean_name = clean_name[:-1]
        object.__setattr__(self, "name", clean_name)

        object.__setattr__(self, "record_type", self.record_type.strip().upper())

        clean_val = self.value.strip()
        if self.record_type in ("CNAME", "NS", "MX", "PTR"):
            clean_val = clean_val.lower()
            if clean_val.endswith(".") and len(clean_val) > 1:
                clean_val = clean_val[:-1]
        elif self.record_type == "TXT":
            if (clean_val.startswith('"') and clean_val.endswith('"')) or (
                clean_val.startswith("'") and clean_val.endswith("'")
            ):
                clean_val = clean_val[1:-1]
        object.__setattr__(self, "value", clean_val)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class WhoisRecord:
    """Normalized WHOIS information for a domain or IP."""

    query: str
    domain: str | None = None
    registrar: str | None = None
    organization: str | None = None
    asn: str | None = None
    created_date: str | None = None
    expires_date: str | None = None
    name_servers: tuple[str, ...] = ()
    status: tuple[str, ...] = ()
    raw_text: str = ""

    def __post_init__(self) -> None:
        clean_ns = tuple(ns.lower().rstrip(".") for ns in self.name_servers if ns.strip())
        object.__setattr__(self, "name_servers", clean_ns)
        object.__setattr__(self, "status", tuple(s.strip() for s in self.status if s.strip()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "domain": self.domain,
            "registrar": self.registrar,
            "organization": self.organization,
            "asn": self.asn,
            "created_date": self.created_date,
            "expires_date": self.expires_date,
            "name_servers": list(self.name_servers),
            "status": list(self.status),
        }


@dataclass(frozen=True)
class DNSResult:
    """Normalized result returned by any DNS tool adapter or parser."""

    tool: str
    target: str
    records: tuple[DNSRecord, ...] = ()
    whois: WhoisRecord | None = None
    errors: tuple[str, ...] = ()
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "records": [r.to_dict() for r in self.records],
            "whois": self.whois.to_dict() if self.whois else None,
            "errors": list(self.errors),
        }

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert normalized DNS/WHOIS data into persistent Observation models."""
        from reconx.models.observation import Observation

        observations: list[Observation] = []
        for record in self.records:
            observations.append(
                Observation(
                    type=f"dns_{record.record_type.lower()}",
                    asset_id=asset_id,
                    source=self.tool,
                    data=record.to_dict(),
                    task_id=task_id,
                )
            )
        if self.whois:
            observations.append(
                Observation(
                    type="whois",
                    asset_id=asset_id,
                    source=self.tool,
                    data=self.whois.to_dict(),
                    task_id=task_id,
                )
            )
        return observations
