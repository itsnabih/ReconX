"""Scope decision types returned by the scope validator."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reconx.scope.validator import ScopeValidator


class ScopeReason(str, Enum):
    ALLOWED_DOMAIN = "ALLOWED_DOMAIN"
    ALLOWED_IP = "ALLOWED_IP"
    EXCLUDED_DOMAIN = "EXCLUDED_DOMAIN"
    EXCLUDED_IP = "EXCLUDED_IP"
    NOT_IN_SCOPE = "NOT_IN_SCOPE"
    INVALID_TARGET = "INVALID_TARGET"
    DISALLOWED_SCHEME = "DISALLOWED_SCHEME"


@dataclass(frozen=True)
class ScopeDecision:
    """Outcome of validating one target against the authorized scope.

    `detail` holds the matching scope rule, or the parse error for invalid targets.
    """

    target: str
    allowed: bool
    reason: ScopeReason
    host: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class ScopePolicy:
    """Raw scope configuration, kept so a scan's authorized scope can be persisted and rebuilt."""

    allowed_domains: tuple[str, ...] = ()
    allowed_ips: tuple[str, ...] = ()
    excluded_domains: tuple[str, ...] = ()
    excluded_ips: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("allowed_domains", "allowed_ips", "excluded_domains", "excluded_ips"):
            value = getattr(self, name)
            if isinstance(value, str):
                raise TypeError(f"{name} must be a sequence of strings, not a string")
            object.__setattr__(self, name, tuple(value))

    def validator(self) -> ScopeValidator:
        """Build the enforcing validator; raises ValueError if the policy is invalid."""
        from reconx.scope.validator import ScopeValidator

        return ScopeValidator(
            allowed_domains=self.allowed_domains,
            allowed_ips=self.allowed_ips,
            excluded_domains=self.excluded_domains,
            excluded_ips=self.excluded_ips,
        )

