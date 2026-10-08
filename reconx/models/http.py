"""Normalized HTTP response, header analysis, baseline, and endpoint models."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reconx.models.observation import Observation

# Standard security headers to evaluate
SECURITY_HEADERS = frozenset({
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
})


@dataclass(frozen=True)
class CookieInfo:
    """Normalized HTTP cookie details."""

    name: str
    value: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "domain": self.domain,
            "path": self.path,
        }


@dataclass(frozen=True)
class HeaderAnalysis:
    """Detailed security and technology analysis of HTTP response headers."""

    server: str | None = None
    technologies: tuple[str, ...] = ()
    security_headers_present: dict[str, str] = field(default_factory=dict)
    security_headers_missing: tuple[str, ...] = ()
    cors_origin: str | None = None
    cors_credentials: bool | None = None
    cookies: tuple[CookieInfo, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "technologies": list(self.technologies),
            "security_headers_present": dict(self.security_headers_present),
            "security_headers_missing": list(self.security_headers_missing),
            "cors_origin": self.cors_origin,
            "cors_credentials": self.cors_credentials,
            "cookies": [c.to_dict() for c in self.cookies],
        }

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert header analysis into persistent Observation models."""
        from reconx.models.observation import Observation

        obs: list[Observation] = []
        if self.server or self.technologies:
            obs.append(
                Observation(
                    type="server_metadata",
                    asset_id=asset_id,
                    source="http",
                    data={
                        "server": self.server,
                        "technologies": list(self.technologies),
                    },
                    task_id=task_id,
                )
            )
        if self.security_headers_missing:
            obs.append(
                Observation(
                    type="missing_security_headers",
                    asset_id=asset_id,
                    source="http",
                    data={
                        "missing": list(self.security_headers_missing),
                        "present": list(self.security_headers_present.keys()),
                    },
                    task_id=task_id,
                )
            )
        return obs


@dataclass(frozen=True)
class HTTPResponse:
    """Normalized HTTP response model."""

    url: str
    status_code: int
    http_version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_length: int = 0
    content_type: str | None = None
    redirect_chain: tuple[str, ...] = ()
    final_url: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    raw_output: str = ""

    def __post_init__(self) -> None:
        if not self.final_url:
            object.__setattr__(self, "final_url", self.url)
        if not self.content_length and self.body:
            object.__setattr__(self, "content_length", len(self.body.encode("utf-8", errors="replace")))
        if not self.content_type and "content-type" in self.headers:
            object.__setattr__(self, "content_type", self.headers["content-type"])

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    @property
    def title(self) -> str | None:
        """Extract HTML <title> tag value if present."""
        m = re.search(r"<title[^>]*>(.*?)</title>", self.body, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else None

    @property
    def body_hash(self) -> str:
        """SHA-256 hash of the response body."""
        return hashlib.sha256(self.body.encode("utf-8", errors="replace")).hexdigest()

    @property
    def word_count(self) -> int:
        """Word count in response body."""
        return len(self.body.split())

    @property
    def line_count(self) -> int:
        """Line count in response body."""
        return len(self.body.splitlines())

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "http_version": self.http_version,
            "headers": dict(self.headers),
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_chain": list(self.redirect_chain),
            "final_url": self.final_url,
            "cookies": dict(self.cookies),
            "elapsed_seconds": self.elapsed_seconds,
            "title": self.title,
            "body_hash": self.body_hash,
        }

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert HTTP response into persistent Observation models."""
        from reconx.models.observation import Observation

        obs: list[Observation] = [
            Observation(
                type="http_endpoint",
                asset_id=asset_id,
                source="http",
                data={
                    "url": self.url,
                    "final_url": self.final_url,
                    "status_code": self.status_code,
                    "content_length": self.content_length,
                    "content_type": self.content_type,
                    "title": self.title,
                    "redirect_chain": list(self.redirect_chain),
                },
                task_id=task_id,
            )
        ]
        return obs


@dataclass(frozen=True)
class BaselineResponse:
    """Baseline response used to detect wildcard 200 responses and reduce false positives."""

    target_url: str
    status_code: int
    content_length: int
    word_count: int
    line_count: int
    body_hash: str
    title: str | None = None
    is_wildcard_200: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "word_count": self.word_count,
            "line_count": self.line_count,
            "body_hash": self.body_hash,
            "title": self.title,
            "is_wildcard_200": self.is_wildcard_200,
        }


@dataclass(frozen=True)
class EndpointDecision:
    """Classification of whether a discovered endpoint is genuinely distinct or a wildcard match."""

    url: str
    status_code: int
    is_distinct: bool
    reason: str
    similarity_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "is_distinct": self.is_distinct,
            "reason": self.reason,
            "similarity_score": self.similarity_score,
        }
