"""Domain model for web endpoint discovery and multi-tool deduplication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit

from reconx.models.observation import Observation


def normalize_endpoint_key(url: str, path: str = "") -> str:
    """Compute a canonical key for endpoint deduplication.

    Normalizes scheme and host to lowercase, strips standard default ports (:80, :443),
    normalizes path by removing redundant trailing slashes (except root '/'),
    canonicalizes and sorts query parameters alphabetically, and drops URL fragments.
    """
    target = url.strip()
    if not target and path:
        target = path.strip()

    if "://" in target:
        parsed = urlsplit(target)
        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc.lower()

        # Strip standard default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        raw_path = parsed.path or "/"
        clean_path = raw_path.rstrip("/") if raw_path != "/" else "/"
        if not clean_path:
            clean_path = "/"

        # Canonicalize and sort query parameters
        query_str = ""
        if parsed.query:
            sorted_q = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
            if sorted_q:
                query_str = f"?{sorted_q}"

        return f"{scheme}://{netloc}{clean_path}{query_str}"

    # Path-only normalization with optional query parameters
    base_part, _, raw_query = target.partition("?")
    clean = base_part.rstrip("/") if base_part != "/" else "/"
    if not clean.startswith("/"):
        clean = f"/{clean}"

    query_str = ""
    if raw_query:
        sorted_q = urlencode(sorted(parse_qsl(raw_query, keep_blank_values=True)))
        if sorted_q:
            query_str = f"?{sorted_q}"

    return f"{clean}{query_str}"


@dataclass(frozen=True)
class DiscoveredEndpoint:
    """Normalized representation of a discovered web directory or endpoint.

    Fulfills Section 15 of Implementation.md with multi-source attribution.
    """

    url: str
    path: str
    status_code: int
    content_length: int | None = None
    sources: tuple[str, ...] = ()
    word_count: int | None = None
    line_count: int | None = None
    redirect_location: str | None = None
    content_type: str | None = None
    duration_ms: float | None = None

    def __post_init__(self) -> None:
        if not self.url and not self.path:
            raise ValueError("Endpoint requires either url or path")
        if self.status_code < 0:
            raise ValueError("status_code must be non-negative")
        if self.content_length is not None and self.content_length < 0:
            raise ValueError("content_length must be non-negative")
        # Ensure sources is a sorted tuple with no duplicates
        object.__setattr__(self, "sources", tuple(sorted(set(self.sources))))

    @property
    def key(self) -> str:
        """Return the canonical deduplication key."""
        return normalize_endpoint_key(self.url, self.path)

    def to_dict(self) -> dict[str, Any]:
        """Serialize endpoint into a dictionary suitable for JSON and Observation data."""
        return {
            "url": self.url,
            "path": self.path,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "sources": list(self.sources),
            "word_count": self.word_count,
            "line_count": self.line_count,
            "redirect_location": self.redirect_location,
            "content_type": self.content_type,
            "duration_ms": self.duration_ms,
        }


class EndpointCollection:
    """Container for discovered endpoints that deduplicates across multiple tools."""

    def __init__(self) -> None:
        self._endpoints: dict[str, DiscoveredEndpoint] = {}

    def add(self, endpoint: DiscoveredEndpoint) -> DiscoveredEndpoint:
        """Add an endpoint to the collection, merging metadata and sources if duplicate."""
        key = endpoint.key
        existing = self._endpoints.get(key)
        if existing is None:
            self._endpoints[key] = endpoint
            return endpoint

        # Merge sources preserving uniqueness and alphabetical sorting
        merged_sources = tuple(sorted(set(existing.sources + endpoint.sources)))

        # Keep best available metadata
        merged_status = existing.status_code if existing.status_code != 0 else endpoint.status_code
        merged_length = (
            existing.content_length
            if existing.content_length is not None
            else endpoint.content_length
        )
        merged_words = (
            existing.word_count
            if existing.word_count is not None
            else endpoint.word_count
        )
        merged_lines = (
            existing.line_count
            if existing.line_count is not None
            else endpoint.line_count
        )
        merged_redirect = existing.redirect_location or endpoint.redirect_location
        merged_content_type = existing.content_type or endpoint.content_type
        merged_duration = (
            existing.duration_ms
            if existing.duration_ms is not None
            else endpoint.duration_ms
        )

        merged = DiscoveredEndpoint(
            url=existing.url,
            path=existing.path,
            status_code=merged_status,
            content_length=merged_length,
            sources=merged_sources,
            word_count=merged_words,
            line_count=merged_lines,
            redirect_location=merged_redirect,
            content_type=merged_content_type,
            duration_ms=merged_duration,
        )
        self._endpoints[key] = merged
        return merged

    def add_all(self, endpoints: Iterable[DiscoveredEndpoint]) -> None:
        """Add multiple endpoints into the collection."""
        for ep in endpoints:
            self.add(ep)

    def get(self, key_or_url: str) -> DiscoveredEndpoint | None:
        """Lookup an endpoint by URL, path, or canonical key."""
        key = normalize_endpoint_key(key_or_url)
        if key in self._endpoints:
            return self._endpoints[key]

        # Path-based lookup fallback
        if "://" not in key_or_url:
            norm_path = normalize_endpoint_key("", key_or_url)
            for ep in self._endpoints.values():
                if normalize_endpoint_key("", ep.path) == norm_path:
                    return ep

        return None

    def get_by_source(self, source: str) -> list[DiscoveredEndpoint]:
        """Return all endpoints discovered by a specific source tool."""
        src_lower = source.strip().lower()
        return [
            ep for ep in self.endpoints
            if any(s.lower() == src_lower for s in ep.sources)
        ]

    def get_by_status(self, status_code: int) -> list[DiscoveredEndpoint]:
        """Return all endpoints matching a specific HTTP status code."""
        return [ep for ep in self.endpoints if ep.status_code == status_code]

    @property
    def endpoints(self) -> list[DiscoveredEndpoint]:
        """Return all deduplicated endpoints sorted by path/URL."""
        return sorted(self._endpoints.values(), key=lambda e: (e.path, e.url))

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert deduplicated endpoints into normalized domain Observations.

        Fulfills Acceptance Criteria:
        'The same endpoint found by multiple tools becomes one normalized observation with multiple sources.'
        """
        observations: list[Observation] = []
        for ep in self.endpoints:
            obs = Observation(
                type="discovered_endpoint",
                asset_id=asset_id,
                source=",".join(ep.sources) if ep.sources else "web_enumeration",
                data=ep.to_dict(),
                task_id=task_id,
            )
            observations.append(obs)
        return observations

    def clear(self) -> None:
        """Remove all endpoints from the collection."""
        self._endpoints.clear()

    def __len__(self) -> int:
        return len(self._endpoints)

    def __iter__(self) -> Iterator[DiscoveredEndpoint]:
        return iter(self.endpoints)

    def __contains__(self, key_or_url: str) -> bool:
        return self.get(key_or_url) is not None

