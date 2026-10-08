"""Deduplication and canonical fingerprinting engine for ReconX observations.

Provides canonical normalization and fingerprinting for:
- Web endpoints, URLs, and query parameters
- Vulnerability vectors and categories
- Multi-tool observation clustering
- Host-level vs endpoint-level vs parameter-level deduplication
"""

from __future__ import annotations

from dataclasses import dataclass
import functools
import hashlib
import re
from typing import Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from reconx.engine.classification import VulnerabilityCategory, VulnerabilityClassifier
from reconx.models.observation import Observation

_RE_MULTI_SLASH = re.compile(r"/{2,}")
_RE_PARAM_DECORATION = re.compile(r"\(.*?\)")


# Common cache-buster or tracking parameters to ignore during canonicalization
EPHEMERAL_PARAMS = frozenset({"_", "timestamp", "cb", "cachebust", "utm_source", "utm_medium", "utm_campaign"})

# Host-level finding keywords that should be deduplicated across endpoints on the same host
HOST_LEVEL_CATEGORIES = frozenset({
    VulnerabilityCategory.SECURITY_MISCONFIGURATION,
    VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES,
    VulnerabilityCategory.NETWORK_EXPOSURE,
})


@functools.lru_cache(maxsize=2048)
def normalize_url(url: str, base_target: str | None = None) -> str:
    """Normalize a URL to its canonical form.

    - Resolves scheme and host to lowercase
    - Strips standard default ports (80 for http, 443 for https)
    - Normalizes duplicate slashes in path
    - Sorts query parameters and removes ephemeral cache busters
    - Strips fragment
    """
    clean = url.strip()
    if not clean:
        return ""

    clean_lower = clean.lower()
    # If endpoint is a relative path and base_target is provided, construct full URL
    if not clean_lower.startswith(("http://", "https://")):
        if base_target:
            base = base_target.strip().lower()
            if not base.startswith(("http://", "https://")):
                base = f"http://{base}"
            if not clean.startswith("/"):
                clean = f"/{clean}"
            clean = f"{base}{clean}"
        else:
            # Normalize standalone path
            clean = _RE_MULTI_SLASH.sub("/", clean)
            return clean

    parsed = urlparse(clean)
    scheme = parsed.scheme.lower() or "http"
    netloc = parsed.netloc.lower()

    # Normalize port
    if ":" in netloc:
        host, port_str = netloc.split(":", 1)
        try:
            port = int(port_str)
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = host
        except ValueError:
            pass

    # Normalize path: collapse // to /
    path = _RE_MULTI_SLASH.sub("/", parsed.path)
    if not path:
        path = "/"
    elif len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Normalize query parameters: sort and filter ephemeral
    query = ""
    if parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        filtered = [(k.lower(), v) for k, v in query_pairs if k.lower() not in EPHEMERAL_PARAMS]
        filtered.sort(key=lambda pair: pair[0])
        query = urlencode(filtered)

    return urlunparse((scheme, netloc, path, "", query, ""))


@functools.lru_cache(maxsize=1024)
def extract_url_path(url: str) -> str:
    """Extract scheme, host, and path without query string."""
    norm = normalize_url(url)
    parsed = urlparse(norm)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


@functools.lru_cache(maxsize=512)
def normalize_parameter(param: str | None) -> str | None:
    """Normalize parameter name."""
    if not param:
        return None
    cleaned = param.strip().lower()
    # Strip common parameter decorations like GET/POST or brackets
    cleaned = _RE_PARAM_DECORATION.sub("", cleaned).strip()
    return cleaned or None


@dataclass(frozen=True)
class DeduplicationFingerprint:
    """Deterministic deduplication fingerprint for an observation or finding."""

    fingerprint: str
    canonical_key: tuple[str, ...]
    scope_level: str  # "parameter", "endpoint", "host"


class VulnerabilityDeduplicator:
    """Clusters and deduplicates vulnerability observations into canonical units."""

    def __init__(self, classifier: VulnerabilityClassifier | None = None) -> None:
        self._classifier = classifier or VulnerabilityClassifier()

    def compute_fingerprint(self, obs: Observation) -> DeduplicationFingerprint:
        """Compute a canonical fingerprint for an observation."""
        data = obs.data or {}
        classification = self._classifier.classify_observation(obs)

        asset_id = obs.asset_id or "unknown_asset"
        raw_endpoint = data.get("endpoint") or ""
        target = data.get("target") or ""
        norm_url = normalize_url(raw_endpoint, base_target=target)
        parsed_url = urlparse(norm_url)
        host = parsed_url.netloc or target or "unknown_host"

        param = normalize_parameter(data.get("parameter"))
        cve = classification.cve or data.get("cve")

        # Determine deduplication scope level
        # 1. Parameter-level: injection flaws with an identifiable parameter
        if param and classification.category == VulnerabilityCategory.INJECTION:
            base_url = extract_url_path(norm_url) or host
            canonical_key = (
                "param",
                asset_id,
                base_url,
                param,
                classification.category.value,
                classification.cwe_id or "CWE-89",
            )
            scope_level = "parameter"

        # 2. Host-level: site-wide misconfigurations (missing headers, SSL/TLS, banners)
        elif (
            classification.category in HOST_LEVEL_CATEGORIES
            and not data.get("parameter")
            and not (cve and "endpoint" in raw_endpoint.lower())
        ):
            cwe_or_title = classification.cwe_id or data.get("title", "misconfig").lower()
            canonical_key = (
                "host",
                asset_id,
                host,
                classification.category.value,
                cwe_or_title,
            )
            scope_level = "host"

        # 3. Endpoint-level: specific URL path vulnerabilities (LFI, exposed files, directory listing)
        else:
            base_url = extract_url_path(norm_url) or f"{host}/{raw_endpoint.lstrip('/')}"
            key_vector = cve or classification.cwe_id or classification.category.value
            canonical_key = (
                "endpoint",
                asset_id,
                base_url,
                classification.category.value,
                key_vector,
            )
            scope_level = "endpoint"

        # Deterministic SHA-256 fingerprint
        key_str = "|".join(canonical_key)
        fp_hash = hashlib.sha256(key_str.encode("utf-8")).hexdigest()

        return DeduplicationFingerprint(
            fingerprint=fp_hash,
            canonical_key=canonical_key,
            scope_level=scope_level,
        )

    def cluster(
        self,
        observations: Sequence[Observation],
    ) -> dict[str, list[Observation]]:
        """Cluster observations by their canonical deduplication fingerprint."""
        clusters: dict[str, list[Observation]] = {}
        for obs in observations:
            fp = self.compute_fingerprint(obs)
            clusters.setdefault(fp.fingerprint, []).append(obs)
        return clusters
