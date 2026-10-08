"""HTTP engine for baseline establishment, wildcard 200 detection, and redirect validation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from reconx.models.http import (
    BaselineResponse,
    EndpointDecision,
    HTTPResponse,
)
from reconx.parsers.http import HeaderAnalyzer
from reconx.tools.curl import CurlAdapter

if TYPE_CHECKING:
    from reconx.scope.validator import ScopeValidator

logger = logging.getLogger("reconx.tools.http_engine")


class BaselineDetector:
    """Detects wildcard 200 responses and accurately distinguishes real endpoints from false positives."""

    def build_baseline(self, target_url: str, probe_response: HTTPResponse) -> BaselineResponse:
        """Construct a BaselineResponse from an intentionally non-existent path probe."""
        # Non-existent path returning 2xx indicates wildcard 200 handling (e.g. SPA / catch-all)
        is_wildcard = probe_response.is_success

        return BaselineResponse(
            target_url=target_url,
            status_code=probe_response.status_code,
            content_length=probe_response.content_length,
            word_count=probe_response.word_count,
            line_count=probe_response.line_count,
            body_hash=probe_response.body_hash,
            title=probe_response.title,
            is_wildcard_200=is_wildcard,
        )

    def evaluate_endpoint(
        self,
        candidate: HTTPResponse,
        baseline: BaselineResponse,
        length_tolerance_bytes: int = 50,
        length_tolerance_ratio: float = 0.05,
    ) -> EndpointDecision:
        """Accurately distinguish a real discovered endpoint from a wildcard 200 response."""
        # 1. Server does not have wildcard 200:
        if not baseline.is_wildcard_200:
            if candidate.is_success and baseline.status_code != candidate.status_code:
                return EndpointDecision(
                    url=candidate.url,
                    status_code=candidate.status_code,
                    is_distinct=True,
                    reason="status_code_divergence",
                    similarity_score=0.0,
                )
            if candidate.status_code == baseline.status_code:
                return EndpointDecision(
                    url=candidate.url,
                    status_code=candidate.status_code,
                    is_distinct=False,
                    reason="baseline_status_match",
                    similarity_score=1.0,
                )
            # Other status (e.g. 403, 301, 500)
            return EndpointDecision(
                url=candidate.url,
                status_code=candidate.status_code,
                is_distinct=True,
                reason="distinct_status_code",
                similarity_score=0.1,
            )

        # 2. Server DOES have wildcard 200:
        # Non-success responses (redirects, auth required, server errors) are distinct from 200 catch-all
        if not candidate.is_success:
            return EndpointDecision(
                url=candidate.url,
                status_code=candidate.status_code,
                is_distinct=True,
                reason="non_200_status",
                similarity_score=0.0,
            )

        # Candidate is 200: compare content against wildcard baseline
        # Exact body hash match -> confirmed wildcard template
        if candidate.body_hash == baseline.body_hash:
            return EndpointDecision(
                url=candidate.url,
                status_code=candidate.status_code,
                is_distinct=False,
                reason="exact_wildcard_hash_match",
                similarity_score=1.0,
            )

        # Title check: if candidate has a different non-empty title -> distinct page
        title_different = False
        if candidate.title and baseline.title and candidate.title.strip().lower() != baseline.title.strip().lower():
            title_different = True
        elif candidate.title and not baseline.title:
            title_different = True

        length_diff = abs(candidate.content_length - baseline.content_length)
        threshold = max(length_tolerance_bytes, int(baseline.content_length * length_tolerance_ratio))

        # Distinct title and significant length divergence -> real endpoint
        if title_different and length_diff > length_tolerance_bytes:
            return EndpointDecision(
                url=candidate.url,
                status_code=candidate.status_code,
                is_distinct=True,
                reason="distinct_title_and_length",
                similarity_score=0.15,
            )

        # Significant content length divergence
        if length_diff > threshold * 2:
            return EndpointDecision(
                url=candidate.url,
                status_code=candidate.status_code,
                is_distinct=True,
                reason="significant_length_divergence",
                similarity_score=0.25,
            )

        # Line/word count divergence check
        word_diff = abs(candidate.word_count - baseline.word_count)
        if word_diff > 25 and title_different:
            return EndpointDecision(
                url=candidate.url,
                status_code=candidate.status_code,
                is_distinct=True,
                reason="distinct_word_count_and_title",
                similarity_score=0.3,
            )

        # Content length, title, and structure closely match the wildcard template -> false positive
        return EndpointDecision(
            url=candidate.url,
            status_code=candidate.status_code,
            is_distinct=False,
            reason="wildcard_template_match",
            similarity_score=0.92,
        )


class HTTPEngine:
    """Coordinates HTTP tool adapters, header analysis, baseline verification, and redirect safety."""

    def __init__(
        self,
        adapter: CurlAdapter | None = None,
        header_analyzer: HeaderAnalyzer | None = None,
        baseline_detector: BaselineDetector | None = None,
    ) -> None:
        self.adapter = adapter if adapter is not None else CurlAdapter()
        self.header_analyzer = header_analyzer if header_analyzer is not None else HeaderAnalyzer()
        self.baseline_detector = baseline_detector if baseline_detector is not None else BaselineDetector()

    def generate_baseline_url(self, base_url: str, suffix: str = "_reconx_nonexistent_probe_404") -> str:
        """Construct a deterministic probe URL guaranteed to not exist on normal web applications."""
        clean = base_url.rstrip("/")
        return f"{clean}/{suffix}"

    def validate_redirects(
        self,
        response: HTTPResponse,
        scope: ScopeValidator | None = None,
    ) -> bool:
        """Validate all redirect targets against scope rules.
        
        Returns True if all redirect steps remain in-scope or if no scope is configured.
        Returns False if any redirect target violates scope boundaries.
        """
        if scope is None:
            return True

        current_url = response.url
        for target_loc in response.redirect_chain:
            decision = scope.check_redirect(current_url, target_loc)
            if not decision.allowed:
                logger.warning(
                    "Redirect from %s to %s rejected by scope policy: %s",
                    current_url,
                    target_loc,
                    decision.reason.value,
                )
                return False
            current_url = urljoin(current_url, target_loc)

        return True
