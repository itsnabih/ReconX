"""Finding correlation and intelligence engine for ReconX.

Integrates:
- Deduplication and canonical clustering
- Taxonomy classification (CWE, OWASP Top 10)
- Multi-source corroborative confidence scoring
- Evidence enrichment and provenance tracking

Fulfills Phase 9 Acceptance Criteria:
'Multiple observations can produce a single high-confidence finding.'
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence
from urllib.parse import urlparse

from reconx.engine.classification import (
    ClassificationResult,
    VulnerabilityCategory,
    VulnerabilityClassifier,
)
from reconx.engine.confidence import ConfidenceAssessment, ConfidenceScorer
from reconx.engine.deduplication import (
    VulnerabilityDeduplicator,
    normalize_parameter,
    normalize_url,
)
from reconx.models.evidence import Evidence
from reconx.models.finding import Finding, Severity
from reconx.models.observation import Observation


# Severity hierarchy for selecting the most appropriate severity in a cluster
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_STR_TO_SEVERITY: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass(frozen=True)
class CorrelationResult:
    """Summary of finding correlation execution."""

    findings: list[Finding]
    raw_observation_count: int
    deduplicated_clusters_count: int
    high_confidence_findings_count: int


class FindingCorrelator:
    """Correlates security observations into enriched, deduplicated findings."""

    def __init__(
        self,
        classifier: VulnerabilityClassifier | None = None,
        confidence_scorer: ConfidenceScorer | None = None,
        deduplicator: VulnerabilityDeduplicator | None = None,
    ) -> None:
        self.classifier = classifier or VulnerabilityClassifier()
        self.confidence_scorer = confidence_scorer or ConfidenceScorer()
        self.deduplicator = deduplicator or VulnerabilityDeduplicator(self.classifier)

    def correlate(
        self,
        observations: Sequence[Observation],
        evidence: Sequence[Evidence] = (),
        asset_id: str | None = None,
    ) -> list[Finding]:
        """Correlate observations into deduplicated, confidence-scored Finding objects."""
        result = self.correlate_detailed(observations, evidence=evidence, default_asset_id=asset_id)
        return result.findings

    def correlate_detailed(
        self,
        observations: Sequence[Observation],
        evidence: Sequence[Evidence] = (),
        default_asset_id: str | None = None,
    ) -> CorrelationResult:
        """Execute full finding correlation pipeline with summary statistics."""
        if not observations:
            return CorrelationResult(
                findings=[],
                raw_observation_count=0,
                deduplicated_clusters_count=0,
                high_confidence_findings_count=0,
            )

        # 1. Cluster observations by canonical deduplication fingerprint
        clusters = self.deduplicator.cluster(observations)

        findings: list[Finding] = []
        for fingerprint, cluster_obs in clusters.items():
            finding = self._synthesize_finding(
                cluster_obs=cluster_obs,
                evidence=evidence,
                default_asset_id=default_asset_id,
            )
            findings.append(finding)

        # Sort findings: severity descending, then confidence descending
        findings.sort(
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, 0), f.confidence),
            reverse=True,
        )

        high_conf_count = sum(1 for f in findings if f.confidence >= 0.70)

        return CorrelationResult(
            findings=findings,
            raw_observation_count=len(observations),
            deduplicated_clusters_count=len(clusters),
            high_confidence_findings_count=high_conf_count,
        )

    def _synthesize_finding(
        self,
        cluster_obs: list[Observation],
        evidence: Sequence[Evidence],
        default_asset_id: str | None,
    ) -> Finding:
        """Synthesize a cluster of related observations into a single canonical Finding."""
        # Determine asset ID
        asset_id = default_asset_id or cluster_obs[0].asset_id or "unknown_asset"

        # Gather supporting observation IDs (strictly deduplicated)
        obs_ids: list[str] = []
        for obs in cluster_obs:
            if obs.id not in obs_ids:
                obs_ids.append(obs.id)

        # Match supporting evidence IDs from task IDs or tool/target
        cluster_task_ids = {obs.task_id for obs in cluster_obs if obs.task_id}
        cluster_sources = {obs.source.lower() for obs in cluster_obs if obs.source}
        ev_ids: list[str] = []
        for ev in evidence:
            if ev.task_id and ev.task_id in cluster_task_ids:
                if ev.id not in ev_ids:
                    ev_ids.append(ev.id)
            elif ev.tool.lower() in cluster_sources:
                if ev.id not in ev_ids:
                    ev_ids.append(ev.id)

        # Extract representative attributes across cluster observations
        representative_obs = self._select_richest_observation(cluster_obs)
        rep_data = representative_obs.data or {}

        # Classify the vulnerability
        classification = self.classifier.classify_observation(representative_obs)

        # Evaluate corroborative confidence score
        confidence_assessment: ConfidenceAssessment = self.confidence_scorer.evaluate(
            observations=cluster_obs,
            evidence=evidence,
        )

        # Determine consolidated severity
        severity = self._resolve_severity(cluster_obs, classification)

        # Determine canonical endpoint and parameter
        raw_endpoint = rep_data.get("endpoint") or ""
        target = rep_data.get("target") or ""
        norm_endpoint = normalize_url(raw_endpoint, base_target=target) or None
        parameter = normalize_parameter(rep_data.get("parameter"))

        # Build clean canonical title
        title = self._build_title(
            classification=classification,
            representative_data=rep_data,
            endpoint=norm_endpoint,
            parameter=parameter,
        )

        # Build enriched description
        description = self._build_description(
            title=title,
            classification=classification,
            confidence_assessment=confidence_assessment,
            cluster_obs=cluster_obs,
            endpoint=norm_endpoint,
            parameter=parameter,
        )

        return Finding(
            finding_type=classification.category.value,
            title=title,
            asset_id=asset_id,
            severity=severity,
            confidence=confidence_assessment.score,
            description=description,
            endpoint=norm_endpoint,
            observation_ids=tuple(obs_ids),
            evidence_ids=tuple(ev_ids),
        )

    def _select_richest_observation(self, cluster_obs: list[Observation]) -> Observation:
        """Select the observation with the most informative metadata in the cluster."""
        def score_obs(obs: Observation) -> int:
            data = obs.data or {}
            score = 0
            if data.get("parameter"):
                score += 10
            if data.get("injection_type"):
                score += 10
            if data.get("cve"):
                score += 8
            if data.get("description"):
                score += 5
            # Active tools carry higher detail
            if (obs.source or "").lower() == "sqlmap":
                score += 15
            return score

        return max(cluster_obs, key=score_obs)

    def _resolve_severity(
        self,
        cluster_obs: list[Observation],
        classification: ClassificationResult,
    ) -> Severity:
        """Determine consolidated severity rating for the finding cluster."""
        highest_order = -1
        highest_severity = classification.default_severity

        # Check all explicit observation severities
        for obs in cluster_obs:
            raw_sev = (obs.data or {}).get("severity", "").lower()
            if raw_sev in _STR_TO_SEVERITY:
                sev = _STR_TO_SEVERITY[raw_sev]
                order = _SEVERITY_ORDER.get(sev, 0)
                if order > highest_order:
                    highest_order = order
                    highest_severity = sev

        # If observation severity is lower than taxonomy default for critical flaw, upgrade
        default_order = _SEVERITY_ORDER.get(classification.default_severity, 0)
        if default_order > highest_order:
            highest_severity = classification.default_severity

        return highest_severity

    def _build_title(
        self,
        classification: ClassificationResult,
        representative_data: dict[str, Any],
        endpoint: str | None,
        parameter: str | None,
    ) -> str:
        """Construct a standardized, descriptive title for the finding."""
        cve = classification.cve or representative_data.get("cve")

        # Specific titles for Injection
        if classification.category == VulnerabilityCategory.INJECTION:
            base_name = "SQL Injection" if "sql" in (classification.cwe_name or "").lower() else "Injection Vulnerability"
            if parameter and endpoint:
                path = urlparse(endpoint).path or endpoint
                return f"{base_name} on {path} (Parameter: {parameter})"
            if parameter:
                return f"{base_name} (Parameter: {parameter})"
            if endpoint:
                path = urlparse(endpoint).path or endpoint
                return f"{base_name} on {path}"
            return base_name

        # Specific titles for Sensitive files / Directory listing
        if classification.category == VulnerabilityCategory.INFORMATION_DISCLOSURE:
            if "directory" in (classification.cwe_name or "").lower():
                path = urlparse(endpoint).path if endpoint else ""
                return f"Directory Listing Enabled on {path}" if path else "Directory Listing Enabled"
            if representative_data.get("title"):
                return representative_data["title"]

        # Security misconfiguration (Headers, Cookies)
        if classification.category == VulnerabilityCategory.SECURITY_MISCONFIGURATION:
            orig_title = representative_data.get("title", "")
            if "header" in orig_title.lower() or "cookie" in orig_title.lower():
                return orig_title

        # CVE findings
        if cve:
            return f"{cve}: {representative_data.get('title') or classification.cwe_name or 'Known Vulnerability'}"

        # General fallback
        return representative_data.get("title") or classification.cwe_name or "Security Finding"

    def _build_description(
        self,
        title: str,
        classification: ClassificationResult,
        confidence_assessment: ConfidenceAssessment,
        cluster_obs: list[Observation],
        endpoint: str | None,
        parameter: str | None,
    ) -> str:
        """Compose comprehensive technical description for the finding."""
        lines: list[str] = [
            f"### Vulnerability Summary: {title}",
            "",
            f"- **Category:** {classification.category.value}",
        ]

        if classification.owasp_category:
            lines.append(f"- **OWASP Top 10:** {classification.owasp_category}")
        if classification.cwe_id:
            cwe_info = f"{classification.cwe_id}"
            if classification.cwe_name:
                cwe_info += f" ({classification.cwe_name})"
            lines.append(f"- **CWE:** {cwe_info}")
        if classification.cve:
            lines.append(f"- **CVE:** {classification.cve}")
        if endpoint:
            lines.append(f"- **Endpoint:** {endpoint}")
        if parameter:
            lines.append(f"- **Parameter:** {parameter}")

        lines.extend([
            f"- **Confidence Score:** {confidence_assessment.score:.2f} ({confidence_assessment.confidence_level})",
            f"- **Corroborating Tools:** {', '.join(confidence_assessment.sources)}",
            "",
            f"**Analysis Rationale:** {confidence_assessment.rationale}",
            "",
            "**Observations:**",
        ])

        for obs in cluster_obs:
            tool = obs.source
            odata = obs.data or {}
            otitle = odata.get("title", obs.type)
            inj = odata.get("injection_type")
            detail = f"- [{tool}] {otitle}"
            if inj:
                detail += f" (Technique: {inj})"
            lines.append(detail)

        if classification.remediation:
            lines.extend([
                "",
                "**Remediation Guidance:**",
                classification.remediation,
            ])

        return "\n".join(lines)
