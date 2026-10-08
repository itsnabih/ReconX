"""Domain models for security scan reports.

Enforces Phase 11 Acceptance Criteria:
'All formats originate from the same ReportModel.'
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import re

from reconx import __version__
from reconx.models.finding import Severity
from reconx.models.scan import ScanState
from reconx.reporting.redaction import SecretRedactor
from reconx.risk.scoring import RiskAssessment, RiskEngine


@dataclass(frozen=True)
class ExecutiveSummary:
    """High-level executive metrics and findings overview."""

    target: str
    scan_date: str
    duration_seconds: float
    scope_summary: str
    total_assets: int
    total_findings: int
    severity_distribution: dict[str, int]
    risk_score_summary: str


@dataclass(frozen=True)
class AttackSurfaceSummary:
    """Discovered attack surface inventory."""

    domains: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReportFinding:
    """Structured security finding entry in the report."""

    id: str
    title: str
    severity: str
    confidence: float
    confidence_level: str
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_status: str
    cvss_rationale: str
    affected_asset: str
    endpoint: str | None
    description: str
    impact: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReportAppendix:
    """Technical execution metadata and diagnostics."""

    reconx_version: str
    tool_versions: dict[str, str] = field(default_factory=dict)
    scan_configuration: dict[str, Any] = field(default_factory=dict)
    executed_modules: list[str] = field(default_factory=list)
    excluded_modules: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    incomplete_tasks: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReportModel:
    """Canonical normalized report model.

    All report formats (JSON, Markdown, HTML, PDF) MUST originate from this single model.
    """

    scan_id: str
    target: str
    title: str
    generated_at: str
    executive_summary: ExecutiveSummary
    attack_surface: AttackSurfaceSummary
    findings: list[ReportFinding]
    appendix: ReportAppendix

    def to_dict(self) -> dict[str, Any]:
        """Convert report model to clean, JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_scan_state(
        cls,
        state: ScanState,
        risk_engine: RiskEngine | None = None,
        redactor: SecretRedactor | None = None,
        tool_versions: dict[str, str] | None = None,
        cvss_version: str = "3.1",
    ) -> ReportModel:
        """Construct a canonical ReportModel from persisted ScanState."""
        engine = risk_engine or RiskEngine()
        redactor = redactor or SecretRedactor(enabled=True)

        target = state.scan.targets[0] if state.scan.targets else "Unknown Target"
        scan_id = state.scan.id
        title = f"Security Reconnaissance & Assessment Report — {target}"
        generated_at = datetime.now(timezone.utc).isoformat()

        # Calculate scan duration
        duration = 0.0
        if state.scan.started_at and state.scan.finished_at:
            duration = (state.scan.finished_at - state.scan.started_at).total_seconds()
        elif state.tasks:
            duration = sum(t.duration for t in state.tasks if t.duration is not None)

        # Severity distribution
        sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in state.findings:
            sev_key = f.severity.value
            if sev_key in sev_dist:
                sev_dist[sev_key] += 1
            else:
                sev_dist["INFO"] += 1

        # Build attack surface
        domains: set[str] = set()
        ips: set[str] = set()
        ports: set[str] = set()
        services: set[str] = set()
        urls: set[str] = set()
        endpoints: set[str] = set()
        technologies: set[str] = set()

        for asset in state.assets:
            kind_val = str(getattr(asset, "kind", "")).upper()
            val = getattr(asset, "value", getattr(asset, "identifier", None))
            if val:
                if "DOMAIN" in kind_val or "HOST" in kind_val:
                    domains.add(str(val))
                elif "IP" in kind_val:
                    ips.add(str(val))
                else:
                    domains.add(str(val))

        for obs in state.observations:
            odata = obs.data or {}
            otype = obs.type

            if otype in ("dns_a", "ip_resolved"):
                if odata.get("ip"):
                    ips.add(str(odata["ip"]))
            elif otype in ("dns_cname", "subdomain_found"):
                if odata.get("subdomain"):
                    domains.add(str(odata["subdomain"]))
                elif odata.get("cname"):
                    domains.add(str(odata["cname"]))
            elif otype in ("open_port", "service_detected"):
                p = odata.get("port")
                proto = odata.get("protocol", "tcp")
                if p:
                    ports.add(f"{p}/{proto}")
                if odata.get("service"):
                    services.add(str(odata["service"]))
            elif otype in ("endpoint_found", "url_discovered", "http_response"):
                ep = odata.get("endpoint") or odata.get("url")
                if ep:
                    endpoints.add(str(ep))
                    urls.add(str(ep))
            elif otype in ("technology_detected", "server_header"):
                tech = odata.get("technology") or odata.get("server")
                if tech:
                    technologies.add(str(tech))

        # Build evidence map
        evidence_by_id = {ev.id: ev for ev in state.evidence}
        obs_by_id = {o.id: o for o in state.observations}

        # Build ReportFindings
        report_findings: list[ReportFinding] = []
        highest_cvss_score = 0.0
        highest_cvss_sev = "INFO"

        for f in state.findings:
            # Risk assessment
            assessment: RiskAssessment = engine.assess_finding(f, cvss_version=cvss_version)
            if assessment.base_score is not None and assessment.base_score > highest_cvss_score:
                highest_cvss_score = assessment.base_score
                highest_cvss_sev = assessment.severity.value

            # Confidence level label
            conf_level = "Low"
            if f.confidence >= 0.9:
                conf_level = "Confirmed"
            elif f.confidence >= 0.7:
                conf_level = "High"
            elif f.confidence >= 0.4:
                conf_level = "Medium"

            # Gather and redact evidence
            ev_snippets: list[str] = []
            for ev_id in f.evidence_ids:
                if ev_id in evidence_by_id:
                    ev = evidence_by_id[ev_id]
                    ev_text = getattr(ev, "stdout", "") or getattr(ev, "description", "") or "Execution Evidence"
                    summary = f"[{ev.tool}] {ev_text.strip()}"
                    raw_ref = getattr(ev, "raw_reference", getattr(ev, "raw_ref", None))
                    if raw_ref:
                        summary += f" (Ref: {raw_ref})"
                    ev_snippets.append(redactor.redact_text(summary))

            # Also include rich observation details if evidence list is empty
            if not ev_snippets:
                for obs_id in f.observation_ids:
                    if obs_id in obs_by_id:
                        obs = obs_by_id[obs_id]
                        odata = obs.data or {}
                        line = f"[{obs.source}] {odata.get('title') or obs.type}"
                        if odata.get("parameter"):
                            line += f" (Parameter: {odata['parameter']})"
                        ev_snippets.append(redactor.redact_text(line))

            # Extract references from description
            refs: list[str] = []
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", f.description)
            refs.extend(cve_matches)
            cwe_matches = re.findall(r"CWE-\d+", f.description)
            refs.extend(cwe_matches)
            if "owasp" in f.description.lower():
                owasp_matches = re.findall(r"A\d{2}:\d{4}-[\w\s]+", f.description)
                refs.extend(owasp_matches)

            # Impact summary
            impact_text = f"Security impact rated as {f.severity.value}."
            if f.severity == Severity.CRITICAL:
                impact_text = "Critical risk: Flaw enables full target compromise or high-privilege arbitrary execution."
            elif f.severity == Severity.HIGH:
                impact_text = "High risk: Flaw allows unauthorized data exposure or boundary evasion."
            elif f.severity == Severity.MEDIUM:
                impact_text = "Medium risk: Flaw reveals internal state or facilitates client-side attacks."
            elif f.severity == Severity.LOW:
                impact_text = "Low risk: Information disclosure or defense-in-depth misconfiguration."

            # Remediation summary
            remediation_text = "Consult vendor documentation and follow security best practices."
            if "Remediation Guidance:" in f.description:
                parts = f.description.split("Remediation Guidance:", 1)
                remediation_text = parts[1].strip()

            report_findings.append(
                ReportFinding(
                    id=f.id,
                    title=f.title,
                    severity=f.severity.value,
                    confidence=f.confidence,
                    confidence_level=conf_level,
                    cvss_version=assessment.cvss_version,
                    cvss_score=assessment.base_score,
                    cvss_vector=assessment.vector,
                    cvss_status=assessment.review_status.value,
                    cvss_rationale=assessment.scoring_rationale,
                    affected_asset=f.asset_id,
                    endpoint=f.endpoint,
                    description=redactor.redact_text(f.description),
                    impact=impact_text,
                    evidence=ev_snippets,
                    remediation=redactor.redact_text(remediation_text),
                    references=sorted(set(refs)),
                )
            )

        # Sort findings: Critical -> High -> Medium -> Low -> Info
        _ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        report_findings.sort(key=lambda rf: (_ORDER.get(rf.severity, 0), rf.confidence), reverse=True)

        risk_score_summary = (
            f"Highest CVSS Base Score: {highest_cvss_score:.1f} ({highest_cvss_sev})"
            if highest_cvss_score > 0
            else "No critical or high CVSS vectors detected."
        )

        scope_rules_count = len(state.scan.scope.allowed_domains) + len(state.scan.scope.allowed_ips)
        scope_desc = f"{scope_rules_count} in-scope target rules ({len(state.scan.scope.excluded_domains) + len(state.scan.scope.excluded_ips)} exclusions)"

        exec_summary = ExecutiveSummary(
            target=target,
            scan_date=state.scan.created_at.isoformat(),
            duration_seconds=duration,
            scope_summary=scope_desc,
            total_assets=len(state.assets),
            total_findings=len(state.findings),
            severity_distribution=sev_dist,
            risk_score_summary=risk_score_summary,
        )

        attack_surface = AttackSurfaceSummary(
            domains=sorted(domains),
            ip_addresses=sorted(ips),
            ports=sorted(ports),
            services=sorted(services),
            urls=sorted(urls),
            endpoints=sorted(endpoints),
            technologies=sorted(technologies),
        )

        # Appendix
        executed_modules = sorted({(t.command[0] if t.command else t.type) for t in state.tasks})
        incomplete = [
            f"{t.id} ({t.command[0] if t.command else t.type}): {t.state.value}"
            for t in state.tasks
            if t.state.value in ("FAILED", "TIMEOUT", "CANCELLED")
        ]
        errors: list[str] = []
        for t in state.tasks:
            err = getattr(t.result, "error_message", None) if t.result else None
            if err:
                tool_label = t.command[0] if t.command else t.type
                errors.append(f"Task {t.id} ({tool_label}): {err}")

        appendix = ReportAppendix(
            reconx_version=state.scan.reconx_version or __version__,
            tool_versions=tool_versions or {},
            scan_configuration={
                "scan_id": scan_id,
                "targets": list(state.scan.targets),
                "status": state.scan.status.value,
            },
            executed_modules=executed_modules,
            excluded_modules=[],
            errors=errors,
            incomplete_tasks=incomplete,
        )

        return cls(
            scan_id=scan_id,
            target=target,
            title=title,
            generated_at=generated_at,
            executive_summary=exec_summary,
            attack_surface=attack_surface,
            findings=report_findings,
            appendix=appendix,
        )
