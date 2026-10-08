"""Risk assessment engine and CVSS scoring orchestration for ReconX.

Integrates:
- CVSS 3.1 and CVSS 4.0 base score computation
- Reproducible vector generation and validation
- Qualitative severity mapping
- Transparent scoring rationale
- Explicit manual review status (REQUIRES_REVIEW vs ASSESSED)

Fulfills Phase 10 Acceptance Criteria:
'Every risk score has a reproducible vector/rationale or is explicitly marked as requiring review.'
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from reconx.models.finding import Finding, Severity
from reconx.risk.cvss31 import CVSS31Calculator, CVSS31Metrics
from reconx.risk.cvss31 import score_to_severity as score_to_severity_31
from reconx.risk.cvss40 import CVSS40Calculator, CVSS40Metrics
from reconx.risk.cvss40 import score_to_severity as score_to_severity_40


class ReviewStatus(str, Enum):
    """Assessment status for CVSS risk scores."""

    ASSESSED = "ASSESSED"                  # Verified, reproducible score with complete vector
    REQUIRES_REVIEW = "REQUIRES_REVIEW"    # Incomplete or ambiguous metrics; requires analyst validation


@dataclass(frozen=True)
class RiskAssessment:
    """Standardized risk scoring result for a Finding."""

    cvss_version: str                      # "3.1" or "4.0"
    base_score: float | None               # 0.0 to 10.0 or None if requiring review
    severity: Severity                     # INFO, LOW, MEDIUM, HIGH, CRITICAL
    vector: str | None                     # Canonical reproducible vector string
    review_status: ReviewStatus            # ASSESSED or REQUIRES_REVIEW
    scoring_rationale: str                 # Detailed justification for metric assignments
    review_reasons: tuple[str, ...] = ()   # Explicit reasons why manual review is needed
    finding_id: str | None = None          # Associated finding ID if linked


# Pre-defined evidence-driven baseline metric archetypes for common vulnerability patterns
_CVSS31_ARCHETYPES: dict[str, dict[str, str]] = {
    # SQL Injection on network parameter
    "sqli": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N",
        "rationale": "Remote unauthenticated SQL injection on network endpoint allows full read/write database access without user interaction.",
    },
    # Remote OS Command Injection / RCE
    "rce": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "rationale": "Arbitrary OS command execution yields complete compromise of confidentiality, integrity, and availability on the target host.",
    },
    # Reflected Cross-Site Scripting (XSS)
    "xss": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N",
        "rationale": "Reflected XSS requires user interaction and executes in victim browser context with scope transition.",
    },
    # Path Traversal / LFI
    "path_traversal": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N",
        "rationale": "Directory traversal allows arbitrary file reading of sensitive host files over network without credentials.",
    },
    # Exposed Backup / Sensitive Config Files
    "sensitive_files": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N",
        "rationale": "Publicly accessible sensitive backup/configuration file leaks credentials and internal state.",
    },
    # Directory Listing / Indexing
    "directory_indexing": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N",
        "rationale": "Directory browsing reveals internal directory structure and resource names with low confidentiality impact.",
    },
    # Missing Security Headers (X-Frame-Options, CSP)
    "missing_headers": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N",
        "rationale": "Missing defense-in-depth security headers facilitate UI redressing or content injection requiring user interaction.",
    },
    # Insecure Cookie Flags (Missing Secure/HttpOnly)
    "insecure_cookie": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N",
        "rationale": "Missing HttpOnly/Secure flags on cookies may expose session tokens to script access or unencrypted transport.",
    },
    # Cleartext Transmission / Deprecated TLS
    "cleartext_tls": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N",
        "rationale": "Weak ciphers or cleartext transport expose network traffic to interception under elevated adversary position.",
    },
    # SSRF
    "ssrf": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "N", "A": "N",
        "rationale": "Server-side request forgery allows internal host scanning and metadata service querying across network boundaries.",
    },
}

_CVSS40_ARCHETYPES: dict[str, dict[str, str]] = {
    # SQL Injection
    "sqli": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Network exploitable SQL injection yields high confidentiality and integrity impact on vulnerable database.",
    },
    # Remote OS Command Execution
    "rce": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H",
        "rationale": "Remote code execution achieves full compromise across vulnerable host and subsequent connected systems.",
    },
    # Reflected XSS
    "xss": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A",
        "VC": "N", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Reflected XSS requires active user interaction with low integrity impact on victim session.",
    },
    # Path Traversal
    "path_traversal": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Arbitrary file reading provides high confidentiality exposure without affecting integrity or availability.",
    },
    # Exposed Backup Files
    "sensitive_files": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Exposed archives or configs leak high confidentiality data over network.",
    },
    # Directory Listing
    "directory_indexing": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Directory indexing provides low confidentiality information disclosure.",
    },
    # Missing Security Headers
    "missing_headers": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A",
        "VC": "N", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Missing security headers expose low client-side integrity under active user interaction.",
    },
    # Insecure Cookie Flags
    "insecure_cookie": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Insecure cookie flags risk low session confidentiality under active interaction.",
    },
    # Cleartext Transmission / TLS
    "cleartext_tls": {
        "AV": "N", "AC": "H", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N",
        "rationale": "Cleartext or weak encryption requires high complexity network sniffing to read confidential traffic.",
    },
    # SSRF
    "ssrf": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "N", "VA": "N", "SC": "H", "SI": "N", "SA": "N",
        "rationale": "SSRF breaches network perimeter to expose sensitive subsequent internal resources.",
    },
}


class RiskEngine:
    """Evaluates finding risk and produces reproducible CVSS 3.1 and 4.0 assessments."""

    def __init__(self) -> None:
        self.calc_31 = CVSS31Calculator()
        self.calc_40 = CVSS40Calculator()

    def assess_finding(self, finding: Finding, cvss_version: str = "3.1") -> RiskAssessment:
        """Assess a Finding's risk score using CVSS 3.1 or 4.0.

        Strictly enforces Phase 10 Acceptance Criteria:
        'Every risk score has a reproducible vector/rationale or is explicitly marked as requiring review.'
        """
        version = cvss_version.strip()
        if version not in ("3.1", "4.0"):
            raise ValueError(f"Unsupported CVSS version '{version}'. Supported: '3.1', '4.0'")

        # Detect vulnerability archetype from finding attributes
        archetype_key = self._detect_archetype(finding)

        if not archetype_key:
            # Evidence is insufficient or ambiguous: mark as requiring manual review
            return RiskAssessment(
                cvss_version=version,
                base_score=None,
                severity=finding.severity,
                vector=None,
                review_status=ReviewStatus.REQUIRES_REVIEW,
                scoring_rationale="Insufficient evidence to reliably determine CVSS base metrics without speculation.",
                review_reasons=(
                    f"Finding type '{finding.finding_type}' lacks reproducible vulnerability metrics.",
                    "Attack vector, complexity, and impact metrics require analyst verification.",
                ),
                finding_id=finding.id,
            )

        if version == "3.1":
            return self._assess_cvss31(finding, archetype_key)
        else:
            return self._assess_cvss40(finding, archetype_key)

    def assess_vector(self, vector_str: str) -> RiskAssessment:
        """Parse and score any valid user- or scanner-supplied CVSS vector string."""
        clean = vector_str.strip()
        if clean.startswith("CVSS:3.1/"):
            score, metrics = self.calc_31.calculate_from_vector(clean)
            severity = score_to_severity_31(score)
            return RiskAssessment(
                cvss_version="3.1",
                base_score=score,
                severity=severity,
                vector=clean,
                review_status=ReviewStatus.ASSESSED,
                scoring_rationale=f"Evaluated from supplied CVSS 3.1 vector string with base score {score:.1f}.",
            )
        elif clean.startswith("CVSS:4.0/"):
            score, metrics = self.calc_40.calculate_from_vector(clean)
            severity = score_to_severity_40(score)
            return RiskAssessment(
                cvss_version="4.0",
                base_score=score,
                severity=severity,
                vector=clean,
                review_status=ReviewStatus.ASSESSED,
                scoring_rationale=f"Evaluated from supplied CVSS 4.0 vector string with base score {score:.1f}.",
            )
        else:
            raise ValueError(f"Unrecognized CVSS vector format: {clean!r}. Must start with 'CVSS:3.1/' or 'CVSS:4.0/'")

    def _assess_cvss31(self, finding: Finding, archetype_key: str) -> RiskAssessment:
        """Compute reproducible CVSS 3.1 score for an identified archetype."""
        arch = _CVSS31_ARCHETYPES[archetype_key]
        metrics = CVSS31Metrics(
            attack_vector=arch["AV"],
            attack_complexity=arch["AC"],
            privileges_required=arch["PR"],
            user_interaction=arch["UI"],
            scope=arch["S"],
            confidentiality=arch["C"],
            integrity=arch["I"],
            availability=arch["A"],
        )
        score = self.calc_31.calculate(metrics)
        vector = metrics.to_vector()
        severity = score_to_severity_31(score)

        rationale = (
            f"CVSS 3.1 Base Score {score:.1f} ({severity.value}): {arch['rationale']} "
            f"Vector: {vector}"
        )

        return RiskAssessment(
            cvss_version="3.1",
            base_score=score,
            severity=severity,
            vector=vector,
            review_status=ReviewStatus.ASSESSED,
            scoring_rationale=rationale,
            finding_id=finding.id,
        )

    def _assess_cvss40(self, finding: Finding, archetype_key: str) -> RiskAssessment:
        """Compute reproducible CVSS 4.0 score for an identified archetype."""
        arch = _CVSS40_ARCHETYPES[archetype_key]
        metrics = CVSS40Metrics(
            attack_vector=arch["AV"],
            attack_complexity=arch["AC"],
            attack_requirements=arch["AT"],
            privileges_required=arch["PR"],
            user_interaction=arch["UI"],
            vuln_confidentiality=arch["VC"],
            vuln_integrity=arch["VI"],
            vuln_availability=arch["VA"],
            sub_confidentiality=arch["SC"],
            sub_integrity=arch["SI"],
            sub_availability=arch["SA"],
        )
        score = self.calc_40.calculate(metrics)
        vector = metrics.to_vector()
        severity = score_to_severity_40(score)

        rationale = (
            f"CVSS 4.0 Base Score {score:.1f} ({severity.value}): {arch['rationale']} "
            f"Vector: {vector}"
        )

        return RiskAssessment(
            cvss_version="4.0",
            base_score=score,
            severity=severity,
            vector=vector,
            review_status=ReviewStatus.ASSESSED,
            scoring_rationale=rationale,
            finding_id=finding.id,
        )

    def _detect_archetype(self, finding: Finding) -> str | None:
        """Match finding attributes to a deterministic vulnerability archetype."""
        text = f"{finding.finding_type} {finding.title} {finding.description}".lower()

        # SQL Injection
        if ("sql" in text and ("injection" in text or "blind" in text or "sqli" in text)) or "cwe-89" in text:
            return "sqli"

        # RCE / OS Command Injection
        if any(term in text for term in ["command injection", "rce", "remote code execution", "shell injection", "cwe-78"]):
            return "rce"

        # Cross-Site Scripting
        if any(term in text for term in ["cross-site scripting", "xss", "cwe-79"]):
            return "xss"

        # Path Traversal / LFI
        if any(term in text for term in ["path traversal", "directory traversal", "local file inclusion", "lfi", "cwe-22"]):
            return "path_traversal"

        # Sensitive / Backup Files
        if any(term in text for term in [".git", ".env", "backup file", "config file", ".bak", "cwe-552"]):
            return "sensitive_files"

        # Directory Indexing
        if any(term in text for term in ["directory indexing", "directory listing", "index of /", "cwe-548"]):
            return "directory_indexing"

        # Missing Security Headers
        if any(term in text for term in ["x-frame-options", "content-security-policy", "missing security header", "anti-clickjacking", "cwe-693", "cwe-1021"]):
            return "missing_headers"

        # Insecure Cookies
        if any(term in text for term in ["httponly", "cookie without 'secure'", "missing secure flag", "cwe-1004", "cwe-614"]):
            return "insecure_cookie"

        # Cleartext / TLS
        if any(term in text for term in ["weak cipher", "ssl 2.0", "ssl 3.0", "tls 1.0", "cleartext transmission", "cwe-319"]):
            return "cleartext_tls"

        # SSRF
        if "ssrf" in text or "server-side request forgery" in text or "cwe-918" in text:
            return "ssrf"

        return None
