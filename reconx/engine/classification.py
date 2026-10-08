"""Vulnerability classification and taxonomy mapping for ReconX.

Maps security observations and hints to standardized taxonomies:
- OWASP Top 10 (2021)
- Common Weakness Enumeration (CWE)
- Normalized Vulnerability Categories
- Baseline Severity Ratings
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any

from reconx.models.finding import Severity
from reconx.models.observation import Observation


class VulnerabilityCategory(str, Enum):
    """Normalized vulnerability classification categories."""

    INJECTION = "injection"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTOGRAPHIC_FAILURES = "cryptographic_failures"
    INSECURE_DESIGN = "insecure_design"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    AUTH_FAILURES = "identification_and_authentication_failures"
    INTEGRITY_FAILURES = "software_and_data_integrity_failures"
    LOGGING_FAILURES = "security_logging_and_monitoring_failures"
    SSRF = "ssrf"
    INFORMATION_DISCLOSURE = "information_disclosure"
    NETWORK_EXPOSURE = "network_exposure"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClassificationResult:
    """Taxonomy and metadata classification for a security observation."""

    category: VulnerabilityCategory
    cwe_id: str | None
    cwe_name: str | None
    owasp_category: str | None
    default_severity: Severity
    cve: str | None = None
    remediation: str = ""


# Standard Taxonomy Definitions
_TAXONOMY_RULES: list[dict[str, Any]] = [
    # 1. SQL Injection
    {
        "patterns": [
            r"sql[\s_-]?injection",
            r"sqli\b",
            r"boolean-based\s+blind",
            r"error-based\s+sql",
            r"time-based\s+blind",
            r"union\s+query\s+sql",
            r"stacked\s+queries",
            r"dbms\s*:",
        ],
        "category": VulnerabilityCategory.INJECTION,
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp_category": "A03:2021-Injection",
        "default_severity": Severity.HIGH,
        "remediation": "Use parameterized queries or prepared statements for all database operations.",
    },
    # 2. Command Injection / RCE
    {
        "patterns": [
            r"command[\s_-]?injection",
            r"os[\s_-]?command",
            r"remote[\s_-]?code[\s_-]?execution",
            r"\brce\b",
            r"shell[\s_-]?injection",
        ],
        "category": VulnerabilityCategory.INJECTION,
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp_category": "A03:2021-Injection",
        "default_severity": Severity.CRITICAL,
        "remediation": "Avoid invoking shell interpreters with user-supplied arguments; use safe parameter arrays.",
    },
    # 3. Cross-Site Scripting (XSS)
    {
        "patterns": [
            r"cross[\s_-]?site[\s_-]?scripting",
            r"\bxss\b",
            r"reflected\s+xss",
            r"stored\s+xss",
            r"dom\s+xss",
        ],
        "category": VulnerabilityCategory.INJECTION,
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp_category": "A03:2021-Injection",
        "default_severity": Severity.MEDIUM,
        "remediation": "Contextually encode user-supplied data before rendering and implement Content-Security-Policy.",
    },
    # 4. Path Traversal / LFI / RFI
    {
        "patterns": [
            r"path[\s_-]?traversal",
            r"directory[\s_-]?traversal",
            r"local[\s_-]?file[\s_-]?inclusion",
            r"\blfi\b",
            r"remote[\s_-]?file[\s_-]?inclusion",
            r"\brfi\b",
            r"\.\./",
        ],
        "category": VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp_category": "A01:2021-Broken Access Control",
        "default_severity": Severity.HIGH,
        "remediation": "Validate path inputs against a strict allowlist and resolve canonical paths.",
    },
    # 5. Directory Listing / Indexing
    {
        "patterns": [
            r"directory[\s_-]?indexing",
            r"directory[\s_-]?listing",
            r"index\s+of\s+/",
        ],
        "category": VulnerabilityCategory.INFORMATION_DISCLOSURE,
        "cwe_id": "CWE-548",
        "cwe_name": "Exposure of Information Through Directory Listing",
        "owasp_category": "A01:2021-Broken Access Control",
        "default_severity": Severity.LOW,
        "remediation": "Disable directory browsing (e.g. Options -Indexes in Apache, autoindex off in Nginx).",
    },
    # 6. Sensitive / Backup Files Exposed
    {
        "patterns": [
            r"\.git",
            r"\.env",
            r"\.bak\b",
            r"backup[\s_-]?file",
            r"config[\s_-]?file",
            r"phpinfo",
            r"core[\s_-]?dump",
            r"database[\s_-]?dump",
            r"\.sql\b",
        ],
        "category": VulnerabilityCategory.INFORMATION_DISCLOSURE,
        "cwe_id": "CWE-552",
        "cwe_name": "Files or Directories Accessible to External Parties",
        "owasp_category": "A01:2021-Broken Access Control",
        "default_severity": Severity.MEDIUM,
        "remediation": "Restrict web server access to dotfiles, backup files, and development configurations.",
    },
    # 7. Missing Security Headers
    {
        "patterns": [
            r"x-frame-options",
            r"content-security-policy",
            r"x-content-type-options",
            r"strict-transport-security",
            r"hsts",
            r"missing.*header",
            r"anti-clickjacking",
        ],
        "category": VulnerabilityCategory.SECURITY_MISCONFIGURATION,
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure (Missing Security Headers)",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "default_severity": Severity.LOW,
        "remediation": "Configure standard HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).",
    },
    # 8. Insecure Cookie Attributes
    {
        "patterns": [
            r"cookie.*(httponly|secure|samesite)",
            r"missing.*httponly",
            r"missing.*secure\s+flag",
        ],
        "category": VulnerabilityCategory.SECURITY_MISCONFIGURATION,
        "cwe_id": "CWE-1004",
        "cwe_name": "Sensitive Cookie Without 'HttpOnly' or 'Secure' Flag",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "default_severity": Severity.LOW,
        "remediation": "Set HttpOnly, Secure, and SameSite attributes on sensitive session cookies.",
    },
    # 9. Server Banner / Version Disclosure
    {
        "patterns": [
            r"server\s+banner",
            r"version\s+disclosure",
            r"reveals\s+system\s+information",
            r"x-powered-by",
            r"uncommon\s+header",
            r"retrieved.*header",
        ],
        "category": VulnerabilityCategory.INFORMATION_DISCLOSURE,
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "default_severity": Severity.INFO,
        "remediation": "Suppress server version banners and technological fingerprints (ServerTokens Prod).",
    },
    # 10. Default / Weak Credentials & Authentication
    {
        "patterns": [
            r"default\s+(password|credential|account|admin)",
            r"weak\s+credential",
            r"authentication\s+bypass",
            r"unauthorized\s+access",
        ],
        "category": VulnerabilityCategory.AUTH_FAILURES,
        "cwe_id": "CWE-1392",
        "cwe_name": "Use of Default Credentials",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "default_severity": Severity.HIGH,
        "remediation": "Change all default credentials and enforce strong multi-factor authentication.",
    },
    # 11. SSL / TLS / Cryptographic Flaws
    {
        "patterns": [
            r"ssl[\s_-]?(v2|v3)",
            r"tls[\s_-]?(1\.0|1\.1)",
            r"weak\s+cipher",
            r"certificate\s+(expired|invalid|self-signed)",
            r"sweet32",
            r"heartbleed",
            r"poodle",
        ],
        "category": VulnerabilityCategory.CRYPTOGRAPHIC_FAILURES,
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "default_severity": Severity.MEDIUM,
        "remediation": "Disable deprecated TLS versions and weak ciphers; require TLS 1.2+ with modern cipher suites.",
    },
    # 12. SSRF
    {
        "patterns": [
            r"server[\s_-]?side\s+request\s+forgery",
            r"\bssrf\b",
        ],
        "category": VulnerabilityCategory.SSRF,
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "default_severity": Severity.HIGH,
        "remediation": "Validate and restrict outgoing requests to allowed target hosts and protocols.",
    },
    # 13. Network Service Exposure
    {
        "patterns": [
            r"telnet\b",
            r"anonymous\s+ftp",
            r"exposed\s+database",
            r"open\s+port\s+exposure",
        ],
        "category": VulnerabilityCategory.NETWORK_EXPOSURE,
        "cwe_id": "CWE-16",
        "cwe_name": "Configuration",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "default_severity": Severity.MEDIUM,
        "remediation": "Restrict network access with firewall rules and replace cleartext protocols.",
    },
]

_CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


class VulnerabilityClassifier:
    """Classifies security observations into standardized taxonomies."""

    def __init__(self, custom_rules: list[dict[str, Any]] | None = None) -> None:
        self._rules = list(custom_rules or _TAXONOMY_RULES)

    def classify(
        self,
        title: str,
        description: str = "",
        parameter: str | None = None,
        injection_type: str | None = None,
        cve: str | None = None,
    ) -> ClassificationResult:
        """Classify a security finding or hint from its textual and structured attributes."""
        # Check explicit CVE or extract from text
        detected_cve = cve
        text_corpus = f"{title} {description} {parameter or ''} {injection_type or ''}"
        if not detected_cve:
            cve_match = _CVE_REGEX.search(text_corpus)
            if cve_match:
                detected_cve = cve_match.group(0).upper()

        # If injection_type is explicitly specified, prioritize INJECTION
        if injection_type:
            inj_norm = injection_type.lower()
            if any(term in inj_norm for term in ["sql", "boolean", "time", "error", "union", "stacked"]):
                return ClassificationResult(
                    category=VulnerabilityCategory.INJECTION,
                    cwe_id="CWE-89",
                    cwe_name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    owasp_category="A03:2021-Injection",
                    default_severity=Severity.HIGH,
                    cve=detected_cve,
                    remediation="Use parameterized queries or prepared statements for all database operations.",
                )

        # Match against taxonomy rules
        for rule in self._rules:
            for pattern in rule["patterns"]:
                if re.search(pattern, text_corpus, re.IGNORECASE):
                    return ClassificationResult(
                        category=rule["category"],
                        cwe_id=rule["cwe_id"],
                        cwe_name=rule["cwe_name"],
                        owasp_category=rule["owasp_category"],
                        default_severity=rule["default_severity"],
                        cve=detected_cve,
                        remediation=rule.get("remediation", ""),
                    )

        # Default fallback classification
        default_sev = Severity.INFO
        if detected_cve:
            return ClassificationResult(
                category=VulnerabilityCategory.VULNERABLE_COMPONENTS,
                cwe_id="CWE-1395",
                cwe_name="Dependency on Vulnerable Third-Party Component",
                owasp_category="A06:2021-Vulnerable and Outdated Components",
                default_severity=Severity.MEDIUM,
                cve=detected_cve,
                remediation="Upgrade the vulnerable component to a patched release.",
            )

        return ClassificationResult(
            category=VulnerabilityCategory.UNKNOWN,
            cwe_id=None,
            cwe_name=None,
            owasp_category=None,
            default_severity=default_sev,
            cve=detected_cve,
            remediation="Review observation details and perform targeted manual verification.",
        )

    def classify_observation(self, obs: Observation) -> ClassificationResult:
        """Classify a domain Observation."""
        data = obs.data or {}
        title = data.get("title") or obs.type
        description = data.get("description", "")
        parameter = data.get("parameter")
        injection_type = data.get("injection_type")
        cve = data.get("cve")

        # Handle specific observation types
        if obs.type == "vulnerability_hint":
            return self.classify(
                title=title,
                description=description,
                parameter=parameter,
                injection_type=injection_type,
                cve=cve,
            )

        if obs.type == "open_port":
            port = data.get("port")
            service = data.get("service", "")
            port_title = f"Open port {port}/{service}"
            return self.classify(title=port_title, description=f"Port {port} running {service}")

        if obs.type == "endpoint_discovery":
            path = data.get("path", "")
            return self.classify(title=f"Discovered endpoint {path}", description=f"Discovered path {path}")

        return self.classify(title=title, description=description)
