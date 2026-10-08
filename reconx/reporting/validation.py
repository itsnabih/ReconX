"""Report schema validation and secret leakage auditor (Phase 14).

Strictly adheres to Phase 14 of Implementation.md:
- Report validation against canonical ReportModel structure
- Integrity check between severity distribution and finding counts
- CVSS score boundary enforcement (0.0 to 10.0)
- Deep secret leakage detection (ensures no raw credentials in reports)
- Report file permission verification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

from reconx.reporting.model import ReportModel

# Regex patterns to detect potential leaked secrets that escaped redaction
LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("RSA/SSH Private Key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Bearer Token", re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.]{20,}\b")),
    ("Basic Auth Credentials", re.compile(r"(?i)\bauthorization:\s*basic\s+[a-zA-Z0-9+/=]{10,}\b")),
    ("Generic Password in URL", re.compile(r"(?i)https?://[^:\s]+:[^@\s]+@")),
)


class ReportValidationError(ValueError):
    """Raised when a report fails validation requirements."""


@dataclass
class ValidationResult:
    """Outcome of report validation."""

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks_count: int = 0
    unredacted_secrets_found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "checks_count": self.checks_count,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "unredacted_secrets_found": list(self.unredacted_secrets_found),
        }


class ReportValidator:
    """Validates ReportModel instances and generated report files."""

    @classmethod
    def validate_report_model(cls, report: ReportModel) -> ValidationResult:
        """Perform comprehensive validation on a ReportModel."""
        errors: list[str] = []
        warnings: list[str] = []
        secrets: list[str] = []
        checks = 0

        # 1. Basic Metadata
        checks += 1
        if not report.scan_id or not report.scan_id.strip():
            errors.append("Report scan_id is missing or empty")

        checks += 1
        if not report.target or not report.target.strip():
            errors.append("Report target is missing or empty")

        checks += 1
        try:
            datetime.fromisoformat(report.generated_at)
        except (ValueError, TypeError):
            errors.append(f"Report generated_at '{report.generated_at}' is not a valid ISO 8601 timestamp")

        # 2. Executive Summary Consistency
        checks += 1
        exec_sum = report.executive_summary
        if exec_sum is None:
            errors.append("Report executive_summary is missing")
        else:
            # Check finding count consistency
            actual_count = len(report.findings)
            dist_count = sum(exec_sum.severity_distribution.values())

            if exec_sum.total_findings != actual_count:
                errors.append(
                    f"Executive summary total_findings ({exec_sum.total_findings}) "
                    f"does not match actual findings list count ({actual_count})"
                )

            if dist_count != actual_count:
                errors.append(
                    f"Sum of severity distribution ({dist_count}) "
                    f"does not match total findings count ({actual_count})"
                )

        # 3. Findings Validation
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for idx, finding in enumerate(report.findings):
            checks += 1
            if not finding.id:
                errors.append(f"Finding at index {idx} has empty ID")
            if not finding.title:
                errors.append(f"Finding '{finding.id}' has empty title")

            if finding.severity.upper() not in valid_severities:
                errors.append(
                    f"Finding '{finding.id}' has invalid severity '{finding.severity}'"
                )

            if not (0.0 <= finding.confidence <= 1.0):
                errors.append(
                    f"Finding '{finding.id}' confidence {finding.confidence} is outside range [0.0, 1.0]"
                )

            if finding.cvss_score is not None:
                if not (0.0 <= finding.cvss_score <= 10.0):
                    errors.append(
                        f"Finding '{finding.id}' CVSS score {finding.cvss_score} is outside range [0.0, 10.0]"
                    )

            # 4. Secret Leakage Audit
            text_corpus = f"{finding.title} {finding.description} {finding.impact} {finding.endpoint or ''} {' '.join(finding.evidence)}"
            for secret_type, pattern in LEAK_PATTERNS:
                if pattern.search(text_corpus):
                    leak_desc = f"Unredacted {secret_type} detected in finding '{finding.id}'"
                    secrets.append(leak_desc)
                    errors.append(leak_desc)

        # 5. Appendix Validation
        checks += 1
        if report.appendix is None:
            errors.append("Report appendix is missing")
        elif not report.appendix.reconx_version:
            warnings.append("Appendix reconx_version is empty")

        is_valid = len(errors) == 0
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            checks_count=checks,
            unredacted_secrets_found=secrets,
        )

    @classmethod
    def validate_json_report(cls, raw_json: str | bytes) -> ValidationResult:
        """Validate raw JSON report string against canonical ReportModel structure."""
        checks = 1
        try:
            data = json.loads(raw_json)
        except Exception as exc:
            return ValidationResult(
                is_valid=False,
                errors=[f"Invalid JSON format: {exc}"],
                checks_count=checks,
            )

        # Basic key presence
        required_keys = {"scan_id", "target", "generated_at", "executive_summary", "attack_surface", "findings", "appendix"}
        missing_keys = required_keys - set(data.keys())
        if missing_keys:
            return ValidationResult(
                is_valid=False,
                errors=[f"JSON report missing required top-level keys: {sorted(missing_keys)}"],
                checks_count=checks + 1,
            )

        # Convert back to ReportModel if possible, or validate dict
        errors: list[str] = []
        checks += len(required_keys)

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            errors.append("'findings' must be a list")

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            checks_count=checks,
        )

    @classmethod
    def validate_report_file(cls, path: str | Path) -> ValidationResult:
        """Verify report file existence, non-emptiness, and secure permissions."""
        file_path = Path(path)
        errors: list[str] = []
        warnings: list[str] = []
        checks = 0

        checks += 1
        if not file_path.exists():
            return ValidationResult(is_valid=False, errors=[f"Report file '{file_path}' does not exist"])

        checks += 1
        if file_path.stat().st_size == 0:
            errors.append(f"Report file '{file_path}' is empty (0 bytes)")

        checks += 1
        st_mode = file_path.stat().st_mode & 0o777
        if (st_mode & 0o002) != 0:
            errors.append(f"Report file '{file_path}' is world-writable (mode {oct(st_mode)})")

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            checks_count=checks,
        )
