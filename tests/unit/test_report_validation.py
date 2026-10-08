"""Unit tests for ReportValidator and Secret Leak Detection (Phase 14)."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from reconx.reporting.model import (
    AttackSurfaceSummary,
    ExecutiveSummary,
    ReportAppendix,
    ReportFinding,
    ReportModel,
)
from reconx.reporting.validation import ReportValidator


def _build_valid_report_model() -> ReportModel:
    return ReportModel(
        scan_id="scan-1234",
        target="example.com",
        title="Security Reconnaissance Report — example.com",
        generated_at="2026-10-08T10:00:00+00:00",
        executive_summary=ExecutiveSummary(
            target="example.com",
            scan_date="2026-10-08",
            duration_seconds=15.0,
            scope_summary="Domain example.com",
            total_assets=1,
            total_findings=1,
            severity_distribution={"MEDIUM": 1},
            risk_score_summary="Moderate risk profile",
        ),
        attack_surface=AttackSurfaceSummary(
            domains=["example.com"],
            ports=["80/tcp"],
        ),
        findings=[
            ReportFinding(
                id="f1",
                title="Missing X-Frame-Options Header",
                severity="MEDIUM",
                confidence=0.9,
                confidence_level="HIGH",
                cvss_version="3.1",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cvss_status="VERIFIED",
                cvss_rationale="Clickjacking exposure",
                affected_asset="example.com",
                endpoint="http://example.com/",
                description="The server does not specify an anti-clickjacking header.",
                impact="Potential UI redressing",
            ),
        ],
        appendix=ReportAppendix(
            reconx_version="0.1.0",
        ),
    )


class TestReportValidation(unittest.TestCase):
    """Tests for ReportValidator."""

    def test_valid_report_model_passes(self) -> None:
        model = _build_valid_report_model()
        res = ReportValidator.validate_report_model(model)
        assert res.is_valid is True
        assert len(res.errors) == 0
        assert len(res.unredacted_secrets_found) == 0

    def test_missing_scan_id_or_target_fails(self) -> None:
        model = ReportModel(
            scan_id="",
            target="",
            title="Title",
            generated_at="invalid-date",
            executive_summary=_build_valid_report_model().executive_summary,
            attack_surface=_build_valid_report_model().attack_surface,
            findings=[],
            appendix=_build_valid_report_model().appendix,
        )
        res = ReportValidator.validate_report_model(model)
        assert res.is_valid is False
        assert any("scan_id" in err for err in res.errors)
        assert any("target" in err for err in res.errors)
        assert any("timestamp" in err for err in res.errors)

    def test_finding_count_mismatch_fails(self) -> None:
        # executive summary claims 5 findings, but list only has 1
        base = _build_valid_report_model()
        bad_exec = ExecutiveSummary(
            target="example.com",
            scan_date="2026-10-08",
            duration_seconds=15.0,
            scope_summary="Domain example.com",
            total_assets=1,
            total_findings=5,
            severity_distribution={"CRITICAL": 5},
            risk_score_summary="High risk",
        )
        model = ReportModel(
            scan_id=base.scan_id,
            target=base.target,
            title=base.title,
            generated_at=base.generated_at,
            executive_summary=bad_exec,
            attack_surface=base.attack_surface,
            findings=base.findings,  # len is 1
            appendix=base.appendix,
        )
        res = ReportValidator.validate_report_model(model)
        assert res.is_valid is False
        assert any("does not match actual findings list count" in err for err in res.errors)

    def test_cvss_score_out_of_bounds_fails(self) -> None:
        base = _build_valid_report_model()
        bad_finding = ReportFinding(
            id="f1",
            title="Invalid Score Finding",
            severity="CRITICAL",
            confidence=0.9,
            confidence_level="HIGH",
            cvss_version="3.1",
            cvss_score=15.0,  # Invalid: > 10.0
            cvss_vector=None,
            cvss_status="VERIFIED",
            cvss_rationale="Over max score",
            affected_asset="example.com",
            endpoint=None,
            description="desc",
            impact="impact",
        )
        model = ReportModel(
            scan_id=base.scan_id,
            target=base.target,
            title=base.title,
            generated_at=base.generated_at,
            executive_summary=base.executive_summary,
            attack_surface=base.attack_surface,
            findings=[bad_finding],
            appendix=base.appendix,
        )
        res = ReportValidator.validate_report_model(model)
        assert res.is_valid is False
        assert any("CVSS score 15.0 is outside range" in err for err in res.errors)

    def test_secret_leak_detected_in_finding(self) -> None:
        base = _build_valid_report_model()
        leaking_finding = ReportFinding(
            id="f_leak",
            title="Leaked AWS Key",
            severity="HIGH",
            confidence=1.0,
            confidence_level="HIGH",
            cvss_version="3.1",
            cvss_score=8.5,
            cvss_vector=None,
            cvss_status="VERIFIED",
            cvss_rationale="Key found",
            affected_asset="example.com",
            endpoint=None,
            description="Found raw credential: AKIAIOSFODNN7EXAMPLE in HTML source",
            impact="Cloud compromise",
        )
        model = ReportModel(
            scan_id=base.scan_id,
            target=base.target,
            title=base.title,
            generated_at=base.generated_at,
            executive_summary=base.executive_summary,
            attack_surface=base.attack_surface,
            findings=[leaking_finding],
            appendix=base.appendix,
        )
        res = ReportValidator.validate_report_model(model)
        assert res.is_valid is False
        assert len(res.unredacted_secrets_found) > 0
        assert any("AWS Access Key" in s for s in res.unredacted_secrets_found)

    def test_validate_json_report(self) -> None:
        model = _build_valid_report_model()
        json_str = json.dumps(model.to_dict())

        res = ReportValidator.validate_json_report(json_str)
        assert res.is_valid is True

        # Malformed JSON
        res_bad = ReportValidator.validate_json_report("not valid json {")
        assert res_bad.is_valid is False
    def test_validate_report_file(self) -> None:
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "report.json"
            report_file.write_text('{"valid": true}')
            os.chmod(report_file, 0o600)

            res = ReportValidator.validate_report_file(report_file)
            assert res.is_valid is True

            empty_file = Path(tmp_dir) / "empty.json"
            empty_file.touch()
            res_empty = ReportValidator.validate_report_file(empty_file)
            assert res_empty.is_valid is False
            assert any("empty" in err for err in res_empty.errors)
