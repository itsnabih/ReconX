"""Unit tests for ReconX Risk Engine, CVSS 3.1, and CVSS 4.0 Calculators.

Validates Phase 10 Requirements:
- CVSS 3.1 base score calculation, round_up, vector generation/parsing
- CVSS 4.0 base score calculation, MacroVector lookup, interpolation
- Severity mappings and scoring rationales
- Explicit manual review status (ASSESSED vs REQUIRES_REVIEW)
- Phase 10 Acceptance Criteria: Every risk score has a reproducible vector/rationale
  or is explicitly marked as requiring review.
"""

from __future__ import annotations

import pytest

from reconx.engine.correlation import FindingCorrelator
from reconx.models.finding import Finding, Severity
from reconx.models.observation import Observation
from reconx.risk import (
    CVSS31Calculator,
    CVSS31Metrics,
    CVSS40Calculator,
    CVSS40Metrics,
    ReviewStatus,
    RiskAssessment,
    RiskEngine,
    round_up,
    score_to_severity_31,
    score_to_severity_40,
)


class TestCVSS31Calculator:
    """Tests for CVSS 3.1 specification compliance."""

    def test_round_up_specification(self) -> None:
        """Test CVSS 3.1 round_up logic per FIRST.org Section 7.4."""
        assert round_up(0.0) == 0.0
        assert round_up(4.0) == 4.0
        assert round_up(4.01) == 4.1
        assert round_up(4.001) == 4.1
        assert round_up(4.09) == 4.1
        # Float precision tolerance test (should round to 4.0, not 4.1)
        assert round_up(4.000001) == 4.0
        assert round_up(9.84) == 9.9
        assert round_up(10.0) == 10.0

    def test_known_reference_vectors(self) -> None:
        """Verify scores against standard official CVSS 3.1 vectors."""
        calc = CVSS31Calculator()

        # Critical: Remote unauthenticated RCE
        score, _ = calc.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8
        assert score_to_severity_31(score) == Severity.CRITICAL

        # High: Arbitrary File Read / Path Traversal
        score, _ = calc.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert score == 7.5
        assert score_to_severity_31(score) == Severity.HIGH

        # Medium: Reflected XSS (Scope Changed)
        score, _ = calc.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert score == 6.1
        assert score_to_severity_31(score) == Severity.MEDIUM

        # Low: High complexity, low impact, physical vector
        score, _ = calc.calculate_from_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        assert score == 1.6
        assert score_to_severity_31(score) == Severity.LOW

        # Info: Zero impact
        score, _ = calc.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0
        assert score_to_severity_31(score) == Severity.INFO

    def test_scope_changed_and_privileges_required(self) -> None:
        """Test scope changed impact formula and PR weights."""
        calc = CVSS31Calculator()

        # Scope Changed SSRF
        metrics_changed = CVSS31Metrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="N", availability="N",
        )
        score_changed = calc.calculate(metrics_changed)
        assert score_changed == 8.6

        # Scope Unchanged with PR:L vs PR:H
        m_pr_low = CVSS31Metrics(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H",
        )
        m_pr_high = CVSS31Metrics(
            attack_vector="N", attack_complexity="L", privileges_required="H",
            user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H",
        )
        assert calc.calculate(m_pr_low) == 8.8
        assert calc.calculate(m_pr_high) == 7.2

    def test_metrics_normalization_and_validation(self) -> None:
        """Test CVSS31Metrics input normalization and validation errors."""
        m = CVSS31Metrics(
            attack_vector="n", attack_complexity="l", privileges_required="n",
            user_interaction="n", scope="u", confidentiality="h", integrity="h", availability="h",
        )
        assert m.attack_vector == "N"
        assert m.to_vector() == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        with pytest.raises(ValueError, match="Invalid CVSS 3.1 value"):
            CVSS31Metrics(
                attack_vector="INVALID", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H",
            )

    def test_parse_vector_unordered_and_errors(self) -> None:
        """Test parse_vector handles valid out-of-order metrics and rejects invalid ones."""
        calc = CVSS31Calculator()

        # Out-of-order metrics
        v = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
        m = calc.parse_vector(v)
        assert m.attack_vector == "N"
        assert m.availability == "H"

        # Missing metric
        with pytest.raises(ValueError, match="Missing required"):
            calc.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

        # Invalid prefix
        with pytest.raises(ValueError, match="does not start with 'CVSS:3.1/'"):
            calc.parse_vector("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        # Malformed segment
        with pytest.raises(ValueError, match="Malformed metric segment"):
            calc.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/BADSEGMENT")

    def test_severity_thresholds(self) -> None:
        """Test score_to_severity_31 mapping boundaries."""
        assert score_to_severity_31(0.0) == Severity.INFO
        assert score_to_severity_31(0.1) == Severity.LOW
        assert score_to_severity_31(3.9) == Severity.LOW
        assert score_to_severity_31(4.0) == Severity.MEDIUM
        assert score_to_severity_31(6.9) == Severity.MEDIUM
        assert score_to_severity_31(7.0) == Severity.HIGH
        assert score_to_severity_31(8.9) == Severity.HIGH
        assert score_to_severity_31(9.0) == Severity.CRITICAL
        assert score_to_severity_31(10.0) == Severity.CRITICAL


class TestCVSS40Calculator:
    """Tests for CVSS 4.0 specification compliance."""

    def test_known_reference_vectors(self) -> None:
        """Verify scores against standard official CVSS 4.0 vectors."""
        calc = CVSS40Calculator()

        # Critical 10.0: Max impact across vulnerable and subsequent system
        score, _ = calc.calculate_from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        )
        assert score == 10.0
        assert score_to_severity_40(score) == Severity.CRITICAL

        # High/Critical 9.3: SQL Injection pattern (VC:H/VI:H)
        score, _ = calc.calculate_from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
        )
        assert score == 9.3
        assert score_to_severity_40(score) == Severity.CRITICAL

        # Medium 5.1: Reflected XSS pattern (UI:A/VI:L)
        score, _ = calc.calculate_from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
        )
        assert score == 5.1
        assert score_to_severity_40(score) == Severity.MEDIUM

        # Info 0.0: Zero impact
        score, _ = calc.calculate_from_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        )
        assert score == 0.0
        assert score_to_severity_40(score) == Severity.INFO

    def test_macro_vector_determination(self) -> None:
        """Verify MacroVector EQ levels."""
        calc = CVSS40Calculator()

        # Critical: Max exploitability & impact -> EQ1=0, EQ2=0, EQ3=0, EQ4=1, EQ5=0, EQ6=0
        m_crit = CVSS40Metrics(
            attack_vector="N", attack_complexity="L", attack_requirements="N",
            privileges_required="N", user_interaction="N", vuln_confidentiality="H",
            vuln_integrity="H", vuln_availability="H", sub_confidentiality="H",
            sub_integrity="H", sub_availability="H",
        )
        assert calc.macro_vector(m_crit) == "000100"

        # Subsequent system integrity/availability safety: SI=S -> EQ4=0
        m_sub_safe = CVSS40Metrics(
            attack_vector="N", attack_complexity="L", attack_requirements="N",
            privileges_required="N", user_interaction="N", vuln_confidentiality="H",
            vuln_integrity="H", vuln_availability="H", sub_confidentiality="N",
            sub_integrity="S", sub_availability="N",
        )
        assert calc.macro_vector(m_sub_safe) == "000000"

        # Low exploitability, high complexity, no impact
        m_none = CVSS40Metrics(
            attack_vector="P", attack_complexity="H", attack_requirements="P",
            privileges_required="H", user_interaction="A", vuln_confidentiality="N",
            vuln_integrity="N", vuln_availability="N", sub_confidentiality="N",
            sub_integrity="N", sub_availability="N",
        )
        assert calc.macro_vector(m_none) == "212201"

    def test_metrics_normalization_and_validation(self) -> None:
        """Test CVSS40Metrics input normalization and validation."""
        m = CVSS40Metrics(
            attack_vector="n", attack_complexity="l", attack_requirements="n",
            privileges_required="n", user_interaction="n", vuln_confidentiality="h",
            vuln_integrity="h", vuln_availability="h", sub_confidentiality="h",
            sub_integrity="h", sub_availability="h",
        )
        assert m.attack_vector == "N"
        assert m.sub_confidentiality == "H"
        assert m.to_vector() == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

        with pytest.raises(ValueError, match="Invalid CVSS 4.0 value"):
            CVSS40Metrics(
                attack_vector="INVALID", attack_complexity="L", attack_requirements="N",
                privileges_required="N", user_interaction="N", vuln_confidentiality="H",
                vuln_integrity="H", vuln_availability="H", sub_confidentiality="H",
                sub_integrity="H", sub_availability="H",
            )

    def test_parse_vector_errors(self) -> None:
        """Test CVSS40Calculator parse_vector error handling."""
        calc = CVSS40Calculator()

        with pytest.raises(ValueError, match="does not start with 'CVSS:4.0/'"):
            calc.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        with pytest.raises(ValueError, match="Missing required"):
            calc.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")

        with pytest.raises(ValueError, match="Malformed metric segment"):
            calc.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA")

    def test_severity_thresholds(self) -> None:
        """Test score_to_severity_40 mapping boundaries."""
        assert score_to_severity_40(0.0) == Severity.INFO
        assert score_to_severity_40(0.1) == Severity.LOW
        assert score_to_severity_40(3.9) == Severity.LOW
        assert score_to_severity_40(4.0) == Severity.MEDIUM
        assert score_to_severity_40(6.9) == Severity.MEDIUM
        assert score_to_severity_40(7.0) == Severity.HIGH
        assert score_to_severity_40(8.9) == Severity.HIGH
        assert score_to_severity_40(9.0) == Severity.CRITICAL
        assert score_to_severity_40(10.0) == Severity.CRITICAL


class TestRiskEngine:
    """Tests for RiskEngine orchestration and finding assessments."""

    def test_archetype_assessment_cvss31(self) -> None:
        """Test scoring of known vulnerability archetypes using CVSS 3.1."""
        engine = RiskEngine()

        archetype_tests = [
            ("sql_injection", "SQL Injection in /api/users", Severity.HIGH, 9.1, Severity.CRITICAL),
            ("remote_code_execution", "Command Injection via shell parameter", Severity.CRITICAL, 9.8, Severity.CRITICAL),
            ("cross_site_scripting", "Reflected XSS in search query", Severity.MEDIUM, 6.1, Severity.MEDIUM),
            ("path_traversal", "Directory Traversal in file viewer", Severity.HIGH, 7.5, Severity.HIGH),
            ("sensitive_file", "Exposed .env configuration file", Severity.HIGH, 7.5, Severity.HIGH),
            ("directory_indexing", "Directory Indexing enabled on /uploads", Severity.LOW, 5.3, Severity.MEDIUM),
            ("missing_header", "Missing X-Frame-Options anti-clickjacking header", Severity.LOW, 4.3, Severity.MEDIUM),
            ("insecure_cookie", "Session cookie without 'secure' flag", Severity.LOW, 4.3, Severity.MEDIUM),
            ("weak_cipher", "Cleartext transmission via TLS 1.0", Severity.MEDIUM, 5.9, Severity.MEDIUM),
            ("ssrf", "Server-Side Request Forgery via webhook", Severity.HIGH, 8.6, Severity.HIGH),
        ]

        for finding_type, title, original_sev, expected_score, expected_sev in archetype_tests:
            finding = Finding(
                finding_type=finding_type,
                title=title,
                asset_id="asset_123",
                severity=original_sev,
                confidence=0.9,
                description=f"Evidence for {title}",
            )
            assessment = engine.assess_finding(finding, cvss_version="3.1")

            assert assessment.review_status == ReviewStatus.ASSESSED
            assert assessment.cvss_version == "3.1"
            assert assessment.base_score == expected_score
            assert assessment.severity == expected_sev
            assert assessment.vector is not None
            assert assessment.vector.startswith("CVSS:3.1/")
            assert len(assessment.scoring_rationale) > 0
            assert assessment.finding_id == finding.id
            assert assessment.review_reasons == ()

    def test_archetype_assessment_cvss40(self) -> None:
        """Test scoring of known vulnerability archetypes using CVSS 4.0."""
        engine = RiskEngine()

        finding_sqli = Finding(
            finding_type="sqli",
            title="SQL Injection on endpoint",
            asset_id="asset_1",
            severity=Severity.HIGH,
            confidence=0.9,
        )
        assessment_sqli = engine.assess_finding(finding_sqli, cvss_version="4.0")
        assert assessment_sqli.review_status == ReviewStatus.ASSESSED
        assert assessment_sqli.cvss_version == "4.0"
        assert assessment_sqli.base_score == 9.3
        assert assessment_sqli.severity == Severity.CRITICAL
        assert assessment_sqli.vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

        finding_rce = Finding(
            finding_type="rce",
            title="Remote Code Execution",
            asset_id="asset_1",
            severity=Severity.CRITICAL,
            confidence=1.0,
        )
        assessment_rce = engine.assess_finding(finding_rce, cvss_version="4.0")
        assert assessment_rce.review_status == ReviewStatus.ASSESSED
        assert assessment_rce.base_score == 10.0
        assert assessment_rce.severity == Severity.CRITICAL

        finding_xss = Finding(
            finding_type="xss",
            title="Cross-Site Scripting",
            asset_id="asset_1",
            severity=Severity.MEDIUM,
            confidence=0.8,
        )
        assessment_xss = engine.assess_finding(finding_xss, cvss_version="4.0")
        assert assessment_xss.review_status == ReviewStatus.ASSESSED
        assert assessment_xss.base_score == 5.1
        assert assessment_xss.severity == Severity.MEDIUM

    def test_ambiguous_finding_requires_review(self) -> None:
        """Test that unclassified, ambiguous, or speculative findings are marked REQUIRES_REVIEW."""
        engine = RiskEngine()

        ambiguous_finding = Finding(
            finding_type="heuristic_port_anomaly",
            title="Unrecognized banner on high port 8888",
            asset_id="asset_999",
            severity=Severity.LOW,
            confidence=0.4,
            description="Raw string returned from socket connect: 'SERVICE_READY'",
        )

        assessment = engine.assess_finding(ambiguous_finding, cvss_version="3.1")

        assert assessment.review_status == ReviewStatus.REQUIRES_REVIEW
        assert assessment.base_score is None
        assert assessment.vector is None
        assert assessment.severity == Severity.LOW  # Retains finding severity
        assert len(assessment.review_reasons) > 0
        assert "analyst verification" in assessment.review_reasons[1]
        assert "Insufficient evidence" in assessment.scoring_rationale
        assert assessment.finding_id == ambiguous_finding.id

    def test_assess_vector_supplied_by_user(self) -> None:
        """Test parsing and evaluating arbitrary supplied CVSS 3.1 and 4.0 vectors."""
        engine = RiskEngine()

        # Supplied CVSS 3.1
        res31 = engine.assess_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert res31.cvss_version == "3.1"
        assert res31.base_score == 9.8
        assert res31.severity == Severity.CRITICAL
        assert res31.review_status == ReviewStatus.ASSESSED

        # Supplied CVSS 4.0
        res40 = engine.assess_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
        assert res40.cvss_version == "4.0"
        assert res40.base_score == 10.0
        assert res40.severity == Severity.CRITICAL
        assert res40.review_status == ReviewStatus.ASSESSED

        # Malformed / Unrecognized prefix
        with pytest.raises(ValueError, match="Unrecognized CVSS vector format"):
            engine.assess_vector("INVALID_VECTOR_STRING")

    def test_unsupported_cvss_version(self) -> None:
        """Test unsupported CVSS version raises ValueError."""
        engine = RiskEngine()
        finding = Finding(
            finding_type="sqli",
            title="SQLi",
            asset_id="asset_1",
            severity=Severity.HIGH,
            confidence=0.9,
        )
        with pytest.raises(ValueError, match="Unsupported CVSS version '2.0'"):
            engine.assess_finding(finding, cvss_version="2.0")


class TestPhase10AcceptanceCriteria:
    """Explicitly verifies Phase 10 Acceptance Criteria:

    'Every risk score has a reproducible vector/rationale or is explicitly marked as requiring review.'
    """

    def test_acceptance_criteria_invariant_across_sample_suite(self) -> None:
        """Verify the invariant holds across both assessed archetypes and ambiguous findings."""
        engine = RiskEngine()

        findings_sample = [
            # Assessed findings
            Finding(
                finding_type="sqli",
                title="SQL Injection in auth",
                asset_id="a1",
                severity=Severity.HIGH,
                confidence=1.0,
            ),
            Finding(
                finding_type="command_injection",
                title="RCE via parameter",
                asset_id="a2",
                severity=Severity.CRITICAL,
                confidence=1.0,
            ),
            Finding(
                finding_type="xss",
                title="Cross-Site Scripting in comments",
                asset_id="a3",
                severity=Severity.MEDIUM,
                confidence=0.9,
            ),
            Finding(
                finding_type="path_traversal",
                title="Directory Traversal via filename",
                asset_id="a4",
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            Finding(
                finding_type="sensitive_files",
                title="Exposed .git repository",
                asset_id="a5",
                severity=Severity.HIGH,
                confidence=0.95,
            ),
            # Ambiguous / Non-archetype findings
            Finding(
                finding_type="heuristic_port_open",
                title="Unknown open port 9000",
                asset_id="a6",
                severity=Severity.INFO,
                confidence=0.3,
            ),
            Finding(
                finding_type="ssl_certificate_metadata",
                title="Certificate expires in 90 days",
                asset_id="a7",
                severity=Severity.LOW,
                confidence=0.5,
            ),
            Finding(
                finding_type="unclassified_response_anomaly",
                title="Unexpected 418 status code",
                asset_id="a8",
                severity=Severity.LOW,
                confidence=0.2,
            ),
        ]

        for cvss_version in ("3.1", "4.0"):
            for finding in findings_sample:
                assessment: RiskAssessment = engine.assess_finding(finding, cvss_version=cvss_version)

                if assessment.review_status == ReviewStatus.ASSESSED:
                    # Invariant 1: ASSESSED must have valid score, vector, and rationale
                    assert assessment.base_score is not None
                    assert 0.0 <= assessment.base_score <= 10.0
                    assert assessment.vector is not None
                    assert assessment.vector.startswith(f"CVSS:{cvss_version}/")
                    assert len(assessment.scoring_rationale.strip()) > 0
                    assert assessment.review_reasons == ()

                    # Invariant 2: The vector must be 100% reproducible
                    # Recalculating the vector must yield the exact same base_score
                    if cvss_version == "3.1":
                        recalc_score, _ = engine.calc_31.calculate_from_vector(assessment.vector)
                    else:
                        recalc_score, _ = engine.calc_40.calculate_from_vector(assessment.vector)

                    assert recalc_score == assessment.base_score, (
                        f"Non-reproducible score for {finding.title}: "
                        f"assessed={assessment.base_score}, recalculated={recalc_score}"
                    )

                elif assessment.review_status == ReviewStatus.REQUIRES_REVIEW:
                    # Invariant 3: REQUIRES_REVIEW must not hallucinate a score or vector
                    assert assessment.base_score is None, (
                        f"Score must be None for REQUIRES_REVIEW, got {assessment.base_score}"
                    )
                    assert assessment.vector is None, (
                        f"Vector must be None for REQUIRES_REVIEW, got {assessment.vector}"
                    )
                    assert len(assessment.scoring_rationale.strip()) > 0
                    assert len(assessment.review_reasons) > 0, (
                        "Explicit reasons must be provided for REQUIRES_REVIEW"
                    )

                else:
                    pytest.fail(f"Invalid ReviewStatus: {assessment.review_status}")

    def test_end_to_end_phase9_correlation_to_phase10_risk_engine(self) -> None:
        """Verify seamless pipeline: Phase 9 FindingCorrelator -> Phase 10 RiskEngine."""
        # Create multi-source observations as produced by Phase 8/9
        obs_nikto = Observation(
            type="vulnerability_hint",
            asset_id="asset_test",
            source="nikto",
            data={
                "title": "SQL Injection in parameter id",
                "endpoint": "http://example.com/login.php",
                "parameter": "id",
                "severity": "high",
            },
        )
        obs_sqlmap = Observation(
            type="vulnerability_hint",
            asset_id="asset_test",
            source="sqlmap",
            data={
                "title": "Confirmed boolean-based blind SQL injection",
                "endpoint": "http://example.com/login.php?id=1",
                "parameter": "id",
                "injection_type": "boolean-based blind",
                "severity": "high",
            },
        )

        correlator = FindingCorrelator()
        findings = correlator.correlate(
            observations=[obs_nikto, obs_sqlmap],
            asset_id="asset_test",
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.confidence >= 0.9

        # Now pass this synthesized finding into Phase 10 RiskEngine
        risk_engine = RiskEngine()

        # CVSS 3.1 evaluation
        assess_31 = risk_engine.assess_finding(finding, cvss_version="3.1")
        assert assess_31.review_status == ReviewStatus.ASSESSED
        assert assess_31.base_score == 9.1
        assert assess_31.severity == Severity.CRITICAL
        assert assess_31.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        assert "SQL injection" in assess_31.scoring_rationale

        # CVSS 4.0 evaluation
        assess_40 = risk_engine.assess_finding(finding, cvss_version="4.0")
        assert assess_40.review_status == ReviewStatus.ASSESSED
        assert assess_40.base_score == 9.3
        assert assess_40.severity == Severity.CRITICAL
        assert assess_40.vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

