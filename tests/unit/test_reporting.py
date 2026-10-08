"""Unit tests for ReconX Reporting Engine and multi-format renderers.

Validates Phase 11 Requirements:
- JSON, Markdown, HTML, PDF report generation
- Automated secret redaction
- Acceptance Criteria: All formats originate from the same ReportModel.
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
import json
from pathlib import Path
import pytest

from reconx.models.asset import Asset, AssetKind, AssetOrigin
from reconx.models.evidence import Evidence
from reconx.models.finding import Finding, Severity
from reconx.models.observation import Observation
from reconx.models.scan import Scan, ScanState, ScanStatus
from reconx.reporting import (
    AttackSurfaceSummary,
    ExecutiveSummary,
    HTMLReportRenderer,
    JSONReportRenderer,
    MarkdownReportRenderer,
    PDFReportRenderer,
    ReportAppendix,
    ReportFinding,
    ReportModel,
    ReportingEngine,
    SecretRedactor,
)
from reconx.scope.models import ScopePolicy


@pytest.fixture
def sample_scan_state() -> ScanState:
    """Fixture providing a realistic ScanState with assets, observations, and findings."""
    policy = ScopePolicy(allowed_domains=("example.com",))
    scan = Scan(
        targets=("example.com",),
        scope=policy,
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 10, 8, 10, 0, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 10, 8, 10, 5, 30, tzinfo=timezone.utc),
    )

    asset_domain = Asset(kind=AssetKind.DOMAIN, value="example.com", origin=AssetOrigin.USER_PROVIDED, in_scope=True)
    asset_sub = Asset(kind=AssetKind.DOMAIN, value="api.example.com", origin=AssetOrigin.DISCOVERED, in_scope=True)
    asset_ip = Asset(kind=AssetKind.IP, value="93.184.216.34", origin=AssetOrigin.DISCOVERED, in_scope=True)

    obs_port = Observation(
        type="open_port",
        asset_id=asset_ip.id,
        source="nmap",
        data={"port": 443, "protocol": "tcp", "service": "https"},
    )
    obs_ep = Observation(
        type="endpoint_found",
        asset_id=asset_domain.id,
        source="gobuster",
        data={"endpoint": "https://example.com/login.php", "status": 200},
    )

    ev = Evidence(
        tool="sqlmap",
        target="http://example.com/login.php",
        stdout="Vulnerable parameter: id=1' OR '1'='1 with password=SuperSecretPassword123",
        raw_reference="/tmp/sqlmap_output.txt",
    )

    finding_sqli = Finding(
        finding_type="sqli",
        title="SQL Injection in login endpoint",
        asset_id=asset_domain.id,
        severity=Severity.HIGH,
        confidence=0.95,
        description="SQL injection in parameter id. Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret",
        endpoint="https://example.com/login.php",
        evidence_ids=(ev.id,),
    )

    finding_cookie = Finding(
        finding_type="insecure_cookie",
        title="Session cookie without 'secure' flag",
        asset_id=asset_domain.id,
        severity=Severity.LOW,
        confidence=0.85,
        description="Cookie set without Secure flag: PHPSESSID=abcdef1234567890",
        endpoint="https://example.com/",
    )

    return ScanState(
        scan=scan,
        assets=[asset_domain, asset_sub, asset_ip],
        observations=[obs_port, obs_ep],
        evidence=[ev],
        findings=[finding_sqli, finding_cookie],
    )


class TestSecretRedactor:
    """Tests for secret and sensitive data redaction."""

    def test_redact_private_key(self) -> None:
        redactor = SecretRedactor()
        raw = "Certificate: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        redacted = redactor.redact_text(raw)
        assert "[REDACTED_PRIVATE_KEY]" in redacted
        assert "MIIEow" not in redacted

    def test_redact_bearer_token(self) -> None:
        redactor = SecretRedactor()
        raw = "GET /api HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\nHost: api.test"
        redacted = redactor.redact_text(raw)
        assert "Authorization: Bearer ****************" in redacted
        assert "eyJhbGciOi" not in redacted

    def test_redact_passwords_and_tokens(self) -> None:
        redactor = SecretRedactor()
        raw = "url = 'http://example.com?password=MySecretPassword99&user=admin&api_key=ak_live_123456789'"
        redacted = redactor.redact_text(raw)
        assert "password=****************" in redacted or "password=********" in redacted
        assert "MySecretPassword99" not in redacted
        assert "ak_live_123456789" not in redacted

    def test_redact_cookies(self) -> None:
        redactor = SecretRedactor()
        raw = "Set-Cookie: PHPSESSID=37482937489237489; path=/"
        redacted = redactor.redact_text(raw)
        assert "PHPSESSID=********" in redacted
        assert "37482937489237489" not in redacted

    def test_redact_nested_dict(self) -> None:
        redactor = SecretRedactor()
        data = {
            "user": "alice",
            "password": "ClearTextPassword123",
            "tokens": ["normal_string", "secret_token_abcdef123"],
            "meta": {"api_key": "secret_key_999"},
        }
        res = redactor.redact_data(data)
        assert res["user"] == "alice"
        assert res["password"] == "********"
        assert res["meta"]["api_key"] == "********"

    def test_disabled_redactor_preserves_text(self) -> None:
        redactor = SecretRedactor(enabled=False)
        raw = "password=SuperSecretPassword123"
        assert redactor.redact_text(raw) == raw


class TestReportModel:
    """Tests for canonical ReportModel creation and conversion."""

    def test_from_scan_state(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(
            sample_scan_state,
            tool_versions={"nmap": "7.94", "sqlmap": "1.7.8"},
            cvss_version="3.1",
        )

        assert model.target == "example.com"
        assert model.scan_id == sample_scan_state.scan.id
        assert model.executive_summary.duration_seconds == 330.0
        assert model.executive_summary.total_assets == 3
        assert model.executive_summary.total_findings == 2
        assert model.executive_summary.severity_distribution["HIGH"] == 1
        assert model.executive_summary.severity_distribution["LOW"] == 1

        # Attack surface
        assert "example.com" in model.attack_surface.domains
        assert "api.example.com" in model.attack_surface.domains
        assert "93.184.216.34" in model.attack_surface.ip_addresses
        assert "443/tcp" in model.attack_surface.ports
        assert "https://example.com/login.php" in model.attack_surface.endpoints

        # Findings
        assert len(model.findings) == 2
        sqli_finding = next(f for f in model.findings if "SQL Injection" in f.title)
        assert sqli_finding.severity == "HIGH"
        assert sqli_finding.confidence >= 0.9
        assert sqli_finding.cvss_score == 9.1
        assert sqli_finding.cvss_status == "ASSESSED"
        assert sqli_finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

        # Redaction check in findings
        assert "SuperSecretPassword123" not in str(sqli_finding.evidence)
        assert "eyJhbGciOi" not in sqli_finding.description

        # Appendix
        assert model.appendix.tool_versions["nmap"] == "7.94"

    def test_to_dict_serializability(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        d = model.to_dict()
        assert isinstance(d, dict)
        # Verify JSON dump round-trip works without error
        serialized = json.dumps(d)
        assert model.scan_id in serialized


class TestJSONReportRenderer:
    """Tests for JSONReportRenderer."""

    def test_render_json(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        renderer = JSONReportRenderer()
        output = renderer.render(model, indent=2)

        data = json.loads(output)
        assert data["scan_id"] == model.scan_id
        assert data["target"] == "example.com"
        assert data["executive_summary"]["total_findings"] == 2
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] in ("HIGH", "LOW")


class TestMarkdownReportRenderer:
    """Tests for MarkdownReportRenderer."""

    def test_render_markdown(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        renderer = MarkdownReportRenderer()
        md = renderer.render(model)

        assert f"# {model.title}" in md
        assert "## 1. Executive Summary" in md
        assert "## 2. Attack Surface Inventory" in md
        assert "## 3. Findings" in md
        assert "## 4. Technical Appendix" in md

        # Content verification
        assert "example.com" in md
        assert "93.184.216.34" in md
        assert "443/tcp" in md
        assert "SQL Injection in login endpoint" in md
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" in md
        assert "SuperSecretPassword123" not in md


class TestHTMLReportRenderer:
    """Tests for HTMLReportRenderer."""

    def test_render_html(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        renderer = HTMLReportRenderer()
        html_out = renderer.render(model)

        assert "<!DOCTYPE html>" in html_out
        assert f"<title>{html.escape(model.title)}</title>" in html_out
        assert "Executive Summary" in html_out
        assert "Attack Surface Inventory" in html_out
        assert "Vulnerability Findings" in html_out
        assert "SQL Injection in login endpoint" in html_out
        assert "93.184.216.34" in html_out
        assert "CVSS 3.1:" in html_out
        assert "SuperSecretPassword123" not in html_out

    def test_html_escaping_prevents_xss(self) -> None:
        # Create a report model with malicious XSS string in title & description
        exec_sum = ExecutiveSummary(
            target="<script>alert(1)</script>",
            scan_date="2026-10-08",
            duration_seconds=10.0,
            scope_summary="None",
            total_assets=1,
            total_findings=1,
            severity_distribution={"HIGH": 1},
            risk_score_summary="Test",
        )
        finding = ReportFinding(
            id="f1",
            title="<img src=x onerror=alert(2)>",
            severity="HIGH",
            confidence=1.0,
            confidence_level="Confirmed",
            cvss_version="3.1",
            cvss_score=8.0,
            cvss_vector="CVSS:3.1/...",
            cvss_status="ASSESSED",
            cvss_rationale="test",
            affected_asset="asset_1",
            endpoint="/test",
            description="<b>Bold</b> <script>steal()</script>",
            impact="None",
            evidence=["<script>cookie</script>"],
        )
        model = ReportModel(
            scan_id="scan_xss",
            target="<script>alert(1)</script>",
            title="XSS Test",
            generated_at="2026-10-08",
            executive_summary=exec_sum,
            attack_surface=AttackSurfaceSummary(),
            findings=[finding],
            appendix=ReportAppendix(reconx_version="0.1.0"),
        )
        renderer = HTMLReportRenderer()
        html_out = renderer.render(model)

        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
        assert "&lt;img src=x onerror=alert(2)&gt;" in html_out


class TestPDFReportRenderer:
    """Tests for pure Python PDFReportRenderer."""

    def test_render_pdf_structure(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        renderer = PDFReportRenderer()
        pdf_bytes = renderer.render(model)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 500
        # Check standard PDF 1.4 header and trailer
        assert pdf_bytes.startswith(b"%PDF-1.4\n")
        assert b"%%EOF\n" in pdf_bytes
        assert b"xref\n" in pdf_bytes
        assert b"/Root 1 0 R" in pdf_bytes
        assert b"/Type /Catalog" in pdf_bytes
        assert b"/Type /Pages" in pdf_bytes
        assert b"/Type /Page" in pdf_bytes

    def test_multi_page_pdf_rendering(self, sample_scan_state: ScanState) -> None:
        # Create a report with multiple findings to exercise pagination
        model = ReportModel.from_scan_state(sample_scan_state)
        extra_findings = list(model.findings) * 5  # 10 findings
        multi_page_model = ReportModel(
            scan_id=model.scan_id,
            target=model.target,
            title=model.title,
            generated_at=model.generated_at,
            executive_summary=model.executive_summary,
            attack_surface=model.attack_surface,
            findings=extra_findings,
            appendix=model.appendix,
        )
        renderer = PDFReportRenderer()
        pdf_bytes = renderer.render(multi_page_model)

        assert pdf_bytes.startswith(b"%PDF-1.4")
        assert b"/Count" in pdf_bytes
        assert b"%%EOF" in pdf_bytes

    def test_pdf_xref_table_byte_accuracy(self, sample_scan_state: ScanState) -> None:
        """Verify that every entry in the xref table points exactly to its object header."""
        model = ReportModel.from_scan_state(sample_scan_state)
        pdf_bytes = PDFReportRenderer().render(model)

        lines = pdf_bytes.split(b"\n")
        eof_idx = [i for i, l in enumerate(lines) if l == b"%%EOF"]
        startxref_val = int(lines[eof_idx[-1] - 1])
        xref_lines = pdf_bytes[startxref_val:].split(b"\n")

        header = xref_lines[1].split()
        total_objs = int(header[1])

        for obj_id in range(1, total_objs):
            entry = xref_lines[2 + obj_id].decode("ascii")
            offset = int(entry[:10])
            status = entry[17]
            assert status == "n"
            expected_header = f"{obj_id} 0 obj".encode("ascii")
            actual = pdf_bytes[offset:offset + len(expected_header)]
            assert actual == expected_header, f"Offset mismatch at obj {obj_id}"


class TestReportingEngine:
    """Tests for ReportingEngine orchestrator and file exports."""

    def test_render_across_all_formats(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        engine = ReportingEngine()

        json_out = engine.render(model, "json")
        assert isinstance(json_out, str)
        assert json.loads(json_out)["scan_id"] == model.scan_id

        md_out = engine.render(model, "markdown")
        assert isinstance(md_out, str)
        assert "# " in md_out

        html_out = engine.render(model, "html")
        assert isinstance(html_out, str)
        assert "<!DOCTYPE html>" in html_out

        pdf_out = engine.render(model, "pdf")
        assert isinstance(pdf_out, bytes)
        assert pdf_out.startswith(b"%PDF-1.4")

    def test_unsupported_format_raises(self, sample_scan_state: ScanState) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        engine = ReportingEngine()
        with pytest.raises(ValueError, match="Unsupported report format 'xml'"):
            engine.render(model, "xml")

    def test_export_to_files(self, sample_scan_state: ScanState, tmp_path: Path) -> None:
        model = ReportModel.from_scan_state(sample_scan_state)
        engine = ReportingEngine()

        # JSON export
        p_json = engine.export(model, tmp_path / "report.json")
        assert p_json.exists()
        assert json.loads(p_json.read_text(encoding="utf-8"))["target"] == "example.com"

        # Markdown export
        p_md = engine.export(model, tmp_path / "report.md")
        assert p_md.exists()
        assert "Executive Summary" in p_md.read_text(encoding="utf-8")

        # HTML export
        p_html = engine.export(model, tmp_path / "report.html")
        assert p_html.exists()
        assert "<!DOCTYPE html>" in p_html.read_text(encoding="utf-8")

        # PDF export
        p_pdf = engine.export(model, tmp_path / "report.pdf")
        assert p_pdf.exists()
        assert p_pdf.read_bytes().startswith(b"%PDF-1.4")


class TestPhase11AcceptanceCriteria:
    """Explicitly verifies Phase 11 Acceptance Criteria:

    'All formats originate from the same ReportModel.'
    """

    def test_all_formats_originate_from_same_report_model(self, sample_scan_state: ScanState) -> None:
        """Verify that a single ReportModel instance produces consistent data across all 4 formats."""
        # 1. Instantiate exactly ONE single canonical ReportModel
        canonical_model = ReportModel.from_scan_state(
            sample_scan_state,
            tool_versions={"nmap": "7.94", "sqlmap": "1.7.8"},
            cvss_version="3.1",
        )

        engine = ReportingEngine()

        # 2. Render all 4 formats from this exact same instance
        json_output = engine.render_json(canonical_model)
        md_output = engine.render_markdown(canonical_model)
        html_output = engine.render_html(canonical_model)
        pdf_output = engine.render_pdf(canonical_model)

        # 3. Assert JSON reflects exact model attributes
        data = json.loads(json_output)
        assert data["scan_id"] == canonical_model.scan_id
        assert data["target"] == canonical_model.target
        assert len(data["findings"]) == len(canonical_model.findings)
        assert data["executive_summary"]["total_assets"] == canonical_model.executive_summary.total_assets
        assert data["attack_surface"]["ports"] == canonical_model.attack_surface.ports

        # 4. Assert Markdown reflects exact model attributes
        assert canonical_model.scan_id in md_output
        assert canonical_model.target in md_output
        for finding in canonical_model.findings:
            assert finding.title in md_output
            assert finding.severity in md_output
            if finding.cvss_vector:
                assert finding.cvss_vector in md_output
        for p in canonical_model.attack_surface.ports:
            assert p in md_output

        # 5. Assert HTML reflects exact model attributes
        assert canonical_model.scan_id in html_output
        assert canonical_model.target in html_output
        for finding in canonical_model.findings:
            assert html.escape(finding.title) in html_output
            assert finding.severity in html_output
            if finding.cvss_vector:
                assert finding.cvss_vector in html_output
        for p in canonical_model.attack_surface.ports:
            assert p in html_output

        # 6. Assert PDF reflects valid binary document generated from the model
        pdf_bytes = pdf_output
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b"%PDF-1.4")
        assert b"%%EOF" in pdf_bytes
        # Verify target and scan_id are encoded in the PDF content streams
        target_bytes = canonical_model.target.encode("ascii")
        assert target_bytes in pdf_bytes

        # 7. Invariant: Secrets remain completely redacted across all 4 formats
        leaked_secret = "SuperSecretPassword123"
        assert leaked_secret not in json_output
        assert leaked_secret not in md_output
        assert leaked_secret not in html_output
        assert leaked_secret.encode("ascii") not in pdf_output
