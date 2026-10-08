"""Unit tests for Phase 9 finding intelligence engine.

Covers:
- Vulnerability classification & taxonomy mapping (CWE, OWASP Top 10)
- Multi-source corroborative confidence scoring
- Canonical deduplication and fingerprinting
- Finding correlation and evidence enrichment
- Discovery inventory aggregation
- Phase 9 Acceptance Criteria verification:
  'Multiple observations can produce a single high-confidence finding.'
"""

from __future__ import annotations

from reconx.engine.classification import (
    VulnerabilityCategory,
    VulnerabilityClassifier,
)
from reconx.engine.confidence import (
    ConfidenceScorer,
)
from reconx.engine.correlation import (
    CorrelationResult,
    FindingCorrelator,
)
from reconx.engine.deduplication import (
    VulnerabilityDeduplicator,
    extract_url_path,
    normalize_parameter,
    normalize_url,
)
from reconx.engine.discovery import (
    DiscoveryEngine,
)
from reconx.models.evidence import Evidence
from reconx.models.finding import Finding, Severity
from reconx.models.observation import Observation
from reconx.models.vulnerability import ExecutionMode, VulnerabilityObservation


# ==============================================================================
# 1. Classification Tests
# ==============================================================================

class TestVulnerabilityClassification:
    """Test classification into CWE, OWASP Top 10, and normalized categories."""

    def test_sql_injection_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Parameter 'id' is vulnerable to SQL injection",
            description="boolean-based blind SQL injection detected on MySQL",
            parameter="id",
        )
        assert result.category == VulnerabilityCategory.INJECTION
        assert result.cwe_id == "CWE-89"
        assert result.owasp_category == "A03:2021-Injection"
        assert result.default_severity == Severity.HIGH
        assert "parameterized" in result.remediation.lower()

    def test_command_injection_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Remote OS Command Injection via ping parameter",
            description="Arbitrary shell execution detected",
        )
        assert result.category == VulnerabilityCategory.INJECTION
        assert result.cwe_id == "CWE-78"
        assert result.owasp_category == "A03:2021-Injection"
        assert result.default_severity == Severity.CRITICAL

    def test_xss_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Reflected Cross-Site Scripting (XSS)",
            description="Payload <script>alert(1)</script> was reflected in response body",
        )
        assert result.category == VulnerabilityCategory.INJECTION
        assert result.cwe_id == "CWE-79"
        assert result.owasp_category == "A03:2021-Injection"
        assert result.default_severity == Severity.MEDIUM

    def test_path_traversal_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Local File Inclusion / Path Traversal",
            description="Detected ../../../etc/passwd retrieval",
        )
        assert result.category == VulnerabilityCategory.BROKEN_ACCESS_CONTROL
        assert result.cwe_id == "CWE-22"
        assert result.owasp_category == "A01:2021-Broken Access Control"
        assert result.default_severity == Severity.HIGH

    def test_directory_indexing_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Directory Indexing / Listing enabled on /images",
            description="Apache mod_autoindex found",
        )
        assert result.category == VulnerabilityCategory.INFORMATION_DISCLOSURE
        assert result.cwe_id == "CWE-548"
        assert result.owasp_category == "A01:2021-Broken Access Control"
        assert result.default_severity == Severity.LOW

    def test_missing_security_headers_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="The anti-clickjacking X-Frame-Options header is not present",
            description="Missing standard protection headers",
        )
        assert result.category == VulnerabilityCategory.SECURITY_MISCONFIGURATION
        assert result.cwe_id == "CWE-693"
        assert result.owasp_category == "A05:2021-Security Misconfiguration"
        assert result.default_severity == Severity.LOW

    def test_cve_pattern_extraction_and_classification(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Apache HTTP Server vulnerable to CVE-2021-41773 path traversal",
            description="Exploit available for Apache 2.4.49",
        )
        assert result.cve == "CVE-2021-41773"
        assert result.cwe_id == "CWE-22"

    def test_unknown_vulnerability_fallback(self) -> None:
        classifier = VulnerabilityClassifier()
        result = classifier.classify(
            title="Miscellaneous obscure warning 999",
            description="Unrecognized diagnostic string",
        )
        assert result.category == VulnerabilityCategory.UNKNOWN
        assert result.cwe_id is None
        assert result.default_severity == Severity.INFO

    def test_classify_observation_model(self) -> None:
        classifier = VulnerabilityClassifier()
        obs = VulnerabilityObservation(
            tool="sqlmap",
            target="http://example.local",
            endpoint="/api/items",
            title="DBMS: PostgreSQL injection",
            description="Error-based SQL injection on parameter item_id",
            parameter="item_id",
            injection_type="error-based",
        ).to_observation(asset_id="asset-1")

        result = classifier.classify_observation(obs)
        assert result.category == VulnerabilityCategory.INJECTION
        assert result.cwe_id == "CWE-89"
        assert result.default_severity == Severity.HIGH


# ==============================================================================
# 2. Confidence Scoring Tests
# ==============================================================================

class TestConfidenceScoring:
    """Test single and multi-source corroborative confidence scoring."""

    def test_default_tool_weights_defined(self) -> None:
        scorer = ConfidenceScorer()
        assert scorer.get_tool_weight("sqlmap") == 0.85
        assert scorer.get_tool_weight("nikto") == 0.50
        assert scorer.get_tool_weight("gobuster") == 0.70
        assert scorer.get_tool_weight("curl") == 0.75
        assert scorer.get_tool_weight("unknown_tool") == 0.45

    def test_single_observation_confidence(self) -> None:
        scorer = ConfidenceScorer()
        obs = VulnerabilityObservation(
            tool="nikto",
            target="http://example.com",
            endpoint="/login",
            title="Missing X-Frame-Options header",
            description="",
            execution_mode=ExecutionMode.SAFE,
        ).to_observation(asset_id="a1")

        score = scorer.score_single(obs)
        assert 0.40 <= score <= 0.60

    def test_observation_with_parameter_and_active_mode_elevated(self) -> None:
        scorer = ConfidenceScorer()
        obs = VulnerabilityObservation(
            tool="sqlmap",
            target="http://example.com",
            endpoint="/search.php",
            title="SQLi on parameter q",
            description="",
            parameter="q",
            injection_type="boolean-based blind",
            execution_mode=ExecutionMode.ACTIVE,
        ).to_observation(asset_id="a1")

        score = scorer.score_single(obs)
        # 0.85 base + parameter (0.05) + injection_type (0.05) + active (0.04) -> ~0.95
        assert score >= 0.90

    def test_multi_tool_corroboration_boosts_confidence(self) -> None:
        scorer = ConfidenceScorer()

        obs_nikto = VulnerabilityObservation(
            tool="nikto",
            target="http://example.com",
            endpoint="/test.php?id=1",
            title="SQL injection hint",
            description="Potential SQLi",
        ).to_observation(asset_id="a1")

        obs_sqlmap = VulnerabilityObservation(
            tool="sqlmap",
            target="http://example.com",
            endpoint="/test.php",
            title="SQL injection confirmed",
            description="Parameter id is injectable",
            parameter="id",
        ).to_observation(asset_id="a1")

        assessment = scorer.evaluate([obs_nikto, obs_sqlmap])

        # Multi-tool corroboration elevates score above either single tool
        assert assessment.score > scorer.score_single(obs_nikto)
        assert assessment.score > scorer.score_single(obs_sqlmap)
        assert assessment.score >= 0.90
        assert assessment.confidence_level == "CONFIRMED"
        assert assessment.independent_tool_count == 2
        assert "Multi-tool corroboration" in assessment.rationale
        assert "nikto" in assessment.sources
        assert "sqlmap" in assessment.sources

    def test_triple_tool_corroboration(self) -> None:
        scorer = ConfidenceScorer()

        obs1 = Observation(type="endpoint_discovery", asset_id="a1", source="gobuster", data={"path": "/backup.zip"})
        obs2 = Observation(type="endpoint_discovery", asset_id="a1", source="ffuf", data={"path": "/backup.zip"})
        obs3 = Observation(type="vulnerability_hint", asset_id="a1", source="nikto", data={"path": "/backup.zip", "title": "Exposed backup archive"})

        assessment = scorer.evaluate([obs1, obs2, obs3])
        assert assessment.independent_tool_count == 3
        assert assessment.score >= 0.95
        assert assessment.confidence_level == "CONFIRMED"

    def test_intra_tool_multiple_observations_boost(self) -> None:
        scorer = ConfidenceScorer()

        obs1 = VulnerabilityObservation(
            tool="sqlmap", target="http://example.com", endpoint="/view", title="Boolean blind SQLi", description="Blind SQLi", parameter="id"
        ).to_observation(asset_id="a1")
        obs2 = VulnerabilityObservation(
            tool="sqlmap", target="http://example.com", endpoint="/view", title="Time-based blind SQLi", description="Time SQLi", parameter="id"
        ).to_observation(asset_id="a1")

        assessment = scorer.evaluate([obs1, obs2])
        assert assessment.independent_tool_count == 1
        assert assessment.observation_count == 2
        assert assessment.score >= 0.90


# ==============================================================================
# 3. Deduplication Tests
# ==============================================================================

class TestDeduplication:
    """Test URL normalization, canonical fingerprinting, and observation clustering."""

    def test_url_normalization(self) -> None:
        url1 = "HTTP://Example.COM:80/api/users/?b=2&a=1&_=12345"
        norm1 = normalize_url(url1)
        assert norm1 == "http://example.com/api/users?a=1&b=2"

        url2 = "https://example.com:443/test//path/"
        norm2 = normalize_url(url2)
        assert norm2 == "https://example.com/test/path"

        # Relative path with base target
        norm3 = normalize_url("/login.php?q=test", base_target="https://target.com")
        assert norm3 == "https://target.com/login.php?q=test"

    def test_extract_url_path(self) -> None:
        assert extract_url_path("http://example.com/api/v1/search?q=1&p=2") == "http://example.com/api/v1/search"

    def test_normalize_parameter(self) -> None:
        assert normalize_parameter("ID") == "id"
        assert normalize_parameter("user_name (GET)") == "user_name"
        assert normalize_parameter("  ") is None
        assert normalize_parameter(None) is None

    def test_parameter_level_fingerprint_matches_across_tools(self) -> None:
        deduplicator = VulnerabilityDeduplicator()

        obs_nikto = VulnerabilityObservation(
            tool="nikto",
            target="http://example.com",
            endpoint="/search.php?q=1",
            title="SQL injection in search.php",
            description="Potential SQLi",
            parameter="q",
        ).to_observation(asset_id="a1")

        obs_sqlmap = VulnerabilityObservation(
            tool="sqlmap",
            target="http://example.com",
            endpoint="/search.php",
            title="Parameter: q (GET) is vulnerable to SQL injection",
            description="Confirmed SQLi",
            parameter="q",
            injection_type="boolean-based blind",
        ).to_observation(asset_id="a1")

        fp1 = deduplicator.compute_fingerprint(obs_nikto)
        fp2 = deduplicator.compute_fingerprint(obs_sqlmap)

        assert fp1.fingerprint == fp2.fingerprint
        assert fp1.scope_level == "parameter"

    def test_host_level_security_headers_deduplication(self) -> None:
        deduplicator = VulnerabilityDeduplicator()

        # Same missing header on two different endpoints of the same host
        obs_page1 = VulnerabilityObservation(
            tool="nikto",
            target="http://example.com",
            endpoint="/index.php",
            title="The anti-clickjacking X-Frame-Options header is not present",
            description="Missing header",
        ).to_observation(asset_id="a1")

        obs_page2 = VulnerabilityObservation(
            tool="nikto",
            target="http://example.com",
            endpoint="/about.php",
            title="The anti-clickjacking X-Frame-Options header is not present",
            description="Missing header",
        ).to_observation(asset_id="a1")

        fp1 = deduplicator.compute_fingerprint(obs_page1)
        fp2 = deduplicator.compute_fingerprint(obs_page2)

        assert fp1.fingerprint == fp2.fingerprint
        assert fp1.scope_level == "host"

    def test_clustering_groups_related_observations(self) -> None:
        deduplicator = VulnerabilityDeduplicator()

        obs1 = VulnerabilityObservation(
            tool="nikto", target="http://example.com", endpoint="/test.php", title="SQL injection hint", description="Hint", parameter="id"
        ).to_observation(asset_id="a1")
        obs2 = VulnerabilityObservation(
            tool="sqlmap", target="http://example.com", endpoint="/test.php", title="SQL injection confirmed", description="Confirmed", parameter="id"
        ).to_observation(asset_id="a1")
        obs3 = VulnerabilityObservation(
            tool="nikto", target="http://example.com", endpoint="/", title="Missing X-Frame-Options header", description="Missing"
        ).to_observation(asset_id="a1")

        clusters = deduplicator.cluster([obs1, obs2, obs3])
        assert len(clusters) == 2  # SQLi cluster and Security Header cluster


# ==============================================================================
# 4. Correlation & Evidence Enrichment Tests
# ==============================================================================

class TestFindingCorrelation:
    """Test correlation orchestrator producing normalized Finding objects."""

    def test_correlate_single_observation(self) -> None:
        correlator = FindingCorrelator()
        obs = VulnerabilityObservation(
            tool="nikto",
            target="http://target.local",
            endpoint="/admin",
            title="Directory indexing enabled on /admin",
            description="Directory listing exposes backup files",
        ).to_observation(asset_id="asset-xyz")

        findings = correlator.correlate([obs])
        assert len(findings) == 1
        finding = findings[0]

        assert isinstance(finding, Finding)
        assert finding.asset_id == "asset-xyz"
        assert finding.severity == Severity.LOW
        assert finding.finding_type == "information_disclosure"
        assert "Directory Listing" in finding.title
        assert len(finding.observation_ids) == 1
        assert finding.observation_ids[0] == obs.id
        assert 0.0 <= finding.confidence <= 1.0

    def test_correlate_detailed_summary(self) -> None:
        correlator = FindingCorrelator()
        obs = VulnerabilityObservation(
            tool="sqlmap",
            target="http://target.local",
            endpoint="/api/v1/user",
            title="SQL injection detected",
            description="SQL injection detected on uid",
            parameter="uid",
            injection_type="boolean-based blind",
        ).to_observation(asset_id="asset-xyz")

        result = correlator.correlate_detailed([obs])
        assert isinstance(result, CorrelationResult)
        assert result.raw_observation_count == 1
        assert result.deduplicated_clusters_count == 1
        assert len(result.findings) == 1
        assert result.high_confidence_findings_count == 1

    def test_evidence_id_enrichment(self) -> None:
        correlator = FindingCorrelator()

        obs = VulnerabilityObservation(
            tool="sqlmap",
            target="http://target.local",
            endpoint="/api/v1/user",
            title="SQL injection",
            description="SQL injection vulnerability",
            parameter="uid",
        ).to_observation(asset_id="asset-xyz", task_id="task-123")

        ev = Evidence(
            tool="sqlmap",
            target="http://target.local",
            command=("sqlmap", "-u", "http://target.local/api/v1/user?uid=1"),
            task_id="task-123",
            exit_code=0,
            stdout="Parameter: uid (GET) is vulnerable",
        )

        findings = correlator.correlate([obs], evidence=[ev])
        assert len(findings) == 1
        finding = findings[0]

        assert ev.id in finding.evidence_ids
        assert obs.id in finding.observation_ids

    def test_severity_synthesis_picks_highest(self) -> None:
        correlator = FindingCorrelator()

        obs_low = VulnerabilityObservation(
            tool="nikto",
            target="http://test.local",
            endpoint="/vuln.php",
            title="SQL injection hint",
            description="Possible SQLi",
            parameter="id",
            severity="low",
        ).to_observation(asset_id="a1")

        obs_high = VulnerabilityObservation(
            tool="sqlmap",
            target="http://test.local",
            endpoint="/vuln.php",
            title="SQL injection confirmed",
            description="Confirmed SQLi",
            parameter="id",
            severity="high",
        ).to_observation(asset_id="a1")

        findings = correlator.correlate([obs_low, obs_high])
        assert len(findings) == 1
        # Upgraded to HIGH
        assert findings[0].severity == Severity.HIGH


# ==============================================================================
# 5. Discovery Engine Tests
# ==============================================================================

class TestDiscoveryEngine:
    """Test discovery engine aggregating endpoints, ports, and subdomains."""

    def test_discovery_engine_aggregates_endpoints(self) -> None:
        engine = DiscoveryEngine()

        obs1 = Observation(type="endpoint_discovery", asset_id="a1", source="gobuster", data={"path": "/admin", "status_code": 200, "target": "http://example.com"})
        obs2 = Observation(type="endpoint_discovery", asset_id="a1", source="ffuf", data={"path": "/admin", "status_code": 200, "target": "http://example.com"})

        inventory = engine.process([obs1, obs2])
        assert len(inventory.endpoints) == 1
        norm_url = "http://example.com/admin"
        assert norm_url in inventory.endpoints
        endpoint = inventory.endpoints[norm_url]
        assert endpoint.sources == ("ffuf", "gobuster")
        assert len(endpoint.observation_ids) == 2

    def test_discovery_engine_aggregates_services_and_subdomains(self) -> None:
        engine = DiscoveryEngine()

        obs_port = Observation(type="open_port", asset_id="a1", source="nmap", data={"port": 443, "service": "https", "protocol": "tcp"})
        obs_sub = Observation(type="subdomain_discovery", asset_id="a1", source="dig", data={"subdomain": "api.example.com"})

        inventory = engine.process([obs_port, obs_sub])
        assert 443 in inventory.services
        assert inventory.services[443].service == "https"
        assert "api.example.com" in inventory.subdomains


# ==============================================================================
# 6. Phase 9 Acceptance Criteria Test
# ==============================================================================

class TestPhase9AcceptanceCriteria:
    """Explicit verification of Phase 9 Acceptance Criteria:

    'Multiple observations can produce a single high-confidence finding.'
    """

    def test_multiple_observations_produce_single_high_confidence_finding(self) -> None:
        """Verify that multiple observations from different tools for the same issue

        cluster into exactly one Finding, linking both observation IDs, and
        elevating the confidence score to >= 0.90 (high confidence).
        """
        correlator = FindingCorrelator()

        # Observation 1: Nikto heuristic discovery
        nikto_obs_data = VulnerabilityObservation(
            tool="nikto",
            target="https://target.corp.local",
            endpoint="/login.php?user=admin",
            title="Possible SQL injection in user parameter",
            description="Server returned database error signature",
            severity="medium",
            parameter="user",
        )
        obs_nikto = nikto_obs_data.to_observation(asset_id="asset-web-01", task_id="task-nikto-01")

        # Observation 2: Sqlmap active confirmation
        sqlmap_obs_data = VulnerabilityObservation(
            tool="sqlmap",
            target="https://target.corp.local",
            endpoint="/login.php",
            title="Parameter user is vulnerable to boolean-based blind SQL injection",
            description="Confirmed DBMS: MySQL 8.0 with boolean-based blind technique",
            severity="high",
            parameter="user",
            injection_type="boolean-based blind",
            execution_mode=ExecutionMode.ACTIVE,
        )
        obs_sqlmap = sqlmap_obs_data.to_observation(asset_id="asset-web-01", task_id="task-sqlmap-01")

        # Supporting evidence
        ev_nikto = Evidence(
            tool="nikto",
            target="https://target.corp.local",
            command=("nikto", "-host", "https://target.corp.local"),
            task_id="task-nikto-01",
            exit_code=0,
            stdout="+ /login.php?user=admin: Possible SQL injection",
        )
        ev_sqlmap = Evidence(
            tool="sqlmap",
            target="https://target.corp.local",
            command=("sqlmap", "-u", "https://target.corp.local/login.php?user=admin", "--batch"),
            task_id="task-sqlmap-01",
            exit_code=0,
            stdout="Parameter: user (GET) is vulnerable. Type: boolean-based blind",
        )

        # Execute correlation
        findings = correlator.correlate(
            observations=[obs_nikto, obs_sqlmap],
            evidence=[ev_nikto, ev_sqlmap],
        )

        # 1. Exactly ONE finding produced (Acceptance Criteria: 'single finding')
        assert len(findings) == 1
        finding = findings[0]

        # 2. Confidence is elevated to high confidence (Acceptance Criteria: 'high-confidence')
        assert finding.confidence >= 0.90
        # 3. Both observations are linked
        assert set(finding.observation_ids) == {obs_nikto.id, obs_sqlmap.id}
        # 4. Supporting evidence is linked
        assert set(finding.evidence_ids) == {ev_nikto.id, ev_sqlmap.id}
        # 5. Asset ID preserved
        assert finding.asset_id == "asset-web-01"
        # 6. Severity is appropriately HIGH
        assert finding.severity == Severity.HIGH
        # 7. Finding type is classified
        assert finding.finding_type == VulnerabilityCategory.INJECTION.value
        # 8. Title is clear and normalized
        assert "SQL Injection on /login.php (Parameter: user)" == finding.title
        # 9. Description contains OWASP, CWE, and multi-tool rationale
        assert "A03:2021-Injection" in finding.description
        assert "CWE-89" in finding.description
        assert "Multi-tool corroboration" in finding.description
        assert "Remediation Guidance" in finding.description
