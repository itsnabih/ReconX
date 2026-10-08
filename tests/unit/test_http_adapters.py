"""Unit tests for HTTP adapters (curl, wget), HTTPEngine, and Phase 6 Acceptance Criteria."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import pytest

from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import TaskState
from reconx.models.http import (
    BaselineResponse,
    EndpointDecision,
    HTTPResponse,
)
from reconx.scope.validator import ScopeValidator
from reconx.tools import (
    BaselineDetector,
    CurlAdapter,
    HTTPEngine,
    WgetAdapter,
    get_default_registry,
)


def _make_mock_result(
    cmd: list[str],
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    timed_out: bool = False,
    cancelled: bool = False,
) -> CommandResult:
    now = datetime.now(timezone.utc)
    return CommandResult(
        command=cmd,
        executable=cmd[0] if cmd else "",
        arguments=cmd[1:] if len(cmd) > 1 else [],
        started_at=now,
        finished_at=now,
        duration=0.05,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        cancelled=cancelled,
    )


class MockRunner(CommandRunner):
    """Predictable mock runner returning configured CommandResults."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        super().__init__()
        self.responses: dict[tuple[str, ...], CommandResult] = responses or {}
        self.recorded_calls: list[list[str]] = []

    async def run(
        self,
        command: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        cancellation_token: Any = None,
    ) -> CommandResult:
        self.recorded_calls.append(command)
        key = tuple(command)
        if key in self.responses:
            return self.responses[key]
        return _make_mock_result(command, stdout="", exit_code=0)


class TestCurlAdapter:
    """Tests for CurlAdapter."""

    def test_build_command_defaults(self) -> None:
        adapter = CurlAdapter()
        cmd = adapter.build_command("http://example.com/api")

        assert cmd[0] == "curl"
        assert "-s" in cmd
        assert "-S" in cmd
        assert "-i" in cmd
        assert "-L" in cmd
        assert "-k" in cmd
        assert "http://example.com/api" == cmd[-1]

    def test_build_command_options(self) -> None:
        adapter = CurlAdapter()
        cmd = adapter.build_command(
            "https://example.com",
            follow_redirects=False,
            timeout_seconds=5,
            method="HEAD",
            headers={"X-Custom": "TestVal"},
            verify_ssl=True,
        )

        assert "-L" not in cmd
        assert "-k" not in cmd
        assert "-X" in cmd
        assert "HEAD" in cmd
        assert "-H" in cmd
        assert "X-Custom: TestVal" in cmd
        assert "--max-time" in cmd
        assert "5" in cmd

    def test_build_command_empty_target_raises(self) -> None:
        adapter = CurlAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("   ")

    @pytest.mark.anyio
    async def test_version_query(self) -> None:
        mock_runner = MockRunner(
            {("curl", "--version"): _make_mock_result(["curl", "--version"], stdout="curl 8.21.0 (x86_64)")}
        )
        adapter = CurlAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "curl 8.21.0" in ver

    def test_create_task(self) -> None:
        adapter = CurlAdapter()
        task = adapter.create_task(
            task_id="curl_task_1",
            target="http://example.com",
        )
        assert task.resource_class == "http"
        assert task.type == "tool_curl"
        assert task.target == "http://example.com"


class TestWgetAdapter:
    """Tests for WgetAdapter."""

    def test_build_command(self) -> None:
        adapter = WgetAdapter()
        cmd = adapter.build_command("http://example.com/download", timeout_seconds=15)

        assert cmd[0] == "wget"
        assert "-q" in cmd
        assert "-S" in cmd
        assert "-O" in cmd
        assert "-" in cmd
        assert "--timeout=15" in cmd
        assert "http://example.com/download" == cmd[-1]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = WgetAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("")

    @pytest.mark.anyio
    async def test_version_query(self) -> None:
        mock_runner = MockRunner(
            {("wget", "--version"): _make_mock_result(["wget", "--version"], stdout="GNU Wget 1.25.0 built on linux")}
        )
        adapter = WgetAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "GNU Wget 1.25.0" in ver

    def test_create_task(self) -> None:
        adapter = WgetAdapter()
        task = adapter.create_task(
            task_id="wget_task_1",
            target="http://example.com/file",
        )
        assert task.resource_class == "http"
        assert task.type == "tool_wget"


class TestHTTPEngine:
    """Tests for HTTPEngine coordination and redirect scope validation."""

    def test_generate_baseline_url(self) -> None:
        engine = HTTPEngine()
        probe_url = engine.generate_baseline_url("https://example.com")
        assert probe_url == "https://example.com/_reconx_nonexistent_probe_404"

    def test_validate_redirects_in_scope(self) -> None:
        engine = HTTPEngine()
        scope = ScopeValidator(allowed_domains=["example.com"])
        res = HTTPResponse(
            url="http://example.com/login",
            status_code=200,
            redirect_chain=("https://example.com/login", "https://example.com/dashboard"),
            final_url="https://example.com/dashboard",
        )
        assert engine.validate_redirects(res, scope=scope) is True

    def test_validate_redirects_out_of_scope_rejected(self) -> None:
        engine = HTTPEngine()
        scope = ScopeValidator(allowed_domains=["example.com"])
        # Redirect chain escapes to evil.com
        res = HTTPResponse(
            url="http://example.com/oauth",
            status_code=200,
            redirect_chain=("https://evil.com/phishing",),
            final_url="https://evil.com/phishing",
        )
        assert engine.validate_redirects(res, scope=scope) is False


class TestSchedulerHTTPIntegration:
    """Tests executing HTTP tasks in Scheduler with bounded concurrency."""

    @pytest.mark.anyio
    async def test_curl_task_in_scheduler(self) -> None:
        raw_curl = """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 13

Hello World!
"""
        cmd = ["curl", "-s", "-S", "-i", "--max-time", "10", "-L", "--max-redirs", "5", "-k", "-H", "User-Agent: ReconX/0.1.0", "http://example.com"]
        mock_runner = MockRunner({tuple(cmd): _make_mock_result(cmd, stdout=raw_curl)})

        adapter = CurlAdapter(runner=mock_runner)
        task = adapter.create_task(
            task_id="curl_task_test",
            target="http://example.com",
        )

        scheduler = Scheduler(
            config=SchedulerConfig(global_concurrency=4, resource_concurrency={"http": 2}),
            runner=mock_runner,
            scope=ScopeValidator(allowed_domains=["example.com"]),
        )
        scheduler.add_task(task)
        summary = await scheduler.run()

        assert summary.completed == 1
        res = summary.results["curl_task_test"]
        assert res.state == TaskState.COMPLETED
        assert isinstance(res.output_data, HTTPResponse)
        assert res.output_data.status_code == 200
        assert "Hello World!" in res.output_data.body


class TestPhase6AcceptanceCriteria:
    """Strict verification of Phase 6 Acceptance Criteria from implementation.md:
    
    'The engine can accurately distinguish a real discovered endpoint from a wildcard 200 response.'
    """

    def test_distinguish_real_endpoint_from_wildcard_200(self) -> None:
        detector = BaselineDetector()

        # Wildcard 200 server baseline: probing a non-existent route returns 200 with SPA/catch-all template
        wildcard_spa_body = """<!DOCTYPE html>
<html>
<head><title>My App - Page Not Found</title></head>
<body>
  <div id="root">
    <h1>404 - We could not find that page</h1>
    <p>Please check the URL or go back to home.</p>
  </div>
</body>
</html>"""
        baseline_probe = HTTPResponse(
            url="https://app.example.com/_reconx_probe_404_xyz",
            status_code=200,
            body=wildcard_spa_body,
        )
        baseline = detector.build_baseline("https://app.example.com", baseline_probe)

        # Baseline should be marked as wildcard 200
        assert isinstance(baseline, BaselineResponse)
        assert baseline.is_wildcard_200 is True
        assert baseline.status_code == 200
        assert baseline.title == "My App - Page Not Found"

        # 1. Candidate A: Random fake endpoint returning the same wildcard template
        fake_candidate = HTTPResponse(
            url="https://app.example.com/fake_random_path_123",
            status_code=200,
            body=wildcard_spa_body,  # Identical body
        )
        decision_fake = detector.evaluate_endpoint(fake_candidate, baseline)
        assert isinstance(decision_fake, EndpointDecision)
        assert decision_fake.is_distinct is False
        assert decision_fake.reason == "exact_wildcard_hash_match"

        # 2. Candidate B: Real discovered API endpoint returning JSON data
        api_candidate = HTTPResponse(
            url="https://app.example.com/api/v1/users",
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"users": [{"id": 1, "name": "admin"}, {"id": 2, "name": "alice"}]}',
        )
        decision_api = detector.evaluate_endpoint(api_candidate, baseline)
        # Real endpoint must be accurately identified as DISTINCT
        assert decision_api.is_distinct is True
        assert decision_api.reason in ("distinct_title_and_length", "significant_length_divergence", "distinct_word_count_and_title")

        # 3. Candidate C: Real discovered Admin Dashboard returning distinct HTML
        admin_body = """<!DOCTYPE html>
<html>
<head><title>Administration Console</title></head>
<body>
  <div id="admin-panel">
    <h1>System Status: Healthy</h1>
    <nav><ul><li>Users</li><li>Settings</li><li>Logs</li><li>Audit</li></ul></nav>
    <section>System metrics and configuration settings for enterprise deployment.</section>
  </div>
</body>
</html>"""
        admin_candidate = HTTPResponse(
            url="https://app.example.com/admin/dashboard",
            status_code=200,
            body=admin_body,
        )
        decision_admin = detector.evaluate_endpoint(admin_candidate, baseline)
        assert decision_admin.is_distinct is True
        assert decision_admin.reason in ("distinct_title_and_length", "significant_length_divergence")

        # 4. Candidate D: Real protected endpoint returning HTTP 403 Forbidden
        forbidden_candidate = HTTPResponse(
            url="https://app.example.com/internal",
            status_code=403,
            body="Access Denied",
        )
        decision_forbidden = detector.evaluate_endpoint(forbidden_candidate, baseline)
        assert decision_forbidden.is_distinct is True
        assert decision_forbidden.reason == "non_200_status"

    def test_distinguish_endpoints_on_standard_404_server(self) -> None:
        detector = BaselineDetector()

        # Standard server: non-existent route returns 404
        standard_404_body = "<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"
        baseline_probe = HTTPResponse(
            url="https://example.com/_reconx_probe_404_xyz",
            status_code=404,
            body=standard_404_body,
        )
        baseline = detector.build_baseline("https://example.com", baseline_probe)

        assert baseline.is_wildcard_200 is False
        assert baseline.status_code == 404

        # Real endpoint returning 200 is distinct from 404
        real_candidate = HTTPResponse(
            url="https://example.com/about",
            status_code=200,
            body="<html><head><title>About Us</title></head><body>About Company</body></html>",
        )
        decision_real = detector.evaluate_endpoint(real_candidate, baseline)
        assert decision_real.is_distinct is True
        assert decision_real.reason == "status_code_divergence"

        # Another missing endpoint returning 404 is not distinct from baseline
        missing_candidate = HTTPResponse(
            url="https://example.com/doesnotexist",
            status_code=404,
            body=standard_404_body,
        )
        decision_missing = detector.evaluate_endpoint(missing_candidate, baseline)
        assert decision_missing.is_distinct is False
        assert decision_missing.reason == "baseline_status_match"


class TestDefaultRegistryWithHttpTools:
    """Verify tool registry includes curl and wget."""

    def test_registry_contains_http_tools(self) -> None:
        reg = get_default_registry()
        assert len(reg) >= 9
        assert "curl" in reg
        assert "wget" in reg
        expected = {"curl", "dig", "host", "nmap", "nslookup", "openssl", "ping", "wget", "whois"}
        assert expected.issubset(set(reg.list_tools()))

    def test_check_all_includes_http_tools(self) -> None:
        reg = get_default_registry()
        availability = reg.check_all()
        assert "curl" in availability
        assert "wget" in availability
