"""Unit tests for web enumeration adapters and multi-tool endpoint deduplication."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import TaskState
from reconx.models.endpoint import (
    DiscoveredEndpoint,
    EndpointCollection,
    normalize_endpoint_key,
)
from reconx.scope.validator import ScopeValidator
from reconx.tools.dirb import DirbAdapter
from reconx.tools.ffuf import FFUFAdapter
from reconx.tools.gobuster import GobusterAdapter
from reconx.tools.registry import get_default_registry


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


class TestEndpointModelAndCollection:
    """Tests for DiscoveredEndpoint and EndpointCollection behavior."""

    def test_normalize_endpoint_key(self) -> None:
        # Standard ports stripped
        assert normalize_endpoint_key("http://example.com:80/admin/") == "http://example.com/admin"
        assert normalize_endpoint_key("https://example.com:443/admin/") == "https://example.com/admin"
        assert normalize_endpoint_key("http://example.com/admin") == "http://example.com/admin"

        # Non-standard ports preserved
        assert normalize_endpoint_key("http://example.com:8080/api/") == "http://example.com:8080/api"

        # Root path preserved
        assert normalize_endpoint_key("http://example.com/") == "http://example.com/"
        assert normalize_endpoint_key("http://example.com") == "http://example.com/"

        # Path only normalization
        assert normalize_endpoint_key("", "/login/") == "/login"
        assert normalize_endpoint_key("", "dashboard") == "/dashboard"
        assert normalize_endpoint_key("", "/") == "/"

    def test_normalize_endpoint_key_query_and_fragments(self) -> None:
        # Query parameters are sorted canonicalized
        assert (
            normalize_endpoint_key("http://example.com/api?b=2&a=1")
            == "http://example.com/api?a=1&b=2"
        )
        assert (
            normalize_endpoint_key("http://example.com/api?a=1&b=2")
            == "http://example.com/api?a=1&b=2"
        )

        # URL fragments are dropped
        assert normalize_endpoint_key("http://example.com/admin#tab1") == "http://example.com/admin"
        assert (
            normalize_endpoint_key("http://example.com/search?q=test#res")
            == "http://example.com/search?q=test"
        )

        # Path-only with query parameters
        assert normalize_endpoint_key("", "/api?z=9&y=8") == "/api?y=8&z=9"

    def test_discovered_endpoint_validation(self) -> None:
        # Missing both url and path raises ValueError
        with pytest.raises(ValueError, match="Endpoint requires either url or path"):
            DiscoveredEndpoint(url="", path="", status_code=200)

        # Negative status code raises ValueError
        with pytest.raises(ValueError, match="status_code must be non-negative"):
            DiscoveredEndpoint(url="http://example.com", path="/", status_code=-1)

        # Negative content length raises ValueError
        with pytest.raises(ValueError, match="content_length must be non-negative"):
            DiscoveredEndpoint(
                url="http://example.com", path="/", status_code=200, content_length=-10
            )

    def test_discovered_endpoint_immutability(self) -> None:
        ep = DiscoveredEndpoint(
            url="http://example.com/admin",
            path="/admin",
            status_code=200,
            sources=("gobuster", "gobuster"),
        )
        # Deduplicated and converted to tuple
        assert ep.sources == ("gobuster",)

        # Frozen dataclass check
        with pytest.raises(AttributeError):
            ep.status_code = 404  # type: ignore[misc]

    def test_endpoint_collection_deduplication_and_merging(self) -> None:
        collection = EndpointCollection()

        # 1. Finding from Gobuster
        ep_gobuster = DiscoveredEndpoint(
            url="http://example.com/admin",
            path="/admin",
            status_code=301,
            content_length=178,
            sources=("gobuster",),
        )

        # 2. Finding from FFUF (trailing slash in URL, with word/line counts)
        ep_ffuf = DiscoveredEndpoint(
            url="http://example.com/admin/",
            path="/admin/",
            status_code=301,
            content_length=178,
            word_count=12,
            line_count=4,
            sources=("ffuf",),
        )

        # 3. Finding from Dirb (with redirect location)
        ep_dirb = DiscoveredEndpoint(
            url="http://example.com/admin",
            path="/admin",
            status_code=301,
            redirect_location="http://example.com/admin/",
            sources=("dirb",),
        )

        collection.add(ep_gobuster)
        collection.add(ep_ffuf)
        collection.add(ep_dirb)

        # All 3 normalized to the same endpoint
        assert len(collection) == 1
        merged = collection.endpoints[0]

        # Multi-source attribution preserved and sorted
        assert merged.sources == ("dirb", "ffuf", "gobuster")
        assert merged.content_length == 178
        assert merged.word_count == 12
        assert merged.line_count == 4
        assert merged.redirect_location == "http://example.com/admin/"
        assert "http://example.com/admin" in collection
        assert "/admin" in collection

    def test_endpoint_collection_query_methods(self) -> None:
        collection = EndpointCollection()
        ep1 = DiscoveredEndpoint(
            url="http://example.com/admin",
            path="/admin",
            status_code=200,
            sources=("gobuster",),
        )
        ep2 = DiscoveredEndpoint(
            url="http://example.com/login",
            path="/login",
            status_code=301,
            sources=("ffuf",),
        )
        collection.add_all([ep1, ep2])

        assert len(collection.get_by_source("gobuster")) == 1
        assert len(collection.get_by_source("ffuf")) == 1
        assert len(collection.get_by_source("dirb")) == 0

        assert len(collection.get_by_status(200)) == 1
        assert len(collection.get_by_status(301)) == 1
        assert len(collection.get_by_status(404)) == 0

        collection.clear()
        assert len(collection) == 0

    def test_phase7_acceptance_criteria(self) -> None:
        """Phase 7 Acceptance Criteria Verification:

        'The same endpoint found by multiple tools becomes one normalized
        observation with multiple sources.'
        """
        collection = EndpointCollection()

        ep1 = DiscoveredEndpoint(
            url="https://target.com/secret",
            path="/secret",
            status_code=403,
            content_length=512,
            sources=("gobuster",),
        )
        ep2 = DiscoveredEndpoint(
            url="https://target.com/secret/",
            path="/secret/",
            status_code=403,
            content_length=512,
            word_count=30,
            line_count=10,
            sources=("ffuf",),
        )
        ep3 = DiscoveredEndpoint(
            url="https://target.com:443/secret",
            path="/secret",
            status_code=403,
            content_length=512,
            sources=("dirb",),
        )

        collection.add_all([ep1, ep2, ep3])

        observations = collection.to_observations(asset_id="asset_web_1", task_id="task_enum")

        # Exactly ONE normalized observation
        assert len(observations) == 1
        obs = observations[0]

        assert obs.type == "discovered_endpoint"
        assert obs.asset_id == "asset_web_1"
        assert obs.task_id == "task_enum"

        # Observation source lists all discovering tools
        assert obs.source == "dirb,ffuf,gobuster"

        # Observation data contains full multi-tool source attribution and normalized metadata
        assert obs.data["sources"] == ["dirb", "ffuf", "gobuster"]
        assert obs.data["path"] == "/secret"
        assert obs.data["status_code"] == 403
        assert obs.data["content_length"] == 512
        assert obs.data["word_count"] == 30
        assert obs.data["line_count"] == 10


class TestGobusterAdapter:
    """Tests for GobusterAdapter command building and task integration."""

    def test_adapter_metadata(self) -> None:
        adapter = GobusterAdapter()
        assert adapter.name == "gobuster"
        assert adapter.executable == "gobuster"
        assert adapter.resource_class == "discovery"

    def test_build_command_defaults(self) -> None:
        adapter = GobusterAdapter()
        cmd = adapter.build_command("http://example.com")
        assert cmd[0] == "gobuster"
        assert cmd[1] == "dir"
        assert cmd[2] == "-u"
        assert cmd[3] == "http://example.com"
        assert "-w" in cmd
        assert "-q" in cmd
        assert "--no-error" in cmd
        assert "-t" in cmd
        assert "-k" in cmd

    def test_build_command_options(self) -> None:
        adapter = GobusterAdapter()
        cmd = adapter.build_command(
            target="http://example.com",
            wordlist="/custom/wordlist.txt",
            threads=20,
            timeout_seconds=15,
            follow_redirects=True,
            extensions=["php", ".html"],
            verify_ssl=True,
            extra_args=["--wildcard"],
        )
        assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "http://example.com"
        assert "-w" in cmd and cmd[cmd.index("-w") + 1] == "/custom/wordlist.txt"
        assert "-t" in cmd and cmd[cmd.index("-t") + 1] == "20"
        assert "--timeout" in cmd and cmd[cmd.index("--timeout") + 1] == "15s"
        assert "-r" in cmd
        assert "-x" in cmd and cmd[cmd.index("-x") + 1] == "php,html"
        assert "-k" not in cmd  # verify_ssl=True skips -k
        assert "--wildcard" in cmd

    def test_build_command_validation(self) -> None:
        adapter = GobusterAdapter()
        with pytest.raises(ValueError, match="Target URL cannot be empty"):
            adapter.build_command("")
        with pytest.raises(ValueError, match="Wordlist path cannot be empty"):
            adapter.build_command("http://example.com", wordlist="")

    def test_build_command_wordlist_preflight_check(self) -> None:
        adapter = GobusterAdapter()
        # Non-existent wordlist with check_wordlist_exists=True raises FileNotFoundError
        with pytest.raises(FileNotFoundError, match="Wordlist file not found"):
            adapter.build_command(
                "http://example.com",
                wordlist="/nonexistent/path/to/words.txt",
                check_wordlist_exists=True,
            )

        # Default wordlist exists on this system
        assert adapter.check_wordlist_available() is True
        assert adapter.check_wordlist_available("/nonexistent/words.txt") is False

    @pytest.mark.anyio
    async def test_version_query(self) -> None:
        runner = CommandRunner()
        mock_result = _make_mock_result(
            cmd=["gobuster", "--version"],
            stdout="gobuster version 3.8.2\nBuild info: go1.24",
        )

        async def _mock_run(*args, **kwargs) -> CommandResult:
            return mock_result

        runner.run = _mock_run  # type: ignore[method-assign]
        adapter = GobusterAdapter(runner=runner)
        adapter.check_available = lambda: True  # type: ignore[method-assign]

        ver = await adapter.version()
        assert ver == "3.8.2"

    def test_create_task(self) -> None:
        adapter = GobusterAdapter()
        task = adapter.create_task(
            task_id="gobuster_1",
            target="http://example.com",
            priority=5,
        )
        assert task.id == "gobuster_1"
        assert task.type == "tool_gobuster"
        assert task.resource_class == "discovery"
        assert task.priority == 5


class TestFFUFAdapter:
    """Tests for FFUFAdapter command building and task integration."""

    def test_adapter_metadata(self) -> None:
        adapter = FFUFAdapter()
        assert adapter.name == "ffuf"
        assert adapter.executable == "ffuf"
        assert adapter.resource_class == "discovery"

    def test_build_command_defaults(self) -> None:
        adapter = FFUFAdapter()
        cmd = adapter.build_command("http://example.com")
        assert cmd[0] == "ffuf"
        assert "-u" in cmd
        assert cmd[cmd.index("-u") + 1] == "http://example.com/FUZZ"
        assert "-w" in cmd
        assert "-json" in cmd
        assert "-s" in cmd
        assert "-noninteractive" in cmd

    def test_build_command_with_existing_fuzz_and_options(self) -> None:
        adapter = FFUFAdapter()
        cmd = adapter.build_command(
            target="http://example.com/api/FUZZ",
            wordlist="/wordlist.txt",
            threads=30,
            timeout_seconds=5,
            follow_redirects=True,
            extensions=["json", ".xml"],
            extra_args=["-ac"],
        )
        assert cmd[cmd.index("-u") + 1] == "http://example.com/api/FUZZ"
        assert cmd[cmd.index("-w") + 1] == "/wordlist.txt"
        assert cmd[cmd.index("-t") + 1] == "30"
        assert "-r" in cmd
        assert "-e" in cmd and cmd[cmd.index("-e") + 1] == ".json,.xml"
        assert "-ac" in cmd

    def test_build_command_validation(self) -> None:
        adapter = FFUFAdapter()
        with pytest.raises(ValueError, match="Target URL cannot be empty"):
            adapter.build_command("")
        with pytest.raises(ValueError, match="Wordlist path cannot be empty"):
            adapter.build_command("http://example.com", wordlist="")

    def test_build_command_wordlist_preflight_check(self) -> None:
        adapter = FFUFAdapter()
        with pytest.raises(FileNotFoundError, match="Wordlist file not found"):
            adapter.build_command(
                "http://example.com",
                wordlist="/nonexistent/path.txt",
                check_wordlist_exists=True,
            )
        assert adapter.check_wordlist_available() is True

    @pytest.mark.anyio
    async def test_version_query(self) -> None:
        runner = CommandRunner()
        mock_result = _make_mock_result(
            cmd=["ffuf", "-V"],
            stdout="ffuf version: 2.1.0-dev\n",
        )

        async def _mock_run(*args, **kwargs) -> CommandResult:
            return mock_result

        runner.run = _mock_run  # type: ignore[method-assign]
        adapter = FFUFAdapter(runner=runner)
        adapter.check_available = lambda: True  # type: ignore[method-assign]

        ver = await adapter.version()
        assert ver == "2.1.0-dev"

    def test_create_task(self) -> None:
        adapter = FFUFAdapter()
        task = adapter.create_task(
            task_id="ffuf_1",
            target="http://example.com",
        )
        assert task.id == "ffuf_1"
        assert task.type == "tool_ffuf"
        assert task.resource_class == "discovery"


class TestDirbAdapter:
    """Tests for DirbAdapter command building and task integration."""

    def test_adapter_metadata(self) -> None:
        adapter = DirbAdapter()
        assert adapter.name == "dirb"
        assert adapter.executable == "dirb"
        assert adapter.resource_class == "discovery"

    def test_build_command_defaults(self) -> None:
        adapter = DirbAdapter()
        cmd = adapter.build_command("http://example.com")
        assert cmd[0] == "dirb"
        assert cmd[1] == "http://example.com"
        assert "-r" in cmd
        assert "-S" in cmd
        assert "-l" in cmd

    def test_build_command_options(self) -> None:
        adapter = DirbAdapter()
        cmd = adapter.build_command(
            target="http://example.com",
            wordlist="/custom.txt",
            delay_ms=250,
            case_insensitive=True,
            extra_args=["-N", "404"],
        )
        assert cmd[1] == "http://example.com"
        assert cmd[2] == "/custom.txt"
        assert "-z" in cmd and cmd[cmd.index("-z") + 1] == "250"
        assert "-i" in cmd
        assert "-N" in cmd

    def test_build_command_validation(self) -> None:
        adapter = DirbAdapter()
        with pytest.raises(ValueError, match="Target URL cannot be empty"):
            adapter.build_command("")
        with pytest.raises(ValueError, match="Wordlist path cannot be empty"):
            adapter.build_command("http://example.com", wordlist="")

    def test_build_command_wordlist_preflight_check(self) -> None:
        adapter = DirbAdapter()
        with pytest.raises(FileNotFoundError, match="Wordlist file not found"):
            adapter.build_command(
                "http://example.com",
                wordlist="/nonexistent/path.txt",
                check_wordlist_exists=True,
            )
        assert adapter.check_wordlist_available() is True

    @pytest.mark.anyio
    async def test_version_query(self) -> None:
        runner = CommandRunner()
        mock_result = _make_mock_result(
            cmd=["dirb"],
            stdout="-----------------\nDIRB v2.22    \nBy The Dark Raver\n-----------------",
        )

        async def _mock_run(*args, **kwargs) -> CommandResult:
            return mock_result

        runner.run = _mock_run  # type: ignore[method-assign]
        adapter = DirbAdapter(runner=runner)
        adapter.check_available = lambda: True  # type: ignore[method-assign]

        ver = await adapter.version()
        assert ver == "2.22"

    def test_create_task(self) -> None:
        adapter = DirbAdapter()
        task = adapter.create_task(
            task_id="dirb_1",
            target="http://example.com",
        )
        assert task.id == "dirb_1"
        assert task.type == "tool_dirb"
        assert task.resource_class == "discovery"


class TestDefaultRegistryWithDiscoveryTools:
    """Verify tool registry includes gobuster, ffuf, and dirb."""

    def test_registry_contains_discovery_tools(self) -> None:
        reg = get_default_registry()
        assert len(reg) >= 12
        assert "gobuster" in reg
        assert "ffuf" in reg
        assert "dirb" in reg
        expected = {"curl", "dig", "dirb", "ffuf", "gobuster", "host", "nmap", "nslookup", "openssl", "ping", "wget", "whois"}
        assert expected.issubset(set(reg.list_tools()))

    def test_check_all_includes_discovery_tools(self) -> None:
        reg = get_default_registry()
        availability = reg.check_all()
        assert "gobuster" in availability
        assert "ffuf" in availability
        assert "dirb" in availability


class TestSchedulerDiscoveryIntegration:
    """Verify scheduler executes discovery tasks under resource_class='discovery'."""

    @pytest.mark.anyio
    async def test_scheduler_runs_discovery_tasks(self) -> None:
        runner = CommandRunner()
        mock_out = "/admin (Status: 200) [Size: 100]"

        async def _mock_run(command, *args, **kwargs) -> CommandResult:
            return _make_mock_result(command, stdout=mock_out)

        runner.run = _mock_run  # type: ignore[method-assign]

        gobuster = GobusterAdapter(runner=runner)
        ffuf = FFUFAdapter(runner=runner)
        dirb = DirbAdapter(runner=runner)

        t1 = gobuster.create_task("task_gobuster", "http://example.com")
        t2 = ffuf.create_task("task_ffuf", "http://example.com")
        t3 = dirb.create_task("task_dirb", "http://example.com")

        config = SchedulerConfig(
            global_concurrency=5,
            resource_concurrency={"discovery": 2},
        )
        scheduler = Scheduler(
            runner=runner,
            config=config,
            scope=ScopeValidator(allowed_domains=["example.com"]),
        )
        scheduler.add_task(t1)
        scheduler.add_task(t2)
        scheduler.add_task(t3)

        summary = await scheduler.run()
        assert summary.total_tasks == 3
        assert summary.completed == 3
        assert summary.failed == 0
        assert summary.results["task_gobuster"].state == TaskState.COMPLETED
        assert summary.results["task_ffuf"].state == TaskState.COMPLETED
        assert summary.results["task_dirb"].state == TaskState.COMPLETED
