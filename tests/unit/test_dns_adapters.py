"""Unit tests for DNS tool adapters (dig, host, nslookup, whois), registry, and scheduler integration."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import TaskState
from reconx.models.dns import DNSResult, RecordType
from reconx.scope.validator import ScopeValidator
from reconx.tools import (
    DigAdapter,
    HostAdapter,
    NslookupAdapter,
    ToolRegistry,
    WhoisAdapter,
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
        duration=0.01,
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
        cancellation_token: CancellationToken | None = None,
    ) -> CommandResult:
        self.recorded_calls.append(list(command))
        cmd_key = tuple(command)
        if cmd_key in self.responses:
            return self.responses[cmd_key]
        return _make_mock_result(command, stdout="default output", exit_code=0)


class TestDigAdapter:
    """Tests for DigAdapter."""

    def test_build_command(self) -> None:
        adapter = DigAdapter()
        cmd = adapter.build_command("example.com", record_type="A")
        assert cmd == ["dig", "example.com", "A"]

        cmd_mx = adapter.build_command("example.com", record_type=RecordType.MX, nameserver="8.8.8.8")
        assert cmd == ["dig", "example.com", "A"]
        assert cmd_mx == ["dig", "@8.8.8.8", "example.com", "MX"]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = DigAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("   ")

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("dig", "-v"): _make_mock_result(["dig", "-v"], stdout="DiG 9.20.27-2-Debian\n")}
        )
        adapter = DigAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "DiG 9.20.27" in ver

    def test_parse_result_from_command_result(self) -> None:
        adapter = DigAdapter()
        raw = "example.com. 300 IN A 93.184.216.34"
        cmd_res = _make_mock_result(["dig", "example.com", "A"], stdout=raw, exit_code=0)
        dns_res = adapter.parse_result(cmd_res)

        assert isinstance(dns_res, DNSResult)
        assert dns_res.tool == "dig"
        assert dns_res.target == "example.com"
        assert len(dns_res.records) == 1
        assert dns_res.records[0].value == "93.184.216.34"


class TestHostAdapter:
    """Tests for HostAdapter."""

    def test_build_command(self) -> None:
        adapter = HostAdapter()
        cmd = adapter.build_command("example.com", record_type="AAAA")
        assert cmd == ["host", "-t", "AAAA", "example.com"]

        cmd_ns = adapter.build_command("example.com", record_type="NS", nameserver="1.1.1.1")
        assert cmd_ns == ["host", "-t", "NS", "example.com", "1.1.1.1"]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = HostAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("")

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("host", "-V"): _make_mock_result(["host", "-V"], stdout="host 9.20.27-2-Debian\n")}
        )
        adapter = HostAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "host 9.20.27" in ver

    def test_parse_result_from_command_result(self) -> None:
        adapter = HostAdapter()
        raw = "example.com has address 93.184.216.34"
        cmd_res = _make_mock_result(["host", "-t", "A", "example.com"], stdout=raw, exit_code=0)
        dns_res = adapter.parse_result(cmd_res)

        assert isinstance(dns_res, DNSResult)
        assert dns_res.tool == "host"
        assert dns_res.target == "example.com"
        assert len(dns_res.records) == 1
        assert dns_res.records[0].value == "93.184.216.34"


class TestNslookupAdapter:
    """Tests for NslookupAdapter."""

    def test_build_command(self) -> None:
        adapter = NslookupAdapter()
        cmd = adapter.build_command("example.com", record_type="TXT")
        assert cmd == ["nslookup", "-type=TXT", "example.com"]

        cmd_ns = adapter.build_command("example.com", record_type="MX", nameserver="8.8.4.4")
        assert cmd_ns == ["nslookup", "-type=MX", "example.com", "8.8.4.4"]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = NslookupAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("  ")

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("nslookup", "-version"): _make_mock_result(["nslookup", "-version"], stdout="nslookup 9.20.27-2-Debian\n")}
        )
        adapter = NslookupAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "nslookup 9.20.27" in ver


class TestWhoisAdapter:
    """Tests for WhoisAdapter."""

    def test_build_command(self) -> None:
        adapter = WhoisAdapter()
        cmd = adapter.build_command("example.com")
        assert cmd == ["whois", "example.com"]

        cmd_host = adapter.build_command("example.com", host="whois.verisign-grs.com")
        assert cmd_host == ["whois", "-h", "whois.verisign-grs.com", "example.com"]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = WhoisAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("")

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("whois", "--version"): _make_mock_result(["whois", "--version"], stdout="Version 5.6.6.\n")}
        )
        adapter = WhoisAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "Version 5.6.6" in ver


class TestToolRegistry:
    """Tests for ToolRegistry and default registry registration."""

    def test_default_registry_contents(self) -> None:
        reg = get_default_registry()
        assert len(reg) >= 4
        assert "dig" in reg
        assert "host" in reg
        assert "nslookup" in reg
        assert "whois" in reg
        assert {"dig", "host", "nslookup", "whois"}.issubset(set(reg.list_tools()))

    def test_require_raises_on_missing(self) -> None:
        reg = ToolRegistry()
        with pytest.raises(KeyError, match="not registered"):
            reg.require("nonexistent_tool")

    def test_check_all(self) -> None:
        reg = get_default_registry()
        availability = reg.check_all()
        assert isinstance(availability, dict)
        assert {"dig", "host", "nslookup", "whois"}.issubset(set(availability.keys()))
        assert all(isinstance(v, bool) for v in availability.values())


class TestAdapterTaskExecution:
    """Tests integration of adapter tasks with Scheduler and CommandRunner."""

    @pytest.mark.anyio
    async def test_dig_task_in_scheduler(self) -> None:
        raw_dig = "example.com. 300 IN A 93.184.216.34\n"
        mock_runner = MockRunner(
            {("dig", "example.com", "A"): _make_mock_result(["dig", "example.com", "A"], stdout=raw_dig)}
        )
        adapter = DigAdapter(runner=mock_runner)
        task = adapter.create_task(
            task_id="dns_dig_example",
            target="example.com",
            record_type="A",
        )

        assert task.resource_class == "dns"
        assert task.command == ["dig", "example.com", "A"]

        scope_validator = ScopeValidator(allowed_domains=["example.com"])
        scheduler = Scheduler(
            config=SchedulerConfig(global_concurrency=4, resource_concurrency={"dns": 2}),
            runner=mock_runner,
            scope=scope_validator,
        )
        scheduler.add_task(task)
        summary = await scheduler.run()

        assert summary.completed == 1
        assert summary.failed == 0
        task_res = summary.results["dns_dig_example"]
        assert task_res.state == TaskState.COMPLETED
        assert isinstance(task_res.output_data, DNSResult)
        assert len(task_res.output_data.records) == 1
        assert task_res.output_data.records[0].value == "93.184.216.34"

    @pytest.mark.anyio
    async def test_task_handles_execution_failure(self) -> None:
        mock_runner = MockRunner(
            {("dig", "example.com", "A"): _make_mock_result(
                ["dig", "example.com", "A"],
                stdout="",
                stderr="connection refused",
                exit_code=1,
            )}
        )
        adapter = DigAdapter(runner=mock_runner)
        task = adapter.create_task(
            task_id="dns_fail",
            target="example.com",
            record_type="A",
        )

        scheduler = Scheduler(
            runner=mock_runner,
            scope=ScopeValidator(allowed_domains=["example.com"]),
        )
        scheduler.add_task(task)
        summary = await scheduler.run()

        assert summary.failed == 1
        task_res = summary.results["dns_fail"]
        assert task_res.state == TaskState.FAILED
        assert task_res.error_message is not None
        assert "connection refused" in task_res.error_message
