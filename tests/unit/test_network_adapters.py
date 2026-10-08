"""Unit tests for Network tool adapters (ping, openssl, nmap), registry, and scheduler integration."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from reconx.core.cancellation import CancellationToken
from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.scheduler import Scheduler, SchedulerConfig
from reconx.core.task import TaskState
from reconx.models.network import NmapResult, PingResult, TLSResult
from reconx.scope.validator import ScopeValidator
from reconx.tools import (
    NmapAdapter,
    OpenSSLAdapter,
    PingAdapter,
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


class TestPingAdapter:
    """Tests for PingAdapter."""

    def test_build_command(self) -> None:
        adapter = PingAdapter()
        cmd = adapter.build_command("example.com", count=4, timeout_seconds=3)
        assert cmd == ["ping", "-c", "4", "-W", "3", "example.com"]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = PingAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("   ")

    def test_build_command_zero_count_raises(self) -> None:
        adapter = PingAdapter()
        with pytest.raises(ValueError, match="greater than zero"):
            adapter.build_command("example.com", count=0)

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("ping", "-V"): _make_mock_result(["ping", "-V"], stdout="ping from iputils 20250605\n")}
        )
        adapter = PingAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "iputils" in ver

    def test_parse_result_from_command_result(self) -> None:
        adapter = PingAdapter()
        raw = "3 packets transmitted, 3 received, 0% packet loss\nrtt min/avg/max/mdev = 1.0/2.0/3.0/0.1 ms"
        cmd_res = _make_mock_result(["ping", "-c", "3", "-W", "2", "example.com"], stdout=raw, exit_code=0)
        res = adapter.parse_result(cmd_res)

        assert isinstance(res, PingResult)
        assert res.target == "example.com"
        assert res.is_alive is True
        assert res.packets_received == 3

    def test_create_task(self) -> None:
        adapter = PingAdapter()
        task = adapter.create_task(task_id="ping_task_1", target="example.com")
        assert task.resource_class == "network"
        assert task.type == "tool_ping"
        assert task.command == ["ping", "-c", "3", "-W", "2", "example.com"]


class TestOpenSSLAdapter:
    """Tests for OpenSSLAdapter."""

    def test_build_command(self) -> None:
        adapter = OpenSSLAdapter()
        cmd = adapter.build_command("example.com", port=443)
        assert cmd == [
            "openssl",
            "s_client",
            "-connect",
            "example.com:443",
            "-servername",
            "example.com",
        ]

        cmd_custom_sni = adapter.build_command("192.0.2.1", port=8443, servername="admin.example.com")
        assert cmd_custom_sni == [
            "openssl",
            "s_client",
            "-connect",
            "192.0.2.1:8443",
            "-servername",
            "admin.example.com",
        ]

    def test_build_command_invalid_port_raises(self) -> None:
        adapter = OpenSSLAdapter()
        with pytest.raises(ValueError, match="Invalid port"):
            adapter.build_command("example.com", port=70000)

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("openssl", "version"): _make_mock_result(["openssl", "version"], stdout="OpenSSL 3.6.3 9 Jun 2026\n")}
        )
        adapter = OpenSSLAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "OpenSSL 3.6.3" in ver

    def test_parse_result_from_command_result(self) -> None:
        adapter = OpenSSLAdapter()
        raw = "subject=CN = example.com\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384"
        cmd_res = _make_mock_result(
            ["openssl", "s_client", "-connect", "example.com:443", "-servername", "example.com"],
            stdout=raw,
            exit_code=0,
        )
        res = adapter.parse_result(cmd_res)

        assert isinstance(res, TLSResult)
        assert res.target == "example.com"
        assert res.port == 443
        assert res.protocol_version == "TLSv1.3"
        assert res.cipher == "TLS_AES_256_GCM_SHA384"


class TestNmapAdapter:
    """Tests for NmapAdapter."""

    def test_build_command(self) -> None:
        adapter = NmapAdapter()
        cmd = adapter.build_command("example.com", ports="80,443,8080")
        assert cmd == [
            "nmap",
            "-sT",
            "-oX",
            "-",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "-p",
            "80,443,8080",
            "example.com",
        ]

    def test_build_command_empty_target_raises(self) -> None:
        adapter = NmapAdapter()
        with pytest.raises(ValueError, match="cannot be empty"):
            adapter.build_command("")

    @pytest.mark.anyio
    async def test_version(self) -> None:
        mock_runner = MockRunner(
            {("nmap", "--version"): _make_mock_result(["nmap", "--version"], stdout="Nmap version 7.94 ( https://nmap.org )\n")}
        )
        adapter = NmapAdapter(runner=mock_runner)
        ver = await adapter.version()
        assert "Nmap version 7.94" in ver

    def test_create_task(self) -> None:
        adapter = NmapAdapter()
        task = adapter.create_task(
            task_id="nmap_task_1",
            target="example.com",
            ports="80,443",
        )
        assert task.resource_class == "network"
        assert task.type == "tool_nmap"
        assert "-p" in task.command


class TestNetworkToolRegistry:
    """Tests ToolRegistry with Phase 5 network adapters included."""

    def test_registry_contains_network_tools(self) -> None:
        reg = get_default_registry()
        assert len(reg) >= 7
        assert "ping" in reg
        assert "openssl" in reg
        assert "nmap" in reg
        assert {"dig", "host", "nmap", "nslookup", "openssl", "ping", "whois"}.issubset(set(reg.list_tools()))

    def test_check_all_includes_network_tools(self) -> None:
        reg = get_default_registry()
        availability = reg.check_all()
        assert "ping" in availability
        assert "openssl" in availability
        assert "nmap" in availability


class TestSchedulerNetworkIntegration:
    """Tests executing network adapter tasks in Scheduler with bounded concurrency."""

    @pytest.mark.anyio
    async def test_nmap_task_in_scheduler(self) -> None:
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="1728290000">
<host>
<status state="up"/>
<address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
</nmaprun>
"""
        cmd = ["nmap", "-sT", "-oX", "-", "-sV", "--version-light", "-Pn", "-n", "-p", "443", "example.com"]
        mock_runner = MockRunner({tuple(cmd): _make_mock_result(cmd, stdout=xml_output, exit_code=0)})

        adapter = NmapAdapter(runner=mock_runner)
        nmap_task = adapter.create_task(
            task_id="nmap_scan_01",
            target="example.com",
            ports="443",
        )

        scheduler = Scheduler(
            config=SchedulerConfig(global_concurrency=4, resource_concurrency={"network": 2, "http": 2}),
            runner=mock_runner,
            scope=ScopeValidator(allowed_domains=["example.com"]),
        )
        scheduler.add_task(nmap_task)
        summary = await scheduler.run()

        assert summary.completed == 1
        nmap_task_res = summary.results["nmap_scan_01"]
        assert nmap_task_res.state == TaskState.COMPLETED
        assert isinstance(nmap_task_res.output_data, NmapResult)

        # Generate downstream HTTP task from the completed scan
        downstream_tasks = adapter.generate_downstream_http_tasks(
            result=nmap_task_res.output_data,
            parent_task_id="nmap_scan_01",
        )
        assert len(downstream_tasks) == 1
        assert downstream_tasks[0].target == "https://93.184.216.34"
        assert downstream_tasks[0].dependencies == {"nmap_scan_01"}
