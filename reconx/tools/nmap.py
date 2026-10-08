"""Adapter for the `nmap` network port scanner and service detection utility."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.core.task import Task
from reconx.models.network import NmapResult
from reconx.parsers.nmap import NmapParser
from reconx.tools.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    """Adapter for the Nmap port scanner and service detection utility."""

    name = "nmap"
    executable = "nmap"
    resource_class = "network"

    def __init__(self, runner: CommandRunner | None = None, parser: NmapParser | None = None) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else NmapParser()

    async def version(self) -> str:
        """Query and return Nmap version information."""
        if not self.check_available():
            return "not_installed"
        res = await self.runner.run([self.executable, "--version"], timeout=5.0)
        output = res.stdout.strip() or res.stderr.strip()
        if output:
            return output.splitlines()[0].strip()
        return "unknown"

    def build_command(
        self,
        target: str,
        ports: str | None = None,
        service_detection: bool = True,
        ping_probe: bool = False,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for nmap port scanning."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target host or network cannot be empty")

        cmd = [self.executable, "-sT", "-oX", "-"]
        if service_detection:
            cmd.extend(["-sV", "--version-light"])
        if not ping_probe:
            cmd.append("-Pn")
        cmd.append("-n")

        if ports:
            clean_ports = ports.strip()
            if clean_ports:
                cmd.extend(["-p", clean_ports])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(clean_target)
        return cmd

    def parse_result(self, result: CommandResult | str, target: str = "") -> NmapResult:
        """Parse raw output or CommandResult into normalized NmapResult."""
        if isinstance(result, CommandResult):
            raw = result.stdout
            tgt = target
            if not tgt and result.arguments:
                tgt = result.arguments[-1]

            parsed = self.parser.parse(raw, target=tgt)
            errs = list(parsed.errors)
            if result.timed_out and "Command timed out" not in errs:
                errs.append("Command timed out")
            if result.cancelled and "Command cancelled" not in errs:
                errs.append("Command cancelled")
            if not result.success and result.stderr.strip() and result.stderr.strip() not in errs:
                errs.append(result.stderr.strip())

            return NmapResult(
                target=tgt,
                hosts=parsed.hosts,
                errors=tuple(errs),
                raw_output=raw or result.stderr,
                scan_args=parsed.scan_args,
            )

        return self.parser.parse(result, target=target)

    def generate_downstream_http_tasks(
        self,
        result: NmapResult,
        parent_task_id: str | None = None,
        priority: int = 10,
    ) -> list[Task]:
        """Generate downstream HTTP discovery tasks ONLY when appropriate HTTP/HTTPS services are detected.

        Adheres strictly to the Phase 5 acceptance criteria:
        'Nmap output can generate downstream HTTP tasks only when appropriate services are detected.'
        """
        http_targets = result.get_http_targets()
        downstream_tasks: list[Task] = []

        for item in http_targets:
            host_val = item["host"]
            port_val = item["port"]
            target_url = item["url"]

            # Task ID incorporates host and port
            task_id = f"http_probe_{host_val}_{port_val}"
            dependencies = {parent_task_id} if parent_task_id else set()

            task = Task(
                id=task_id,
                type="http_probe",
                target=target_url,
                dependencies=dependencies,
                priority=priority,
                resource_class="http",
            )
            downstream_tasks.append(task)

        return downstream_tasks


def generate_downstream_http_tasks(
    result: NmapResult,
    parent_task_id: str | None = None,
    priority: int = 10,
) -> list[Task]:
    """Module-level function to generate downstream HTTP tasks only when appropriate services are detected."""
    adapter = NmapAdapter()
    return adapter.generate_downstream_http_tasks(result, parent_task_id=parent_task_id, priority=priority)
