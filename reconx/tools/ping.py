"""Adapter for the system `ping` ICMP network utility."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.network import PingResult
from reconx.parsers.ping import PingParser
from reconx.tools.base import ToolAdapter


class PingAdapter(ToolAdapter):
    """Adapter for the `ping` reachability utility."""

    name = "ping"
    executable = "ping"
    resource_class = "network"

    def __init__(self, runner: CommandRunner | None = None, parser: PingParser | None = None) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else PingParser()

    async def version(self) -> str:
        """Query and return ping version information."""
        if not self.check_available():
            return "not_installed"
        res = await self.runner.run([self.executable, "-V"], timeout=5.0)
        output = res.stdout.strip() or res.stderr.strip()
        if output:
            return output.splitlines()[0].strip()
        return "unknown"

    def build_command(
        self,
        target: str,
        count: int = 3,
        timeout_seconds: int = 2,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for ping."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target host or IP cannot be empty")
        if count <= 0:
            raise ValueError("Packet count must be greater than zero")

        return [
            self.executable,
            "-c",
            str(count),
            "-W",
            str(timeout_seconds),
            clean_target,
        ]

    def parse_result(self, result: CommandResult | str, target: str = "") -> PingResult:
        """Parse raw output or CommandResult into normalized PingResult."""
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

            return PingResult(
                target=tgt,
                is_alive=parsed.is_alive,
                packets_transmitted=parsed.packets_transmitted,
                packets_received=parsed.packets_received,
                packet_loss=parsed.packet_loss,
                rtt_min_ms=parsed.rtt_min_ms,
                rtt_avg_ms=parsed.rtt_avg_ms,
                rtt_max_ms=parsed.rtt_max_ms,
                rtt_mdev_ms=parsed.rtt_mdev_ms,
                errors=tuple(errs),
                raw_output=raw or result.stderr,
            )

        return self.parser.parse(result, target=target)
