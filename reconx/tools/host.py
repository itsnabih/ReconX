"""Adapter for the `host` DNS lookup utility."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.dns import DNSResult, RecordType
from reconx.parsers.dns import HostParser
from reconx.tools.base import DNSToolAdapter


class HostAdapter(DNSToolAdapter):
    """Adapter for the `host` DNS lookup utility."""

    name = "host"
    executable = "host"

    def __init__(self, runner: CommandRunner | None = None, parser: HostParser | None = None) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else HostParser()

    async def version(self) -> str:
        """Query and return host version information."""
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
        record_type: str | RecordType = RecordType.A,
        nameserver: str | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for host."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target domain or IP cannot be empty")

        rtype = record_type.value if hasattr(record_type, "value") else str(record_type).strip().upper()
        cmd = [self.executable, "-t", rtype, clean_target]
        if nameserver:
            cmd.append(nameserver.strip().lstrip("@"))
        return cmd

    def parse_result(self, result: CommandResult | str, target: str = "") -> DNSResult:
        """Parse raw output or CommandResult into normalized DNSResult."""
        if isinstance(result, CommandResult):
            raw = result.stdout
            tgt = target
            if not tgt and result.arguments:
                for arg in reversed(result.arguments):
                    if not arg.startswith("-") and arg.upper() not in RecordType.__members__:
                        tgt = arg
                        break

            parsed = self.parser.parse(raw, target=tgt)
            errs = list(parsed.errors)
            if result.timed_out and "Command timed out" not in errs:
                errs.append("Command timed out")
            if result.cancelled and "Command cancelled" not in errs:
                errs.append("Command cancelled")
            if not result.success and result.stderr.strip() and result.stderr.strip() not in errs:
                errs.append(result.stderr.strip())

            return DNSResult(
                tool=self.name,
                target=tgt,
                records=parsed.records,
                whois=None,
                errors=tuple(errs),
                raw_output=raw or result.stderr,
            )

        return self.parser.parse(result, target=target)
