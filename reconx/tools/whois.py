"""Adapter for the `whois` domain and IP registration lookup utility."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.dns import DNSResult
from reconx.parsers.dns import WhoisParser
from reconx.tools.base import ToolAdapter


class WhoisAdapter(ToolAdapter):
    """Adapter for the system `whois` lookup utility."""

    name = "whois"
    executable = "whois"
    resource_class = "dns"

    def __init__(self, runner: CommandRunner | None = None, parser: WhoisParser | None = None) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else WhoisParser()

    async def version(self) -> str:
        """Query and return whois version information."""
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
        host: str | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for whois."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target domain or IP cannot be empty")

        cmd = [self.executable]
        if host:
            cmd.extend(["-h", host.strip()])
        cmd.append(clean_target)
        return cmd

    def parse_result(self, result: CommandResult | str, target: str = "") -> DNSResult:
        """Parse raw output or CommandResult into normalized DNSResult."""
        if isinstance(result, CommandResult):
            raw = result.stdout
            tgt = target
            if not tgt and result.arguments:
                tgt = result.arguments[-1]

            parsed = self.parser.parse(raw, query=tgt)
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
                records=(),
                whois=parsed.whois,
                errors=tuple(errs),
                raw_output=raw or result.stderr,
            )

        return self.parser.parse(result, query=target)
