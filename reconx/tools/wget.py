"""Adapter for the `wget` network retrieval utility."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.http import HTTPResponse
from reconx.parsers.http import WgetParser
from reconx.tools.base import ToolAdapter


class WgetAdapter(ToolAdapter):
    """Adapter for executing HTTP requests via `wget`."""

    name = "wget"
    executable = "wget"
    resource_class = "http"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: WgetParser | None = None,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else WgetParser()

    async def version(self) -> str:
        """Query and return wget version information."""
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
        timeout_seconds: int = 10,
        max_redirects: int = 5,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for wget execution."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target URL cannot be empty")
        if max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")

        cmd = [
            self.executable,
            "-q",
            "-S",
            "-O",
            "-",
            f"--timeout={timeout_seconds}",
            "--tries=1",
            "--no-check-certificate",
            f"--max-redirect={max_redirects}",
            "--user-agent=ReconX/0.1.0",
        ]

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(clean_target)
        return cmd

    def parse_result(self, result: CommandResult | str, target: str = "") -> HTTPResponse:
        """Parse raw output or CommandResult into normalized HTTPResponse."""
        if isinstance(result, CommandResult):
            stdout_text = result.stdout
            stderr_text = result.stderr
            tgt = target
            if not tgt and result.arguments:
                tgt = result.arguments[-1]

            return self.parser.parse(
                stdout=stdout_text,
                stderr=stderr_text,
                url=tgt,
                elapsed_seconds=result.duration,
            )

        # String fallback assumes raw combined header+body
        return self.parser.parse(stdout=result, stderr="", url=target)
