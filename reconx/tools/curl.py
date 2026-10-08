"""Adapter for the `curl` HTTP transfer utility."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.http import HTTPResponse
from reconx.parsers.http import HTTPResponseParser
from reconx.tools.base import ToolAdapter


class CurlAdapter(ToolAdapter):
    """Adapter for executing HTTP requests via `curl`."""

    name = "curl"
    executable = "curl"
    resource_class = "http"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: HTTPResponseParser | None = None,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else HTTPResponseParser()

    async def version(self) -> str:
        """Query and return curl version information."""
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
        follow_redirects: bool = True,
        max_redirects: int = 5,
        timeout_seconds: int = 10,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        verify_ssl: bool = False,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for curl execution."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target URL cannot be empty")
        if max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")

        cmd = [
            self.executable,
            "-s",
            "-S",
            "-i",
            "--max-time",
            str(timeout_seconds),
        ]

        if follow_redirects:
            cmd.extend(["-L", "--max-redirs", str(max_redirects)])

        if not verify_ssl:
            cmd.append("-k")

        if method.upper() != "GET":
            cmd.extend(["-X", method.upper()])

        # Default User-Agent if not provided
        req_headers = dict(headers or {})
        if "user-agent" not in {k.lower() for k in req_headers}:
            req_headers["User-Agent"] = "ReconX/0.1.0"

        for k, v in req_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(clean_target)
        return cmd

    def parse_result(self, result: CommandResult | str, target: str = "") -> HTTPResponse:
        """Parse raw output or CommandResult into normalized HTTPResponse."""
        if isinstance(result, CommandResult):
            raw = result.stdout
            tgt = target
            if not tgt and result.arguments:
                tgt = result.arguments[-1]

            return self.parser.parse(
                raw,
                url=tgt,
                elapsed_seconds=result.duration,
            )

        return self.parser.parse(result, url=target)
