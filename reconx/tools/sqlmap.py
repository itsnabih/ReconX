"""Sqlmap SQL injection assessment tool adapter."""

from __future__ import annotations

import logging
import re
from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.vulnerability import ExecutionMode, ToolVulnerabilityResult
from reconx.parsers.sqlmap import SqlmapParser
from reconx.tools.base import ToolAdapter

logger = logging.getLogger("reconx.tools.sqlmap")

SQLMAP_VERSION_REGEX = re.compile(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:#[a-z0-9]+)?)", re.IGNORECASE)

DISALLOWED_FLAGS = frozenset({
    "--os-shell",
    "--os-pwn",
    "--os-cmd",
    "--os-bof",
    "--priv-esc",
    "--msf-path",
    "--sql-shell",
    "--sql-file",
    "--dump",
    "--dump-all",
    "--dbs",
    "--passwords",
    "--schema",
    "--tamper",
})


class SqlmapAdapter(ToolAdapter):
    """Adapter for the sqlmap SQL injection scanner.

    Orchestrates execution of `sqlmap` under bounded vulnerability concurrency
    and translates raw scan outputs into normalized domain vulnerability observations.
    """

    name = "sqlmap"
    executable = "sqlmap"
    resource_class = "vulnerability"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: SqlmapParser | None = None,
        default_mode: ExecutionMode = ExecutionMode.SAFE,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser or SqlmapParser()
        self.default_mode = default_mode

    async def version(self) -> str:
        """Query and return the installed sqlmap version."""
        res = await self.runner.run([self.executable, "--version"], timeout=5.0)
        combined = f"{res.stdout} {res.stderr}".strip()
        match = SQLMAP_VERSION_REGEX.search(combined)
        if match:
            return f"sqlmap {match.group(1)}"
        return "sqlmap (unknown version)"

    def build_command(
        self,
        target: str,
        mode: ExecutionMode | str | None = None,
        parameter: str | None = None,
        data: str | None = None,
        cookie: str | None = None,
        dbms: str | None = None,
        level: int = 1,
        risk: int = 1,
        timeout: int = 10,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Safely construct command arguments for sqlmap execution."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target cannot be empty")

        if mode is None:
            exec_mode = self.default_mode
        elif isinstance(mode, str):
            exec_mode = ExecutionMode(mode.lower())
        else:
            exec_mode = mode

        cmd = [
            self.executable,
            "-u",
            clean_target,
            "--batch",
        ]

        if exec_mode == ExecutionMode.SAFE:
            # Safe mode: non-destructive, lowest risk, heuristic-gated
            cmd.extend([
                "--smart",
                "--level",
                "1",
                "--risk",
                "1",
                "--timeout",
                str(max(1, timeout)),
                "--retries",
                "1",
            ])
        elif exec_mode == ExecutionMode.PASSIVE:
            # Passive mode: minimal response footprint, null connection
            cmd.extend([
                "--smart",
                "--level",
                "1",
                "--risk",
                "1",
                "--null-connection",
                "--timeout",
                str(max(1, timeout)),
                "--retries",
                "1",
            ])
        elif exec_mode == ExecutionMode.ACTIVE:
            # Active mode: bounded level (max 3) and risk (max 2)
            safe_level = max(1, min(level, 3))
            safe_risk = max(1, min(risk, 2))
            cmd.extend([
                "--level",
                str(safe_level),
                "--risk",
                str(safe_risk),
                "--timeout",
                str(max(1, timeout)),
            ])

        if parameter:
            cmd.extend(["-p", parameter.strip()])

        if data:
            cmd.extend(["--data", data.strip()])

        if cookie:
            cmd.extend(["--cookie", cookie.strip()])

        if dbms:
            cmd.extend(["--dbms", dbms.strip()])

        if extra_args:
            # Guardrail check against disallowed offensive flags
            for arg in extra_args:
                clean_arg = arg.strip().split("=")[0]
                if clean_arg in DISALLOWED_FLAGS:
                    raise ValueError(f"Disallowed offensive argument: {clean_arg}")
            cmd.extend(extra_args)

        return cmd

    def parse_result(
        self,
        result: CommandResult | str,
        target: str = "",
        mode: ExecutionMode | str | None = None,
    ) -> ToolVulnerabilityResult:
        """Parse raw process output or CommandResult into normalized ToolVulnerabilityResult."""
        if mode is None:
            exec_mode = self.default_mode
        elif isinstance(mode, str):
            exec_mode = ExecutionMode(mode.lower())
        else:
            exec_mode = mode

        if isinstance(result, CommandResult):
            raw = result.stdout or result.stderr
            tgt = target
            if not tgt and result.arguments:
                try:
                    u_idx = result.arguments.index("-u")
                    tgt = result.arguments[u_idx + 1]
                except (ValueError, IndexError):
                    tgt = target
            return self.parser.parse(raw, target=tgt, mode=exec_mode)

        return self.parser.parse(result, target=target, mode=exec_mode)

