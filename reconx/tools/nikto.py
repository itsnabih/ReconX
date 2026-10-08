"""Nikto web server vulnerability scanner adapter."""

from __future__ import annotations

import logging
import re
from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.vulnerability import ExecutionMode, ToolVulnerabilityResult
from reconx.parsers.nikto import NiktoParser
from reconx.tools.base import ToolAdapter

logger = logging.getLogger("reconx.tools.nikto")

NIKTO_VERSION_REGEX = re.compile(r"Nikto\s+([0-9\.]+[^\s\)]*)", re.IGNORECASE)


class NiktoAdapter(ToolAdapter):
    """Adapter for the Nikto web server scanner.

    Orchestrates execution of `nikto` under bounded vulnerability concurrency
    and translates raw scan outputs into normalized domain vulnerability observations.
    """

    name = "nikto"
    executable = "nikto"
    resource_class = "vulnerability"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: NiktoParser | None = None,
        default_mode: ExecutionMode = ExecutionMode.SAFE,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser or NiktoParser()
        self.default_mode = default_mode

    async def version(self) -> str:
        """Query and return the installed Nikto version."""
        res = await self.runner.run([self.executable, "-Version"], timeout=5.0)
        combined = f"{res.stdout} {res.stderr}".strip()
        match = NIKTO_VERSION_REGEX.search(combined)
        if match:
            return f"Nikto {match.group(1)}"
        return "Nikto (unknown version)"

    def build_command(
        self,
        target: str,
        mode: ExecutionMode | str | None = None,
        port: int | None = None,
        ssl: bool = False,
        vhost: str | None = None,
        tuning: str | None = None,
        max_time: str | None = None,
        extra_args: list[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Safely construct command arguments for Nikto execution."""
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
            "-host",
            clean_target,
            "-nointeractive",
            "-ask",
            "no",
        ]

        if exec_mode == ExecutionMode.SAFE:
            # Safe mode: non-destructive inspection, config, information disclosure, admin consoles
            tuning_val = tuning or "1,2,3,b,e"
            cmd.extend(["-Tuning", tuning_val])
            cmd.extend(["-maxtime", max_time or "300s"])
        elif exec_mode == ExecutionMode.PASSIVE:
            # Passive mode: information disclosure and software banner identification only
            tuning_val = tuning or "3,b"
            cmd.extend(["-Tuning", tuning_val])
            cmd.extend(["-maxtime", max_time or "120s"])
        elif exec_mode == ExecutionMode.ACTIVE:
            # Active mode: broader vulnerability check suite
            tuning_val = tuning or "1,2,3,4,5,7,8,9,0,a,b,c,d,e"
            cmd.extend(["-Tuning", tuning_val])
            cmd.extend(["-maxtime", max_time or "600s"])

        if port is not None:
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")
            cmd.extend(["-port", str(port)])

        if ssl:
            cmd.append("-ssl")

        if vhost:
            clean_vhost = vhost.strip()
            if clean_vhost:
                cmd.extend(["-vhost", clean_vhost])

        if extra_args:
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
                    h_idx = result.arguments.index("-host")
                    tgt = result.arguments[h_idx + 1]
                except (ValueError, IndexError):
                    tgt = target
            return self.parser.parse(raw, target=tgt, mode=exec_mode)

        return self.parser.parse(result, target=target, mode=exec_mode)
