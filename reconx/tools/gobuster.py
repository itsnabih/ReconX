"""Adapter for the `gobuster` directory/file enumeration tool."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.endpoint import DiscoveredEndpoint
from reconx.parsers.gobuster import GobusterParser
from reconx.tools.base import ToolAdapter

DEFAULT_WORDLIST = "/usr/share/dirb/wordlists/common.txt"


def validate_wordlist(wordlist: str, check_exists: bool = False) -> str:
    """Validate wordlist path and optionally verify file existence."""
    clean = wordlist.strip()
    if not clean:
        raise ValueError("Wordlist path cannot be empty")
    if check_exists and not Path(clean).is_file():
        raise FileNotFoundError(f"Wordlist file not found: {clean}")
    return clean


class GobusterAdapter(ToolAdapter):
    """Adapter for executing web directory enumeration via `gobuster`."""

    name = "gobuster"
    executable = "gobuster"
    resource_class = "discovery"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: GobusterParser | None = None,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else GobusterParser()

    async def version(self) -> str:
        """Query and return gobuster version information."""
        if not self.check_available():
            return "not_installed"
        res = await self.runner.run([self.executable, "--version"], timeout=5.0)
        output = res.stdout.strip() or res.stderr.strip()
        if output:
            match = re.search(r"gobuster\s+version\s+([0-9a-zA-Z.-]+)", output, re.IGNORECASE)
            if match:
                return match.group(1)
            return output.splitlines()[0].strip()
        return "unknown"

    def check_wordlist_available(self, wordlist: str = DEFAULT_WORDLIST) -> bool:
        """Check whether the specified wordlist file exists on the filesystem."""
        return os.path.isfile(wordlist)

    def build_command(
        self,
        target: str,
        wordlist: str = DEFAULT_WORDLIST,
        threads: int = 10,
        timeout_seconds: int = 10,
        follow_redirects: bool = False,
        extensions: list[str] | None = None,
        verify_ssl: bool = False,
        extra_args: list[str] | None = None,
        check_wordlist_exists: bool = False,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for gobuster execution."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target URL cannot be empty")

        clean_wordlist = validate_wordlist(wordlist, check_exists=check_wordlist_exists)

        cmd = [
            self.executable,
            "dir",
            "-u",
            clean_target,
            "-w",
            clean_wordlist,
            "-q",
            "--no-error",
            "--no-progress",
            "-t",
            str(threads),
            "--timeout",
            f"{timeout_seconds}s",
        ]

        if not verify_ssl:
            cmd.append("-k")

        if follow_redirects:
            cmd.append("-r")

        if extensions:
            clean_exts = [e.strip().lstrip(".") for e in extensions if e.strip()]
            if clean_exts:
                cmd.extend(["-x", ",".join(clean_exts)])

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    def parse_result(
        self, result: CommandResult | str, target: str = ""
    ) -> list[DiscoveredEndpoint]:
        """Parse raw process output or CommandResult into normalized DiscoveredEndpoints."""
        if isinstance(result, CommandResult):
            raw = result.stdout
            tgt = target
            if not tgt and result.arguments:
                try:
                    u_idx = result.arguments.index("-u")
                    tgt = result.arguments[u_idx + 1]
                except (ValueError, IndexError):
                    tgt = ""
            return self.parser.parse(raw, base_url=tgt)

        return self.parser.parse(result, base_url=target)
