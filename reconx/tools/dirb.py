"""Adapter for the `dirb` web content scanner."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.endpoint import DiscoveredEndpoint
from reconx.parsers.dirb import DirbParser
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


class DirbAdapter(ToolAdapter):
    """Adapter for executing web directory enumeration via `dirb`."""

    name = "dirb"
    executable = "dirb"
    resource_class = "discovery"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: DirbParser | None = None,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else DirbParser()

    async def version(self) -> str:
        """Query and return dirb version information."""
        if not self.check_available():
            return "not_installed"
        # dirb without arguments prints the banner containing version
        res = await self.runner.run([self.executable], timeout=5.0)
        output = res.stdout.strip() or res.stderr.strip()
        if output:
            match = re.search(r"DIRB\s+v([0-9a-zA-Z.-]+)", output, re.IGNORECASE)
            if match:
                return match.group(1)
        return "unknown"

    def check_wordlist_available(self, wordlist: str = DEFAULT_WORDLIST) -> bool:
        """Check whether the specified wordlist file exists on the filesystem."""
        return os.path.isfile(wordlist)

    def build_command(
        self,
        target: str,
        wordlist: str = DEFAULT_WORDLIST,
        delay_ms: int = 0,
        case_insensitive: bool = False,
        extra_args: list[str] | None = None,
        check_wordlist_exists: bool = False,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for dirb execution."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target URL cannot be empty")

        clean_wordlist = validate_wordlist(wordlist, check_exists=check_wordlist_exists)

        cmd = [
            self.executable,
            clean_target,
            clean_wordlist,
            "-r",  # Non-recursive
            "-S",  # Silent mode (no progress words)
            "-l",  # Print Location header for redirects
        ]

        if delay_ms > 0:
            cmd.extend(["-z", str(delay_ms)])

        if case_insensitive:
            cmd.append("-i")

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
            if not tgt and len(result.arguments) >= 2:
                tgt = result.arguments[1]
            return self.parser.parse(raw, base_url=tgt)

        return self.parser.parse(result, base_url=target)
