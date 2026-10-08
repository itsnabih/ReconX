"""Adapter for the `ffuf` web fuzzer."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.endpoint import DiscoveredEndpoint
from reconx.parsers.ffuf import FFUFParser
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


class FFUFAdapter(ToolAdapter):
    """Adapter for executing directory and endpoint fuzzing via `ffuf`."""

    name = "ffuf"
    executable = "ffuf"
    resource_class = "discovery"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        parser: FFUFParser | None = None,
    ) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else FFUFParser()

    async def version(self) -> str:
        """Query and return ffuf version information."""
        if not self.check_available():
            return "not_installed"
        res = await self.runner.run([self.executable, "-V"], timeout=5.0)
        output = res.stdout.strip() or res.stderr.strip()
        if output:
            match = re.search(r"ffuf\s+version:\s*([0-9a-zA-Z.-]+)", output, re.IGNORECASE)
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
        extra_args: list[str] | None = None,
        check_wordlist_exists: bool = False,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for ffuf execution."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target URL cannot be empty")

        clean_wordlist = validate_wordlist(wordlist, check_exists=check_wordlist_exists)

        if "FUZZ" not in clean_target:
            fuzz_url = f"{clean_target.rstrip('/')}/FUZZ"
        else:
            fuzz_url = clean_target

        cmd = [
            self.executable,
            "-u",
            fuzz_url,
            "-w",
            clean_wordlist,
            "-json",
            "-s",
            "-noninteractive",
            "-t",
            str(threads),
            "-timeout",
            str(timeout_seconds),
        ]

        if follow_redirects:
            cmd.append("-r")

        if extensions:
            clean_exts = [f".{e.strip().lstrip('.')}" for e in extensions if e.strip()]
            if clean_exts:
                cmd.extend(["-e", ",".join(clean_exts)])

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
                    fuzz_url = result.arguments[u_idx + 1]
                    # Strip /FUZZ from base target
                    tgt = fuzz_url.replace("/FUZZ", "").replace("FUZZ", "")
                except (ValueError, IndexError):
                    tgt = ""
            return self.parser.parse(raw, base_url=tgt)

        return self.parser.parse(result, base_url=target)
