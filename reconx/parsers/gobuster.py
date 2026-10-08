"""Parser for gobuster directory/file enumeration output."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from reconx.models.endpoint import DiscoveredEndpoint

# Matches ANSI escape sequences
ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Matches gobuster finding line:
# /admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]
# Found: /admin (Status: 301) [Size: 178]
# http://example.com/admin (Status: 200) [Size: 1045]
GOBUSTER_LINE_REGEX = re.compile(
    r"^(?:Found:\s+)?(?P<target>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?",
    re.IGNORECASE,
)


class GobusterParser:
    """Parses raw text output from `gobuster dir` executions."""

    def parse(self, output: str, base_url: str = "") -> list[DiscoveredEndpoint]:
        """Parse gobuster stdout text into a list of DiscoveredEndpoint objects."""
        if not output:
            return []

        endpoints: list[DiscoveredEndpoint] = []
        clean_text = ANSI_REGEX.sub("", output)

        for raw_line in clean_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("===") or line.startswith("[+]") or line.startswith("[-]"):
                continue
            if line.startswith("Progress:") or line.startswith("Starting gobuster"):
                continue

            match = GOBUSTER_LINE_REGEX.match(line)
            if not match:
                continue

            target = match.group("target").strip()
            status = int(match.group("status"))
            size_str = match.group("size")
            size = int(size_str) if size_str is not None else None
            redirect = match.group("redirect")
            if redirect:
                redirect = redirect.strip()

            if "://" in target:
                url = target
                parsed = urlsplit(target)
                path = parsed.path or "/"
            else:
                path = "/" + target.lstrip("/")
                if base_url:
                    url = f"{base_url.rstrip('/')}{path}"
                else:
                    url = path

            endpoints.append(
                DiscoveredEndpoint(
                    url=url,
                    path=path,
                    status_code=status,
                    content_length=size,
                    sources=("gobuster",),
                    redirect_location=redirect,
                )
            )

        return endpoints
