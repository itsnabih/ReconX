"""Parser for dirb web content scanner output."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from reconx.models.endpoint import DiscoveredEndpoint, normalize_endpoint_key

logger = logging.getLogger("reconx.parsers.dirb")

ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Matches:
# + http://example.com/admin (CODE:200|SIZE:1234)
# + http://example.com/login (CODE:302|SIZE:0)
DIRB_FINDING_REGEX = re.compile(
    r"^\+\s+(?P<url>\S+)\s+\(CODE:(?P<status>\d+)\|SIZE:(?P<size>\d+)\)",
    re.IGNORECASE,
)

# Matches:
# ==> DIRECTORY: http://example.com/images/
DIRB_DIR_REGEX = re.compile(
    r"^==>\s+DIRECTORY:\s*(?P<url>\S+)",
    re.IGNORECASE,
)

# Matches:
# LOCATION: http://example.com/redirect/
DIRB_LOCATION_REGEX = re.compile(
    r"^LOCATION:\s*(?P<location>\S+)",
    re.IGNORECASE,
)


class DirbParser:
    """Parses raw text output from `dirb` directory enumeration executions."""

    def parse(self, output: str, base_url: str = "") -> list[DiscoveredEndpoint]:
        """Parse dirb stdout output into DiscoveredEndpoint list."""
        if not output or not output.strip():
            return []

        endpoints: list[DiscoveredEndpoint] = []
        clean_text = ANSI_REGEX.sub("", output)

        for raw_line in clean_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Check if this line is a LOCATION header following a redirect
            loc_match = DIRB_LOCATION_REGEX.match(line)
            if loc_match and endpoints:
                loc = loc_match.group("location").strip()
                last = endpoints[-1]
                # Replace last endpoint with updated redirect_location
                endpoints[-1] = DiscoveredEndpoint(
                    url=last.url,
                    path=last.path,
                    status_code=last.status_code,
                    content_length=last.content_length,
                    sources=last.sources,
                    word_count=last.word_count,
                    line_count=last.line_count,
                    redirect_location=loc,
                    content_type=last.content_type,
                    duration_ms=last.duration_ms,
                )
                continue

            # Check for regular finding line (+ URL (CODE:xxx|SIZE:yyy))
            match = DIRB_FINDING_REGEX.match(line)
            if match:
                raw_url = match.group("url").strip()
                status = int(match.group("status"))
                size = int(match.group("size"))

                if "://" in raw_url:
                    url = raw_url
                    parsed = urlsplit(raw_url)
                    path = parsed.path or "/"
                else:
                    path = "/" + raw_url.lstrip("/")
                    url = f"{base_url.rstrip('/')}{path}" if base_url else path

                endpoints.append(
                    DiscoveredEndpoint(
                        url=url,
                        path=path,
                        status_code=status,
                        content_length=size,
                        sources=("dirb",),
                    )
                )
                continue

            # Check for directory line (==> DIRECTORY: URL)
            dir_match = DIRB_DIR_REGEX.match(line)
            if dir_match:
                raw_url = dir_match.group("url").strip()
                if "://" in raw_url:
                    url = raw_url
                    parsed = urlsplit(raw_url)
                    path = parsed.path or "/"
                else:
                    path = "/" + raw_url.lstrip("/")
                    url = f"{base_url.rstrip('/')}{path}" if base_url else path

                # Only add if not already present in this parse batch (using canonical key comparison)
                canonical_dir_key = normalize_endpoint_key(url, path)
                if not any(e.key == canonical_dir_key for e in endpoints):
                    endpoints.append(
                        DiscoveredEndpoint(
                            url=url,
                            path=path,
                            status_code=200,
                            sources=("dirb",),
                        )
                    )

        return endpoints

