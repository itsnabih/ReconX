"""Parser for ffuf web fuzzing output in JSON and text modes."""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

from reconx.models.endpoint import DiscoveredEndpoint

logger = logging.getLogger("reconx.parsers.ffuf")

ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Matches plain text ffuf line:
# admin [Status: 200, Size: 1045, Words: 45, Lines: 15, Duration: 25ms]
# admin [Status: 301, Size: 178, Words: 12, Lines: 4] [--> http://example.com/admin/]
# [Status: 200, Size: 1045, Words: 45, Lines: 15] | URL: http://example.com/admin
FFUF_TEXT_REGEX = re.compile(
    r"^(?:(?P<payload>\S+)\s+)?"
    r"\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)"
    r"(?:,\s*Words:\s*(?P<words>\d+))?"
    r"(?:,\s*Lines:\s*(?P<lines>\d+))?[^\]]*\]"
    r"(?:\s*\|\s*URL:\s*(?P<url>\S+))?"
    r"(?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?",
    re.IGNORECASE,
)


class FFUFParser:
    """Parses JSON records and plain text output from `ffuf` fuzzing executions."""

    def parse(self, output: str, base_url: str = "") -> list[DiscoveredEndpoint]:
        """Parse ffuf stdout output into DiscoveredEndpoint list."""
        if not output or not output.strip():
            return []

        clean_text = ANSI_REGEX.sub("", output).strip()

        # Try parsing as batch JSON object
        try:
            batch = json.loads(clean_text)
            if isinstance(batch, dict) and "results" in batch:
                return self._parse_json_results(batch["results"], base_url)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try line-by-line parsing (NDJSON or fallback text)
        endpoints: list[DiscoveredEndpoint] = []
        for line in clean_text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            # Try parsing line as JSON object (ffuf -json mode produces NDJSON)
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    record = json.loads(line_str)
                    if isinstance(record, dict) and ("status" in record or "url" in record):
                        ep = self._record_to_endpoint(record, base_url)
                        if ep is not None:
                            endpoints.append(ep)
                        continue
                except (json.JSONDecodeError, ValueError):
                    pass

            # Fallback to plain text line regex
            match = FFUF_TEXT_REGEX.match(line_str)
            if match:
                ep = self._match_to_endpoint(match, base_url)
                if ep is not None:
                    endpoints.append(ep)

        return endpoints

    def _parse_json_results(
        self, results: list[dict[str, Any]], base_url: str
    ) -> list[DiscoveredEndpoint]:
        endpoints: list[DiscoveredEndpoint] = []
        for rec in results:
            if isinstance(rec, dict):
                ep = self._record_to_endpoint(rec, base_url)
                if ep is not None:
                    endpoints.append(ep)
        return endpoints

    def _record_to_endpoint(
        self, rec: dict[str, Any], base_url: str
    ) -> DiscoveredEndpoint | None:
        raw_url = str(rec.get("url") or "").strip()
        payload = ""
        input_data = rec.get("input")
        if isinstance(input_data, dict):
            payload = str(input_data.get("FUZZ") or "")

        if not raw_url and payload:
            if base_url:
                raw_url = f"{base_url.rstrip('/')}/{payload.lstrip('/')}"
            else:
                raw_url = f"/{payload.lstrip('/')}"

        if not raw_url:
            return None

        if "://" in raw_url:
            url = raw_url
            parsed = urlsplit(raw_url)
            path = parsed.path or "/"
        else:
            path = "/" + raw_url.lstrip("/")
            url = f"{base_url.rstrip('/')}{path}" if base_url else path

        status = int(rec.get("status", 0))
        size = int(rec.get("length")) if rec.get("length") is not None else None
        words = int(rec.get("words")) if rec.get("words") is not None else None
        lines = int(rec.get("lines")) if rec.get("lines") is not None else None
        redirect = str(rec.get("redirectlocation") or "").strip() or None
        content_type = str(rec.get("content-type") or "").strip() or None

        raw_duration = rec.get("duration")
        duration_ms: float | None = None
        if raw_duration is not None:
            try:
                # ffuf reports duration in nanoseconds
                duration_ms = float(raw_duration) / 1_000_000.0
            except (ValueError, TypeError):
                duration_ms = None

        return DiscoveredEndpoint(
            url=url,
            path=path,
            status_code=status,
            content_length=size,
            sources=("ffuf",),
            word_count=words,
            line_count=lines,
            redirect_location=redirect,
            content_type=content_type,
            duration_ms=duration_ms,
        )

    def _match_to_endpoint(
        self, match: re.Match[str], base_url: str
    ) -> DiscoveredEndpoint | None:
        status = int(match.group("status"))
        size_str = match.group("size")
        size = int(size_str) if size_str is not None else None
        words_str = match.group("words")
        words = int(words_str) if words_str is not None else None
        lines_str = match.group("lines")
        lines = int(lines_str) if lines_str is not None else None
        redirect = match.group("redirect")
        if redirect:
            redirect = redirect.strip()

        matched_url = match.group("url")
        payload = match.group("payload")

        if matched_url:
            raw_url = matched_url.strip()
        elif payload:
            raw_url = payload.strip()
        else:
            return None

        if "://" in raw_url:
            url = raw_url
            parsed = urlsplit(raw_url)
            path = parsed.path or "/"
        else:
            path = "/" + raw_url.lstrip("/")
            url = f"{base_url.rstrip('/')}{path}" if base_url else path

        return DiscoveredEndpoint(
            url=url,
            path=path,
            status_code=status,
            content_length=size,
            sources=("ffuf",),
            word_count=words,
            line_count=lines,
            redirect_location=redirect,
        )

