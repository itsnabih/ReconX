"""Parser for nikto web vulnerability scanner output."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from reconx.models.vulnerability import (
    ExecutionMode,
    ToolVulnerabilityResult,
    VulnerabilityObservation,
)

logger = logging.getLogger("reconx.parsers.nikto")

# Matches text findings:
# + OSVDB-3092: /test.php: This might be interesting...
# + /login: The anti-clickjacking X-Frame-Options header is not present.
# + Server: Apache/2.4.41
NIKTO_TEXT_LINE_REGEX = re.compile(
    r"^\+\s+(?:OSVDB-(?P<osvdb>\d+):\s*)?(?:(?P<path>/\S*):\s*)?(?P<msg>.+)$",
    re.IGNORECASE,
)

# Target header info in text output
NIKTO_TARGET_REGEX = re.compile(
    r"^\+\s+Target (?:Hostname|Host):\s*(?P<host>\S+)",
    re.IGNORECASE,
)


def _classify_nikto_severity(msg: str) -> str:
    """Assign an advisory severity rating based on Nikto finding content."""
    msg_lower = msg.lower()
    if any(k in msg_lower for k in ("remote code execution", "command execution", "remote shell", "sql injection")):
        return "critical"
    if any(k in msg_lower for k in ("authentication bypass", "arbitrary file", "upload", "xss", "cross-site")):
        return "high"
    if any(k in msg_lower for k in ("directory indexing", "interesting", "config", "backup", "vulnerable", "admin")):
        return "medium"
    if any(k in msg_lower for k in ("header is not present", "cookie", "leak", "disclosure", "version")):
        return "low"
    return "info"


class NiktoParser:
    """Parses JSON records and plain text output from `nikto` executions."""

    def parse(
        self,
        output: str,
        target: str = "",
        mode: ExecutionMode = ExecutionMode.SAFE,
    ) -> ToolVulnerabilityResult:
        """Parse raw nikto output into a normalized ToolVulnerabilityResult."""
        result = ToolVulnerabilityResult(
            tool="nikto",
            target=target,
            execution_mode=mode,
            raw_output=output,
        )

        if not output or not output.strip():
            return result

        clean_text = output.strip()

        # Try parsing JSON format
        try:
            data = json.loads(clean_text)
            if isinstance(data, dict):
                return self._parse_json(data, target=target, mode=mode, raw_output=clean_text)
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback to plain text parsing
        return self._parse_text(clean_text, target=target, mode=mode)

    def _parse_json(
        self,
        data: dict[str, Any],
        target: str,
        mode: ExecutionMode,
        raw_output: str,
    ) -> ToolVulnerabilityResult:
        resolved_target = target or str(data.get("host") or data.get("ip") or "")
        result = ToolVulnerabilityResult(
            tool="nikto",
            target=resolved_target,
            execution_mode=mode,
            raw_output=raw_output,
        )

        vulns = data.get("vulnerabilities") or []
        for item in vulns:
            if not isinstance(item, dict):
                continue

            msg = str(item.get("msg") or item.get("message") or "").strip()
            if not msg:
                continue

            path = str(item.get("url") or item.get("uri") or "").strip()
            osvdb = str(item.get("OSVDB") or item.get("osvdb") or "").strip()
            if osvdb in ("0", ""):
                osvdb = None  # type: ignore[assignment]

            cve = None
            cve_match = re.search(r"CVE-\d{4}-\d+", msg, re.IGNORECASE)
            if cve_match:
                cve = cve_match.group(0).upper()

            obs = VulnerabilityObservation(
                tool="nikto",
                target=resolved_target,
                endpoint=path or "/",
                title=re.split(r"\.\s+", msg)[0].strip() or msg[:80],
                description=msg,
                severity=_classify_nikto_severity(msg),
                cve=cve,
                osvdb=osvdb,
                execution_mode=mode,
                raw_data=item,
            )
            result.add(obs)

        return result

    def _parse_text(
        self,
        text: str,
        target: str,
        mode: ExecutionMode,
    ) -> ToolVulnerabilityResult:
        resolved_target = target
        result = ToolVulnerabilityResult(
            tool="nikto",
            target=resolved_target,
            execution_mode=mode,
            raw_output=text,
        )

        for line in text.splitlines():
            sline = line.strip()
            if not sline or sline.startswith("---") or sline.startswith("- Nikto"):
                continue

            # Detect target host if not provided
            if not resolved_target:
                host_match = NIKTO_TARGET_REGEX.match(sline)
                if host_match:
                    resolved_target = host_match.group("host").strip()
                    result.target = resolved_target
                    continue

            # Skip general summary statistics lines
            if any(term in sline.lower() for term in ("items checked:", "end time:", "start time:", "reported on remote host", "host(s) tested", "error(s) and")):
                continue
            if sline.startswith("+ Target IP:") or sline.startswith("+ Target Port:"):
                continue

            match = NIKTO_TEXT_LINE_REGEX.match(sline)
            if not match:
                continue

            msg = (match.group("msg") or "").strip()
            if not msg:
                continue

            path = (match.group("path") or "").strip()
            osvdb = match.group("osvdb")
            if osvdb:
                osvdb = osvdb.strip()

            cve = None
            cve_match = re.search(r"CVE-\d{4}-\d+", msg, re.IGNORECASE)
            if cve_match:
                cve = cve_match.group(0).upper()

            obs = VulnerabilityObservation(
                tool="nikto",
                target=resolved_target or "unknown_target",
                endpoint=path or "/",
                title=re.split(r"\.\s+", msg)[0].strip() or msg[:80],
                description=msg,
                severity=_classify_nikto_severity(msg),
                cve=cve,
                osvdb=osvdb,
                execution_mode=mode,
                raw_data={"line": sline},
            )
            result.add(obs)

        return result
