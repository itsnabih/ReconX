"""Parser for sqlmap SQL injection detection output."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from reconx.models.vulnerability import (
    ExecutionMode,
    ToolVulnerabilityResult,
    VulnerabilityObservation,
)

logger = logging.getLogger("reconx.parsers.sqlmap")

# Regular expressions for sqlmap output extraction
PARAMETER_HEADER_REGEX = re.compile(
    r"^Parameter:\s*(?P<param>[^\n\r(]+?)(?:\s*\((?P<place>.+)\))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
TYPE_REGEX = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.IGNORECASE | re.MULTILINE)
TITLE_REGEX = re.compile(r"^\s*Title:\s*(?P<title>.+)$", re.IGNORECASE | re.MULTILINE)
PAYLOAD_REGEX = re.compile(r"^\s*Payload:\s*(?P<payload>.+)$", re.IGNORECASE | re.MULTILINE)

DBMS_INFO_REGEX = re.compile(
    r"(?:back-end DBMS is|back-end DBMS:\s*)\s*(?P<dbms>[^\n\r]+)",
    re.IGNORECASE,
)
WEB_TECH_REGEX = re.compile(
    r"web application technology:\s*(?P<tech>[^\n\r]+)",
    re.IGNORECASE,
)
HEURISTIC_REGEX = re.compile(
    r"heuristics detected that the target parameter '(?P<param>[^']+)' might be injectable",
    re.IGNORECASE,
)
VULNERABLE_PARAM_REGEX = re.compile(
    r"parameter '(?P<param>[^']+)' is vulnerable",
    re.IGNORECASE,
)


def _extract_endpoint(target: str) -> str:
    """Extract path from URL or return root."""
    if not target:
        return "/"
    try:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.path or "/"
    except Exception:
        return "/"


class SqlmapParser:
    """Parses raw text and structured log outputs from `sqlmap` executions."""

    def parse(
        self,
        output: str,
        target: str = "",
        mode: ExecutionMode = ExecutionMode.SAFE,
    ) -> ToolVulnerabilityResult:
        """Parse raw sqlmap stdout/log into a normalized ToolVulnerabilityResult."""
        result = ToolVulnerabilityResult(
            tool="sqlmap",
            target=target,
            execution_mode=mode,
            raw_output=output,
        )

        if not output or not output.strip():
            return result

        clean_text = output.replace("\r\n", "\n").replace("\r", "\n").strip()
        endpoint = _extract_endpoint(target)

        # Detect backend DBMS
        dbms = None
        dbms_match = DBMS_INFO_REGEX.search(clean_text)
        if dbms_match:
            dbms = dbms_match.group("dbms").strip()

        # Parse confirmed injection blocks between '---' markers
        found_parameters: set[str] = set()
        blocks = self._extract_injection_blocks(clean_text)

        for block in blocks:
            param_match = PARAMETER_HEADER_REGEX.search(block)
            if not param_match:
                continue

            param_name = param_match.group("param").strip()
            param_place = param_match.group("place")
            full_param = f"{param_name} ({param_place})" if param_place else param_name
            found_parameters.add(param_name)

            # Split block into sub-entries by 'Type:'
            entries = self._parse_injection_entries(block)
            for entry in entries:
                itype = entry.get("type", "SQL Injection")
                title = entry.get("title", f"SQL Injection in {full_param}")
                payload = entry.get("payload", "")

                desc = f"Parameter '{full_param}' is vulnerable to {itype}."
                if title:
                    desc += f" Vector: {title}."
                if dbms:
                    desc += f" Back-end DBMS: {dbms}."

                obs = VulnerabilityObservation(
                    tool="sqlmap",
                    target=target or "unknown_target",
                    endpoint=endpoint,
                    title=f"SQL Injection ({itype}) in parameter '{param_name}'",
                    description=desc,
                    severity="high",
                    parameter=full_param,
                    injection_type=itype,
                    execution_mode=mode,
                    raw_data={
                        "parameter": full_param,
                        "type": itype,
                        "title": title,
                        "payload": payload,
                        "dbms": dbms,
                    },
                )
                result.add(obs)

        # If no injection blocks were parsed, check for 'parameter X is vulnerable'
        if not result.has_findings:
            for v_match in VULNERABLE_PARAM_REGEX.finditer(clean_text):
                param_name = v_match.group("param").strip()
                if param_name not in found_parameters:
                    found_parameters.add(param_name)
                    desc = f"Parameter '{param_name}' identified as vulnerable to SQL injection."
                    if dbms:
                        desc += f" Back-end DBMS: {dbms}."
                    obs = VulnerabilityObservation(
                        tool="sqlmap",
                        target=target or "unknown_target",
                        endpoint=endpoint,
                        title=f"SQL Injection in parameter '{param_name}'",
                        description=desc,
                        severity="high",
                        parameter=param_name,
                        injection_type="sql_injection",
                        execution_mode=mode,
                        raw_data={"parameter": param_name, "dbms": dbms},
                    )
                    result.add(obs)

        # Check for heuristic warnings if still no confirmed injection point
        if not result.has_findings:
            for h_match in HEURISTIC_REGEX.finditer(clean_text):
                param_name = h_match.group("param").strip()
                desc = (
                    f"Heuristics detected that parameter '{param_name}' might be injectable."
                )
                if dbms:
                    desc += f" Possible DBMS: {dbms}."
                obs = VulnerabilityObservation(
                    tool="sqlmap",
                    target=target or "unknown_target",
                    endpoint=endpoint,
                    title=f"Potential SQL Injection heuristic in parameter '{param_name}'",
                    description=desc,
                    severity="medium",
                    parameter=param_name,
                    injection_type="heuristic_indicator",
                    execution_mode=mode,
                    raw_data={"parameter": param_name, "dbms": dbms, "heuristic": True},
                )
                result.add(obs)

        return result

    def _extract_injection_blocks(self, text: str) -> list[str]:
        """Extract sections enclosed between '---' markers or Parameter sections."""
        blocks: list[str] = []
        delim_pattern = re.compile(r"^---\s*\n(.*?)\n---", re.MULTILINE | re.DOTALL)
        for m in delim_pattern.finditer(text):
            content = m.group(1).strip()
            param_chunks = re.split(r"(?=^Parameter:\s*)", content, flags=re.MULTILINE)
            for chunk in param_chunks:
                if chunk.strip().startswith("Parameter:"):
                    blocks.append(chunk.strip())

        if not blocks and "Parameter:" in text:
            param_chunks = re.split(r"(?=^Parameter:\s*)", text, flags=re.MULTILINE)
            for chunk in param_chunks:
                if chunk.strip().startswith("Parameter:"):
                    end_pos = re.search(r"(\n\[[A-Z]+\]|\n---|\Z)", chunk)
                    end_idx = end_pos.start() if end_pos else len(chunk)
                    blocks.append(chunk[:end_idx].strip())

        return blocks

    def _parse_injection_entries(self, block: str) -> list[dict[str, str]]:
        """Parse distinct Type/Title/Payload sub-entries within a parameter block."""
        entries: list[dict[str, str]] = []
        type_chunks = re.split(r"(?=^\s*Type:\s*)", block, flags=re.MULTILINE)

        for chunk in type_chunks:
            t_match = TYPE_REGEX.search(chunk)
            if not t_match:
                continue

            itype = t_match.group("type").strip()
            title = ""
            payload = ""

            title_match = TITLE_REGEX.search(chunk)
            if title_match:
                title = title_match.group("title").strip()

            payload_match = PAYLOAD_REGEX.search(chunk)
            if payload_match:
                payload = payload_match.group("payload").strip()

            entries.append({
                "type": itype,
                "title": title,
                "payload": payload,
            })

        return entries

