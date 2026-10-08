"""Parsers for HTTP responses, headers, and redirect chains."""

from __future__ import annotations

import re

from reconx.models.http import (
    SECURITY_HEADERS,
    CookieInfo,
    HTTPResponse,
    HeaderAnalysis,
)


def _parse_cookie_directive(raw_cookie: str) -> CookieInfo:
    """Parse a single Set-Cookie header into a CookieInfo object."""
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    if not parts:
        return CookieInfo(name="", value="")

    # Name-value is the first part
    name_val = parts[0]
    name, _, val = name_val.partition("=")

    secure = False
    http_only = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None

    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower == "secure":
            secure = True
        elif attr_lower == "httponly":
            http_only = True
        elif attr_lower.startswith("samesite="):
            same_site = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            domain = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("path="):
            path = attr.split("=", 1)[1].strip()

    return CookieInfo(
        name=name.strip(),
        value=val.strip(),
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
    )


class HeaderAnalyzer:
    """Analyzes response headers for security headers, technologies, and metadata."""

    def analyze(self, headers: dict[str, str], raw_headers: list[tuple[str, str]] | None = None) -> HeaderAnalysis:
        # 1. Server metadata & technologies
        server = headers.get("server")
        techs: list[str] = []
        if server:
            techs.append(server)
        if "x-powered-by" in headers:
            techs.append(headers["x-powered-by"])
        if "x-aspnet-version" in headers:
            techs.append(f"ASP.NET {headers['x-aspnet-version']}")
        if "x-generator" in headers:
            techs.append(headers["x-generator"])

        # 2. Security headers
        present_sec: dict[str, str] = {}
        missing_sec: list[str] = []
        for sec_h in sorted(SECURITY_HEADERS):
            if sec_h in headers:
                present_sec[sec_h] = headers[sec_h]
            else:
                missing_sec.append(sec_h)

        # 3. CORS
        cors_origin = headers.get("access-control-allow-origin")
        cors_cred = None
        if "access-control-allow-credentials" in headers:
            cors_cred = headers["access-control-allow-credentials"].lower() == "true"

        # 4. Cookie flags
        cookies_list: list[CookieInfo] = []
        if raw_headers:
            for k, v in raw_headers:
                if k.lower() == "set-cookie":
                    cookies_list.append(_parse_cookie_directive(v))
        elif "set-cookie" in headers:
            cookies_list.append(_parse_cookie_directive(headers["set-cookie"]))

        return HeaderAnalysis(
            server=server,
            technologies=tuple(techs),
            security_headers_present=present_sec,
            security_headers_missing=tuple(missing_sec),
            cors_origin=cors_origin,
            cors_credentials=cors_cred,
            cookies=tuple(cookies_list),
        )


class HTTPResponseParser:
    """Parses curl output (-i) or raw HTTP responses into normalized HTTPResponse."""

    def parse(self, raw_output: str, url: str = "", elapsed_seconds: float = 0.0) -> HTTPResponse:
        clean = raw_output.strip()
        if not clean:
            return HTTPResponse(
                url=url,
                status_code=0,
                raw_output=raw_output,
                elapsed_seconds=elapsed_seconds,
            )

        # Split headers and body
        # Multiple HTTP blocks can occur if redirects were followed (-L) or 100 Continue
        # Blocks are separated by \r\n\r\n or \n\n
        blocks = re.split(r"(?:\r?\n){2}", raw_output)

        http_blocks: list[str] = []
        body_parts: list[str] = []

        found_final_headers = False
        for i, block in enumerate(blocks):
            # Check if block starts with an HTTP status line
            if not found_final_headers and re.match(r"^HTTP/\d+(?:\.\d+)?\s+\d+", block.strip(), re.IGNORECASE):
                http_blocks.append(block.strip())
            else:
                found_final_headers = True
                body_parts.append(block)

        # If all blocks were header blocks and no body
        body = "\n\n".join(body_parts) if body_parts else ""

        if not http_blocks:
            # Fallback: assume the whole thing might be body if no HTTP/ line
            return HTTPResponse(
                url=url,
                status_code=200 if clean else 0,
                body=clean,
                raw_output=raw_output,
                elapsed_seconds=elapsed_seconds,
            )

        # Parse redirect chain and final block
        redirect_chain: list[str] = []
        final_block = http_blocks[-1]

        current_url = url
        for block in http_blocks[:-1]:
            for line in block.splitlines():
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    redirect_chain.append(loc)
                    current_url = loc
                    break

        final_url = redirect_chain[-1] if redirect_chain else url

        # Parse final headers and status line
        lines = final_block.splitlines()
        status_line = lines[0].strip()
        m_status = re.match(r"^HTTP/(\d+(?:\.\d+)?)\s+(\d+)", status_line, re.IGNORECASE)
        http_version = f"HTTP/{m_status.group(1)}" if m_status else "HTTP/1.1"
        status_code = int(m_status.group(2)) if m_status else 200

        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}

        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                k_clean = k.strip().lower()
                v_clean = v.strip()
                headers[k_clean] = v_clean
                if k_clean == "set-cookie":
                    cookie_obj = _parse_cookie_directive(v_clean)
                    if cookie_obj.name:
                        cookies[cookie_obj.name] = cookie_obj.value

        content_len = 0
        if "content-length" in headers:
            try:
                content_len = int(headers["content-length"])
            except ValueError:
                content_len = len(body.encode("utf-8", errors="replace"))
        else:
            content_len = len(body.encode("utf-8", errors="replace"))

        return HTTPResponse(
            url=url,
            status_code=status_code,
            http_version=http_version,
            headers=headers,
            body=body,
            content_length=content_len,
            content_type=headers.get("content-type"),
            redirect_chain=tuple(redirect_chain),
            final_url=final_url,
            cookies=cookies,
            elapsed_seconds=elapsed_seconds,
            raw_output=raw_output,
        )


class WgetParser:
    """Parses Wget output (stderr headers + stdout body) into normalized HTTPResponse."""

    def parse(
        self,
        stdout: str,
        stderr: str,
        url: str = "",
        elapsed_seconds: float = 0.0,
    ) -> HTTPResponse:
        # Wget outputs server response headers to stderr when run with -S
        # Header lines in stderr typically start with 2 leading spaces: "  HTTP/1.1 200 OK"
        header_lines: list[str] = []
        for line in stderr.splitlines():
            stripped = line.strip()
            if stripped.startswith("HTTP/") or (header_lines and ":" in stripped):
                header_lines.append(stripped)

        raw_combined = "\n".join(header_lines) + "\n\n" + stdout
        parser = HTTPResponseParser()
        return parser.parse(raw_combined, url=url, elapsed_seconds=elapsed_seconds)
