"""Unit tests for HTTP response parsers, header analyzer, and wget parser."""

from __future__ import annotations

from reconx.models.http import (
    HTTPResponse,
    HeaderAnalysis,
)
from reconx.parsers.http import (
    HTTPResponseParser,
    HeaderAnalyzer,
    WgetParser,
)

RAW_CURL_200 = """HTTP/1.1 200 OK
Date: Wed, 07 Oct 2026 10:00:00 GMT
Server: Apache/2.4.51 (Unix)
Content-Type: text/html; charset=UTF-8
Content-Length: 78
Set-Cookie: session_id=xyz123; Path=/; Secure; HttpOnly; SameSite=Strict
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body>Hello World</body>
</html>"""

RAW_CURL_REDIRECT_CHAIN = """HTTP/1.1 301 Moved Permanently
Date: Wed, 07 Oct 2026 10:00:00 GMT
Server: nginx/1.18.0
Location: https://example.com/login
Content-Type: text/html
Content-Length: 0

HTTP/2 302 Found
date: Wed, 07 Oct 2026 10:00:01 GMT
server: nginx/1.18.0
location: https://example.com/dashboard
content-type: text/html
content-length: 0

HTTP/2 200 
date: Wed, 07 Oct 2026 10:00:02 GMT
server: nginx/1.18.0
content-type: text/html; charset=utf-8
content-length: 54
x-frame-options: SAMEORIGIN

<html><head><title>Dashboard</title></head><body>OK</body></html>"""

RAW_WGET_STDERR = """  HTTP/1.1 200 OK
  Date: Wed, 07 Oct 2026 10:00:00 GMT
  Server: gunicorn/20.1.0
  Content-Type: application/json
  Content-Length: 27
  Access-Control-Allow-Origin: *
"""
RAW_WGET_STDOUT = '{"status": "ok", "code": 1}'


class TestHTTPResponseParser:
    """Tests for HTTPResponseParser."""

    def test_parse_200_response(self) -> None:
        parser = HTTPResponseParser()
        res = parser.parse(RAW_CURL_200, url="http://example.com", elapsed_seconds=0.15)

        assert isinstance(res, HTTPResponse)
        assert res.url == "http://example.com"
        assert res.status_code == 200
        assert res.http_version == "HTTP/1.1"
        assert res.is_success is True
        assert res.is_redirect is False
        assert res.headers["server"] == "Apache/2.4.51 (Unix)"
        assert res.headers["content-type"] == "text/html; charset=UTF-8"
        assert res.title == "Example Domain"
        assert res.cookies["session_id"] == "xyz123"
        assert res.elapsed_seconds == 0.15
        assert "Hello World" in res.body

    def test_parse_redirect_chain(self) -> None:
        parser = HTTPResponseParser()
        res = parser.parse(RAW_CURL_REDIRECT_CHAIN, url="http://example.com")

        assert res.status_code == 200
        assert res.redirect_chain == ("https://example.com/login", "https://example.com/dashboard")
        assert res.final_url == "https://example.com/dashboard"
        assert res.title == "Dashboard"
        assert res.headers["x-frame-options"] == "SAMEORIGIN"
        assert "OK" in res.body

    def test_parse_empty_output(self) -> None:
        parser = HTTPResponseParser()
        res = parser.parse("", url="http://example.com")

        assert res.status_code == 0
        assert res.is_success is False
        assert res.body == ""
        assert res.content_length == 0

    def test_to_observations(self) -> None:
        parser = HTTPResponseParser()
        res = parser.parse(RAW_CURL_200, url="http://example.com")
        obs = res.to_observations(asset_id="asset-1", task_id="task-1")

        assert len(obs) == 1
        assert obs[0].type == "http_endpoint"
        assert obs[0].asset_id == "asset-1"
        assert obs[0].data["status_code"] == 200
        assert obs[0].data["title"] == "Example Domain"


class TestHeaderAnalyzer:
    """Tests for HeaderAnalyzer."""

    def test_analyze_security_headers_and_metadata(self) -> None:
        parser = HTTPResponseParser()
        res = parser.parse(RAW_CURL_200, url="http://example.com")

        analyzer = HeaderAnalyzer()
        analysis = analyzer.analyze(res.headers)

        assert isinstance(analysis, HeaderAnalysis)
        assert analysis.server == "Apache/2.4.51 (Unix)"
        assert "Apache/2.4.51 (Unix)" in analysis.technologies
        # Check present security headers
        assert "strict-transport-security" in analysis.security_headers_present
        assert "x-content-type-options" in analysis.security_headers_present
        assert "x-frame-options" in analysis.security_headers_present
        # Check missing security headers
        assert "content-security-policy" in analysis.security_headers_missing
        assert "referrer-policy" in analysis.security_headers_missing
        assert "permissions-policy" in analysis.security_headers_missing

    def test_analyze_cookies_flags(self) -> None:
        headers = {
            "server": "nginx",
            "set-cookie": "token=secret; Path=/api; Secure; HttpOnly; SameSite=Lax",
        }
        analyzer = HeaderAnalyzer()
        analysis = analyzer.analyze(headers)

        assert len(analysis.cookies) == 1
        cookie = analysis.cookies[0]
        assert cookie.name == "token"
        assert cookie.value == "secret"
        assert cookie.secure is True
        assert cookie.http_only is True
        assert cookie.same_site == "Lax"
        assert cookie.path == "/api"

    def test_cors_analysis(self) -> None:
        headers = {
            "access-control-allow-origin": "https://trusted.example",
            "access-control-allow-credentials": "true",
        }
        analyzer = HeaderAnalyzer()
        analysis = analyzer.analyze(headers)

        assert analysis.cors_origin == "https://trusted.example"
        assert analysis.cors_credentials is True

    def test_header_analysis_to_observations(self) -> None:
        analyzer = HeaderAnalyzer()
        analysis = analyzer.analyze({
            "server": "nginx/1.22",
            "x-powered-by": "PHP/8.2",
            "strict-transport-security": "max-age=3600",
        })
        obs = analysis.to_observations(asset_id="asset-web", task_id="task-http")

        types = [o.type for o in obs]
        assert "server_metadata" in types
        assert "missing_security_headers" in types
        server_obs = next(o for o in obs if o.type == "server_metadata")
        assert "PHP/8.2" in server_obs.data["technologies"]


class TestWgetParser:
    """Tests for WgetParser."""

    def test_parse_wget_output(self) -> None:
        parser = WgetParser()
        res = parser.parse(
            stdout=RAW_WGET_STDOUT,
            stderr=RAW_WGET_STDERR,
            url="http://api.example.com/status",
            elapsed_seconds=0.08,
        )

        assert res.status_code == 200
        assert res.headers["server"] == "gunicorn/20.1.0"
        assert res.headers["content-type"] == "application/json"
        assert res.body == RAW_WGET_STDOUT
        assert res.content_length == len(RAW_WGET_STDOUT.encode("utf-8"))
        assert res.elapsed_seconds == 0.08
