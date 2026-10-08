"""Unit tests for web enumeration parsers (Gobuster, FFUF, Dirb)."""

from __future__ import annotations

import json
from reconx.parsers.dirb import DirbParser
from reconx.parsers.ffuf import FFUFParser
from reconx.parsers.gobuster import GobusterParser


class TestGobusterParser:
    """Tests for Gobuster directory/file enumeration output parsing."""

    def test_parse_empty_or_whitespace(self) -> None:
        parser = GobusterParser()
        assert parser.parse("") == []
        assert parser.parse("   \n\t  ") == []

    def test_parse_standard_output(self) -> None:
        parser = GobusterParser()
        sample_output = """
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://example.com/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]
/login                (Status: 200) [Size: 1045]
/test.php             (Status: 403) [Size: 281]
/index.html           (Status: 200) [Size: 312]
Progress: 4612 / 4612 (100.00%)
===============================================================
Finished
===============================================================
"""
        endpoints = parser.parse(sample_output, base_url="http://example.com")
        assert len(endpoints) == 4

        # Admin redirect
        admin = endpoints[0]
        assert admin.path == "/admin"
        assert admin.url == "http://example.com/admin"
        assert admin.status_code == 301
        assert admin.content_length == 178
        assert admin.redirect_location == "http://example.com/admin/"
        assert admin.sources == ("gobuster",)

        # Login
        login = endpoints[1]
        assert login.path == "/login"
        assert login.url == "http://example.com/login"
        assert login.status_code == 200
        assert login.content_length == 1045
        assert login.redirect_location is None

        # Test php
        test_php = endpoints[2]
        assert test_php.path == "/test.php"
        assert test_php.status_code == 403
        assert test_php.content_length == 281

        # Index html
        index = endpoints[3]
        assert index.path == "/index.html"
        assert index.status_code == 200
        assert index.content_length == 312

    def test_parse_found_prefix_and_expanded_mode(self) -> None:
        parser = GobusterParser()
        sample_output = """
Found: /secret (Status: 200) [Size: 512]
http://example.com/api/v1 (Status: 200) [Size: 980]
"""
        endpoints = parser.parse(sample_output, base_url="http://example.com")
        assert len(endpoints) == 2

        assert endpoints[0].path == "/secret"
        assert endpoints[0].status_code == 200
        assert endpoints[0].content_length == 512

        assert endpoints[1].url == "http://example.com/api/v1"
        assert endpoints[1].path == "/api/v1"
        assert endpoints[1].status_code == 200
        assert endpoints[1].content_length == 980

    def test_parse_ansi_escape_codes(self) -> None:
        parser = GobusterParser()
        ansi_output = "\x1b[32m/admin\x1b[0m (Status: \x1b[33m301\x1b[0m) [Size: 178]"
        endpoints = parser.parse(ansi_output, base_url="http://example.com")
        assert len(endpoints) == 1
        assert endpoints[0].path == "/admin"
        assert endpoints[0].status_code == 301
        assert endpoints[0].content_length == 178


class TestFFUFParser:
    """Tests for FFUF fuzzing output parsing in JSON and text modes."""

    def test_parse_empty_or_whitespace(self) -> None:
        parser = FFUFParser()
        assert parser.parse("") == []
        assert parser.parse("   \n\t  ") == []

    def test_parse_ndjson_records(self) -> None:
        parser = FFUFParser()
        lines = [
            json.dumps({
                "input": {"FUZZ": "admin"},
                "position": 1,
                "status": 301,
                "length": 178,
                "words": 12,
                "lines": 4,
                "content-type": "text/html",
                "redirectlocation": "http://example.com/admin/",
                "url": "http://example.com/admin",
                "duration": 25000000,
            }),
            json.dumps({
                "input": {"FUZZ": "api"},
                "position": 2,
                "status": 200,
                "length": 2048,
                "words": 85,
                "lines": 30,
                "content-type": "application/json",
                "redirectlocation": "",
                "url": "http://example.com/api",
                "duration": 15000000,
            }),
        ]
        ndjson_output = "\n".join(lines)
        endpoints = parser.parse(ndjson_output)
        assert len(endpoints) == 2

        admin = endpoints[0]
        assert admin.url == "http://example.com/admin"
        assert admin.path == "/admin"
        assert admin.status_code == 301
        assert admin.content_length == 178
        assert admin.word_count == 12
        assert admin.line_count == 4
        assert admin.redirect_location == "http://example.com/admin/"
        assert admin.content_type == "text/html"
        assert admin.duration_ms == 25.0
        assert admin.sources == ("ffuf",)

        api = endpoints[1]
        assert api.url == "http://example.com/api"
        assert api.path == "/api"
        assert api.status_code == 200
        assert api.content_length == 2048
        assert api.word_count == 85
        assert api.line_count == 30
        assert api.redirect_location is None
        assert api.content_type == "application/json"
        assert api.duration_ms == 15.0

    def test_parse_batch_json(self) -> None:
        parser = FFUFParser()
        batch_payload = {
            "commandline": "ffuf -u http://example.com/FUZZ -w /wordlist.txt",
            "time": "2026-10-07T12:00:00Z",
            "results": [
                {
                    "input": {"FUZZ": "dashboard"},
                    "status": 200,
                    "length": 512,
                    "words": 20,
                    "lines": 8,
                    "url": "http://example.com/dashboard",
                }
            ],
        }
        endpoints = parser.parse(json.dumps(batch_payload))
        assert len(endpoints) == 1
        assert endpoints[0].url == "http://example.com/dashboard"
        assert endpoints[0].path == "/dashboard"
        assert endpoints[0].status_code == 200
        assert endpoints[0].content_length == 512
        assert endpoints[0].word_count == 20
        assert endpoints[0].line_count == 8

    def test_parse_plain_text_fallback(self) -> None:
        parser = FFUFParser()
        sample_text = """
admin                   [Status: 301, Size: 178, Words: 12, Lines: 4, Duration: 23ms] [--> http://example.com/admin/]
login                   [Status: 200, Size: 1045, Words: 45, Lines: 15, Duration: 18ms]
[Status: 200, Size: 312, Words: 15, Lines: 5] | URL: http://example.com/robots.txt
"""
        endpoints = parser.parse(sample_text, base_url="http://example.com")
        assert len(endpoints) == 3

        assert endpoints[0].path == "/admin"
        assert endpoints[0].status_code == 301
        assert endpoints[0].content_length == 178
        assert endpoints[0].word_count == 12
        assert endpoints[0].line_count == 4
        assert endpoints[0].redirect_location == "http://example.com/admin/"

        assert endpoints[1].path == "/login"
        assert endpoints[1].status_code == 200
        assert endpoints[1].content_length == 1045

        assert endpoints[2].url == "http://example.com/robots.txt"
        assert endpoints[2].path == "/robots.txt"
        assert endpoints[2].status_code == 200
        assert endpoints[2].content_length == 312


class TestDirbParser:
    """Tests for Dirb directory scanner output parsing."""

    def test_parse_empty_or_whitespace(self) -> None:
        parser = DirbParser()
        assert parser.parse("") == []
        assert parser.parse("   \n\t  ") == []

    def test_parse_standard_dirb_output(self) -> None:
        parser = DirbParser()
        sample_output = """
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct  7 12:00:00 2026
URL_BASE: http://example.com/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- SCANNING: http://example.com/ ----
+ http://example.com/admin (CODE:301|SIZE:178)
LOCATION: http://example.com/admin/
+ http://example.com/index.html (CODE:200|SIZE:312)
==> DIRECTORY: http://example.com/images/
+ http://example.com/login (CODE:200|SIZE:1045)
+ http://example.com/secret (CODE:403|SIZE:281)

-----------------
DOWNLOADED: 4612 - FOUND: 4
"""
        endpoints = parser.parse(sample_output, base_url="http://example.com")
        assert len(endpoints) == 5

        # Admin redirect
        admin = endpoints[0]
        assert admin.url == "http://example.com/admin"
        assert admin.path == "/admin"
        assert admin.status_code == 301
        assert admin.content_length == 178
        assert admin.redirect_location == "http://example.com/admin/"
        assert admin.sources == ("dirb",)

        # Index
        index = endpoints[1]
        assert index.url == "http://example.com/index.html"
        assert index.path == "/index.html"
        assert index.status_code == 200
        assert index.content_length == 312

        # Directory detection
        images = endpoints[2]
        assert images.url == "http://example.com/images/"
        assert images.path == "/images/"
        assert images.status_code == 200

        # Login
        login = endpoints[3]
        assert login.url == "http://example.com/login"
        assert login.status_code == 200
        assert login.content_length == 1045

        # Secret
        secret = endpoints[4]
        assert secret.url == "http://example.com/secret"
        assert secret.status_code == 403
        assert secret.content_length == 281

    def test_directory_duplicate_suppression_with_trailing_slash(self) -> None:
        parser = DirbParser()
        sample_output = """
+ http://example.com/images (CODE:200|SIZE:500)
==> DIRECTORY: http://example.com/images/
"""
        endpoints = parser.parse(sample_output)
        # Should NOT duplicate images because canonical key matches
        assert len(endpoints) == 1
        assert endpoints[0].url == "http://example.com/images"
