"""Unit tests for packaging metadata, CLI parser, and command dispatch (Phase 14)."""

from __future__ import annotations

import asyncio
from pathlib import Path
import unittest

from reconx.cli import build_parser, cmd_session_list, cmd_tools_check, main
from reconx.session.manager import ScanSessionManager


class TestPackagingAndCLI(unittest.IsolatedAsyncioTestCase):
    """Tests for CLI arguments, packaging, and subcommands."""

    def test_pyproject_toml_configuration(self) -> None:
        pyproject_path = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
        assert pyproject_path.exists()
        content = pyproject_path.read_text(encoding="utf-8")
        assert 'name = "reconx"' in content
        assert 'reconx = "reconx.cli:main"' in content
        assert "setuptools" in content

    def test_cli_parser_scan_subcommand(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "-t", "example.com", "-p", "web", "-m", "active", "--modules", "dns,http", "-f", "json", "-w", "/tmp/list.txt", "--timeout", "15"])
        assert args.subcommand == "scan"
        assert args.target_flag == "example.com"
        assert args.profile == "web"
        assert args.mode == "active"
        assert args.modules == "dns,http"
        assert args.format == "json"
        assert args.wordlist == "/tmp/list.txt"
        assert args.timeout == 15.0

    def test_cli_parser_scan_positional_target(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "example.com", "-p", "quick"])
        assert args.subcommand == "scan"
        assert args.target_pos == "example.com"
        assert args.target_flag is None

    def test_cli_parser_tools_check(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["tools", "check", "--tools", "nmap,curl", "--json"])
        assert args.subcommand == "tools"
        assert args.tools_action == "check"
        assert args.tools == "nmap,curl"
        assert args.json is True

    def test_cli_parser_session_commands(self) -> None:
        parser = build_parser()
        args_list = parser.parse_args(["session", "list", "--db", "custom.db"])
        assert args_list.subcommand == "session"
        assert args_list.session_action == "list"
        assert args_list.db == "custom.db"

        args_resume = parser.parse_args(["session", "resume", "scan-abc-123"])
        assert args_resume.subcommand == "session"
        assert args_resume.session_action == "resume"
        assert args_resume.scan_id == "scan-abc-123"

    async def test_cmd_tools_check_execution(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["tools", "check", "--tools", "curl"])
        exit_code = await cmd_tools_check(args)
        assert exit_code in (0, 1)

    def test_cmd_session_list_empty(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "empty.db"
            parser = build_parser()
            args = parser.parse_args(["session", "list", "--db", str(db_path)])
            exit_code = cmd_session_list(args)
            assert exit_code == 0

    def test_cli_rejects_unsafe_target_early(self) -> None:
        # Malicious target with command injection
        exit_code = main(["scan", "-t", "example.com; rm -rf /"])
        assert exit_code == 2
