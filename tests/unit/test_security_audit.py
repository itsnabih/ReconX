"""Unit tests for Target Security Validator, Command Safety Auditor, and Framework Security (Phase 14)."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from reconx.security.audit import (
    CommandSafetyAuditor,
    FileSecurityAuditor,
    SecurityViolation,
    TargetSecurityValidator,
    audit_framework_environment,
)


class TestTargetSecurityValidator:
    """Tests for validating target inputs against injection and metacharacters."""

    @pytest.mark.parametrize(
        "valid_target",
        [
            "example.com",
            "api.subdomain.example.com",
            "192.168.1.1",
            "10.0.0.0/24",
            "::1",
            "http://example.com",
            "https://api.example.com:8443/login",
            "sub-domain.example-site.co.uk",
        ],
    )
    def test_valid_targets_accepted(self, valid_target: str) -> None:
        assert TargetSecurityValidator.is_safe_target(valid_target) is True
        TargetSecurityValidator.validate_target(valid_target)

    @pytest.mark.parametrize(
        "malicious_target,expected_substr",
        [
            ("example.com; rm -rf /", "shell metacharacters"),
            ("example.com && curl http://evil.com", "shell metacharacters"),
            ("example.com | nc -e /bin/sh", "shell metacharacters"),
            ("example.com`whoami`", "shell metacharacters"),
            ("example.com$(whoami)", "shell metacharacters"),
            ("example.com\x00extra", "shell metacharacters"),
            ("example.com\x01extra", "control character"),
            ("-oG output.txt", "cannot start with a flag parameter"),
            ("--script malicious.lua", "cannot start with a flag parameter"),
            ("", "empty"),
            ("   ", "empty"),
        ],
    )
    def test_malicious_and_malformed_targets_rejected(
        self, malicious_target: str, expected_substr: str
    ) -> None:
        assert TargetSecurityValidator.is_safe_target(malicious_target) is False
        with pytest.raises(SecurityViolation) as exc_info:
            TargetSecurityValidator.validate_target(malicious_target)
        assert expected_substr.lower() in str(exc_info.value).lower()


class TestCommandSafetyAuditor:
    """Tests for CommandSafetyAuditor verifying argument safety and forbidden flags."""

    def test_safe_command_passes(self) -> None:
        cmd = ["nmap", "-sV", "-p80,443", "example.com"]
        assert CommandSafetyAuditor.is_command_safe(cmd) is True
        assert len(CommandSafetyAuditor.audit_command(cmd)) == 0

    def test_empty_command_rejected(self) -> None:
        violations = CommandSafetyAuditor.audit_command([])
        assert len(violations) > 0
        assert "empty" in violations[0].lower()

    def test_shell_interpreter_wrapper_rejected(self) -> None:
        cmd = ["bash", "-c", "curl example.com"]
        violations = CommandSafetyAuditor.audit_command(cmd)
        assert any("shell interpreter" in v.lower() for v in violations)

    def test_sqlmap_forbidden_flags_rejected(self) -> None:
        forbidden_calls = [
            ["sqlmap", "-u", "http://example.com", "--os-shell"],
            ["sqlmap", "-u", "http://example.com", "--sql-shell"],
            ["sqlmap", "-u", "http://example.com", "--dump-all"],
            ["sqlmap", "-u", "http://example.com", "--os-cmd=id"],
        ]
        for cmd in forbidden_calls:
            assert CommandSafetyAuditor.is_command_safe(cmd) is False
            violations = CommandSafetyAuditor.audit_command(cmd)
            assert any("forbidden destructive option" in v.lower() for v in violations)


class TestFileSecurityAuditor:
    """Tests for path traversal prevention and file permission auditing."""

    def test_path_traversal_detected(self, tmp_path: Path) -> None:
        base = tmp_path / "sandbox"
        base.mkdir()
        traversal_target = base / ".." / "escaped.txt"

        with pytest.raises(SecurityViolation):
            FileSecurityAuditor.validate_safe_path(traversal_target, base_directory=base)

    def test_safe_path_allowed(self, tmp_path: Path) -> None:
        base = tmp_path / "sandbox"
        base.mkdir()
        safe_target = base / "reports" / "report.json"

        resolved = FileSecurityAuditor.validate_safe_path(safe_target, base_directory=base)
        assert resolved == safe_target.resolve()

    def test_file_permissions_audit(self, tmp_path: Path) -> None:
        test_file = tmp_path / "secret.txt"
        test_file.write_text("sensitive")
        os.chmod(test_file, 0o666)  # world-writable & world-readable

        violations = FileSecurityAuditor.audit_file_permissions(test_file, max_mode=0o600)
        assert len(violations) > 0

        # Now restrict permissions
        os.chmod(test_file, 0o600)
        violations_secure = FileSecurityAuditor.audit_file_permissions(test_file, max_mode=0o600)
        assert len(violations_secure) == 0


class TestFrameworkSecurityAudit:
    """Tests for audit_framework_environment."""

    def test_environment_audit_runs(self) -> None:
        report = audit_framework_environment()
        assert report.checks_performed > 0
        data = report.to_dict()
        assert "checks_performed" in data
        assert "passed" in data
