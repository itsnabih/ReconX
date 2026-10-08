"""Security auditing, input validation, and guardrails engine (Phase 14).

Strictly adheres to Section 33 of Implementation.md:
- No shell injection / metacharacter prevention
- Target input sanitization and verification
- Command argument safety audit
- Path traversal defense
- File permission hardening (0600)
- Guardrails against destructive options
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path
import re
from typing import Any, Sequence
from urllib.parse import urlparse

# Shell metacharacters strictly disallowed in targets
DISALLOWED_TARGET_CHARS = frozenset({
    ";", "&", "|", "`", "$", "\n", "\r", ">", "<", "\x00", "\\", "'", '"', "(", ")", "{", "}", "[", "]",
})

# Destructive or unsafe offensive flags that must never be run autonomously
FORBIDDEN_COMMAND_FLAGS: dict[str, set[str]] = {
    "sqlmap": {
        "--os-shell",
        "--sql-shell",
        "--os-cmd",
        "--os-pwn",
        "--os-bof",
        "--priv-esc",
        "--dump-all",
    },
    "nmap": {
        "--interactive",
        "--script-updatedb",
    },
}

# Domain name regex complying with RFC 1035 / RFC 1123
_RE_DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class SecurityViolation(ValueError):
    """Raised when a security boundary, injection attempt, or unsafe option is detected."""


class TargetSecurityValidator:
    """Validates targets to ensure they cannot cause command injection or scope abuse."""

    @classmethod
    def is_safe_target(cls, target: str) -> bool:
        """Return True if target passes all security validation checks."""
        try:
            cls.validate_target(target)
            return True
        except SecurityViolation:
            return False

    @classmethod
    def validate_target(cls, target: str) -> None:
        """Validate target against command injection, metacharacters, and malformed inputs.

        Raises:
            SecurityViolation: if the target is unsafe or malformed.
        """
        clean = target.strip()
        if not clean:
            raise SecurityViolation("Target cannot be empty or whitespace only")

        # 1. Check for command flag injection (target starting with '-' or '/')
        if clean.startswith("-"):
            raise SecurityViolation(f"Target cannot start with a flag parameter: '{clean}'")

        # 2. Check for shell metacharacters
        found_chars = [c for c in clean if c in DISALLOWED_TARGET_CHARS]
        if found_chars:
            unique_chars = sorted(set(found_chars))
            raise SecurityViolation(
                f"Target contains disallowed shell metacharacters {unique_chars}: '{clean}'"
            )

        # 3. Check for embedded null bytes or control characters
        for ch in clean:
            if ord(ch) < 32 or ord(ch) == 127:
                raise SecurityViolation(f"Target contains invalid control character (ASCII {ord(ch)})")

        # 4. Syntactic validation: must be valid domain, IP, CIDR, or URL
        cls._validate_target_syntax(clean)

    @classmethod
    def _validate_target_syntax(cls, target: str) -> None:
        """Validate syntax: URL, CIDR, IP address, or domain name."""
        # Case A: URL
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            if not parsed.hostname:
                raise SecurityViolation(f"URL target has invalid hostname: '{target}'")
            # Validate the hostname portion
            cls._validate_host_or_ip(parsed.hostname)
            return

        # Case B: CIDR network
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return
            except ValueError:
                raise SecurityViolation(f"Invalid CIDR notation target: '{target}'")

        # Case C: Host with port (e.g., 192.168.18.107:8080 or example.com:8443)
        if ":" in target and not target.startswith("["):
            # Check if it's an IPv6 address or host:port
            try:
                ipaddress.IPv6Address(target)
                return
            except ValueError:
                pass

            parts = target.rsplit(":", 1)
            host_part, port_str = parts[0], parts[1]
            try:
                port_num = int(port_str)
                if not (1 <= port_num <= 65535):
                    raise SecurityViolation(f"Port number out of valid range (1-65535): '{port_str}'")
            except ValueError:
                raise SecurityViolation(f"Invalid port in target: '{port_str}'")

            cls._validate_host_or_ip(host_part)
            return

        # Case D: Single host, IPv4, or IPv6
        cls._validate_host_or_ip(target)

    @classmethod
    def _validate_host_or_ip(cls, host: str) -> None:
        # Check IP
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass

        # Check domain name
        if len(host) > 253:
            raise SecurityViolation(f"Domain name exceeds 253 characters: '{host}'")

        labels = host.rstrip(".").split(".")
        if len(labels) == 0:
            raise SecurityViolation(f"Invalid host label: '{host}'")

        for label in labels:
            if not label:
                raise SecurityViolation(f"Empty label in domain name: '{host}'")
            if not _RE_DOMAIN_LABEL.match(label):
                raise SecurityViolation(
                    f"Domain label '{label}' contains invalid characters in '{host}'"
                )


class CommandSafetyAuditor:
    """Audits process argument sequences to ensure no shell injection or dangerous flags exist."""

    @classmethod
    def is_command_safe(cls, command: Sequence[str]) -> bool:
        """Return True if command argument array passes all security audit rules."""
        return len(cls.audit_command(command)) == 0

    @classmethod
    def audit_command(cls, command: Sequence[str]) -> list[str]:
        """Audit command arguments for forbidden flags, shell wrappers, and malformations.

        Returns:
            List of violation descriptions (empty if safe).
        """
        violations: list[str] = []

        if not command:
            return ["Command argument sequence cannot be empty"]

        # Ensure all elements are strings
        for i, arg in enumerate(command):
            if not isinstance(arg, str):
                violations.append(f"Argument at index {i} is not a string: {type(arg).__name__}")
                continue

            if "\x00" in arg:
                violations.append(f"Argument at index {i} contains forbidden null byte")

        if violations:
            return violations

        executable = Path(command[0]).name.lower()

        # Check for disallowed shell wrapping
        if executable in {"sh", "bash", "zsh", "dash", "ksh", "cmd.exe", "powershell.exe"}:
            violations.append(
                f"Subprocess invoked via shell interpreter '{executable}' "
                "(violates Section 8/33 requirement for direct binary execution)"
            )

        # Check tool-specific dangerous flags
        forbidden_flags = FORBIDDEN_COMMAND_FLAGS.get(executable, set())
        for arg in command[1:]:
            arg_lower = arg.lower()
            for forbidden in forbidden_flags:
                if arg_lower == forbidden or arg_lower.startswith(f"{forbidden}="):
                    violations.append(
                        f"Forbidden destructive option '{arg}' for tool '{executable}' "
                        "(violates Section 33 safety boundary)"
                    )

        return violations


class FileSecurityAuditor:
    """Audits file paths and filesystem permissions for security compliance."""

    @staticmethod
    def validate_safe_path(path: str | Path, base_directory: str | Path | None = None) -> Path:
        """Validate path against directory traversal attacks.

        Raises:
            SecurityViolation: if path escapes base directory.
        """
        resolved = Path(path).resolve()
        if base_directory is not None:
            base_resolved = Path(base_directory).resolve()
            try:
                resolved.relative_to(base_resolved)
            except ValueError:
                raise SecurityViolation(
                    f"Path traversal detected: '{path}' resolves outside '{base_directory}'"
                )
        return resolved

    @staticmethod
    def audit_file_permissions(path: str | Path, max_mode: int = 0o600) -> list[str]:
        """Audit file permissions ensuring it is not world-readable/writable.

        Returns list of warnings/violations.
        """
        target = Path(path)
        if not target.exists():
            return [f"File '{target}' does not exist"]

        stat_info = target.stat()
        current_mode = stat_info.st_mode & 0o777

        violations: list[str] = []
        if (current_mode & 0o007) != 0:
            violations.append(
                f"File '{target}' is world-accessible (mode {oct(current_mode)}), expected {oct(max_mode)}"
            )
        if (current_mode & 0o070) > (max_mode & 0o070):
            violations.append(
                f"File '{target}' has excessive group permissions (mode {oct(current_mode)}), expected {oct(max_mode)}"
            )

        return violations


@dataclass
class SecurityAuditReport:
    """Consolidated audit report of system and framework security posture."""

    passed: bool
    checks_performed: int
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks_performed": self.checks_performed,
            "violations": list(self.violations),
            "warnings": list(self.warnings),
        }


def audit_framework_environment() -> SecurityAuditReport:
    """Run an automated security audit of framework runtime configurations and environment."""
    violations: list[str] = []
    warnings: list[str] = []
    checks = 0

    # 1. Check umask
    checks += 1
    current_umask = os.umask(0)
    os.umask(current_umask)
    if current_umask == 0:
        violations.append("System umask is 000 (creates world-writable files)")
    elif (current_umask & 0o002) == 0:
        warnings.append("System umask does not restrict other-write (risk of insecure file permissions)")

    # 2. Check environment for plaintext secrets
    checks += 1
    sensitive_keys = {"AWS_SECRET_ACCESS_KEY", "RECONX_API_KEY", "DATABASE_PASSWORD"}
    for key in sensitive_keys:
        if os.environ.get(key):
            warnings.append(f"Sensitive variable '{key}' is exposed in process environment")

    passed = len(violations) == 0
    return SecurityAuditReport(
        passed=passed,
        checks_performed=checks,
        violations=violations,
        warnings=warnings,
    )
