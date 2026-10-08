"""Secret and sensitive value redaction for security reports.

Ensures credentials, API keys, tokens, session cookies, and private keys
are redacted by default in report output per Implementation.md Section 28
and Agent-rules.md Section 22.
"""

from __future__ import annotations

from typing import Any
import re


# Regex patterns for sensitive patterns in strings
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    re.MULTILINE,
)

_BEARER_PATTERN = re.compile(
    r"(?i)(authorization:\s*bearer\s+)([A-Za-z0-9._~+/-]{8,}=*)",
)

_BASIC_AUTH_PATTERN = re.compile(
    r"(?i)(authorization:\s*basic\s+)([A-Za-z0-9+/=]{8,})",
)

_JWT_PATTERN = re.compile(
    r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b",
)

_KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|secret|secret_key|api_key|apikey|access_token|auth_token|token|private_token|client_secret|aws_secret_access_key)"
    r"(\s*[:=]\s*|\s*:\s*\"|\s*=\s*\")([^\"'\s&,;]{4,})",
)

_COOKIE_SECRET_PATTERN = re.compile(
    r"(?i)\b(phpsessid|jsessionid|sessionid|sess|remember_token|connect\.sid|auth_token|token)\s*=\s*([^\"'\s&,;]{6,})",
)

_AWS_ACCESS_KEY_PATTERN = re.compile(
    r"\b(AKIA[0-9A-Z]{16})\b",
)

_SENSITIVE_DICT_KEYS = {
    "password", "passwd", "pwd", "secret", "secret_key", "api_key",
    "apikey", "access_token", "auth_token", "token", "private_token",
    "client_secret", "aws_secret_access_key", "authorization",
    "cookie", "set-cookie", "private_key",
}


class SecretRedactor:
    """Detects and redacts sensitive data from report strings and structures."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def redact_text(self, text: str) -> str:
        """Redact sensitive patterns in arbitrary text."""
        if not self.enabled or not text:
            return text

        result = text

        # 1. Private keys
        result = _PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", result)

        # 2. JWT tokens
        result = _JWT_PATTERN.sub("[REDACTED_JWT]", result)

        # 3. Bearer tokens
        result = _BEARER_PATTERN.sub(r"\g<1>****************", result)

        # 4. Basic Auth
        result = _BASIC_AUTH_PATTERN.sub(r"\g<1>****************", result)

        # 5. AWS Access Key IDs
        result = _AWS_ACCESS_KEY_PATTERN.sub(r"AKIA****************", result)

        # 6. Sensitive cookies
        result = _COOKIE_SECRET_PATTERN.sub(r"\g<1>=********", result)

        # 7. Generic key=value or key: value secrets
        result = _KEY_VALUE_SECRET_PATTERN.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{'*' * min(max(len(m.group(3)), 8), 16)}",
            result,
        )

        return result

    def redact_data(self, data: Any) -> Any:
        """Recursively redact sensitive keys and values in nested data structures."""
        if not self.enabled:
            return data

        if isinstance(data, str):
            return self.redact_text(data)

        if isinstance(data, dict):
            redacted_dict: dict[str, Any] = {}
            for k, v in data.items():
                k_str = str(k).lower()
                if any(sens in k_str for sens in _SENSITIVE_DICT_KEYS):
                    redacted_dict[k] = "********"
                else:
                    redacted_dict[k] = self.redact_data(v)
            return redacted_dict

        if isinstance(data, list):
            return [self.redact_data(item) for item in data]

        if isinstance(data, tuple):
            return tuple(self.redact_data(item) for item in data)

        return data
