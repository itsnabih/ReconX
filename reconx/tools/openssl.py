"""Adapter for the `openssl` tool for TLS probing and certificate extraction."""

from __future__ import annotations

from typing import Any

from reconx.core.runner import CommandResult, CommandRunner
from reconx.models.network import TLSResult
from reconx.parsers.tls import TLSParser
from reconx.tools.base import ToolAdapter


class OpenSSLAdapter(ToolAdapter):
    """Adapter for the OpenSSL command line tool."""

    name = "openssl"
    executable = "openssl"
    resource_class = "network"

    def __init__(self, runner: CommandRunner | None = None, parser: TLSParser | None = None) -> None:
        super().__init__(runner=runner)
        self.parser = parser if parser is not None else TLSParser()

    async def version(self) -> str:
        """Query and return OpenSSL version information."""
        if not self.check_available():
            return "not_installed"
        res = await self.runner.run([self.executable, "version"], timeout=5.0)
        output = res.stdout.strip() or res.stderr.strip()
        if output:
            return output.splitlines()[0].strip()
        return "unknown"

    def build_command(
        self,
        target: str,
        port: int = 443,
        servername: str | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Build argument array for openssl s_client."""
        clean_target = target.strip()
        if not clean_target:
            raise ValueError("Target host or IP cannot be empty")
        if port <= 0 or port > 65535:
            raise ValueError(f"Invalid port number: {port}")

        sni = servername.strip() if servername else clean_target
        return [
            self.executable,
            "s_client",
            "-connect",
            f"{clean_target}:{port}",
            "-servername",
            sni,
        ]

    def parse_result(self, result: CommandResult | str, target: str = "", port: int = 443) -> TLSResult:
        """Parse raw output or CommandResult into normalized TLSResult."""
        if isinstance(result, CommandResult):
            raw = result.stdout
            tgt = target
            actual_port = port
            if not tgt and result.arguments:
                for idx, arg in enumerate(result.arguments):
                    if arg == "-connect" and idx + 1 < len(result.arguments):
                        conn_val = result.arguments[idx + 1]
                        if ":" in conn_val:
                            h, _, p = conn_val.partition(":")
                            tgt = h
                            if p.isdigit():
                                actual_port = int(p)
                        else:
                            tgt = conn_val
                        break

            parsed = self.parser.parse(raw, target=tgt, port=actual_port)
            errs = list(parsed.errors)
            if result.timed_out and "Command timed out" not in errs:
                errs.append("Command timed out")
            if result.cancelled and "Command cancelled" not in errs:
                errs.append("Command cancelled")
            if not result.success and result.stderr.strip() and result.stderr.strip() not in errs:
                errs.append(result.stderr.strip())

            return TLSResult(
                target=tgt,
                port=actual_port,
                certificate=parsed.certificate,
                protocol_version=parsed.protocol_version,
                cipher=parsed.cipher,
                errors=tuple(errs),
                raw_output=raw or result.stderr,
            )

        return self.parser.parse(result, target=target, port=port)
