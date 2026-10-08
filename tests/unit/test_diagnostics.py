"""Unit tests for External Tool Diagnostics (Phase 14 / Section 31)."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from reconx.core.runner import CommandRunner
from reconx.tools.base import ToolAdapter
from reconx.tools.diagnostics import (
    DiagnosticEngine,
    ToolDiagnosticItem,
    ToolDiagnosticReport,
    ToolStatus,
)
from reconx.tools.registry import ToolRegistry


class DummyDiagnosableAdapter(ToolAdapter):
    """Mock adapter for testing diagnostic outcomes."""

    name = "dummytool"
    executable = "dummytool"

    def __init__(self, version_str: str = "v1.2.3", should_error: bool = False) -> None:
        super().__init__()
        self._version_str = version_str
        self._should_error = should_error

    async def version(self) -> str:
        if self._should_error:
            raise RuntimeError("Segmentation fault while probing version")
        return self._version_str

    def build_command(self, target: str, **kwargs: object) -> list[str]:
        return [self.executable, target]

    def parse_result(self, result: object, target: str = "") -> dict[str, str]:
        return {"status": "ok"}


class TestToolDiagnostics(unittest.IsolatedAsyncioTestCase):
    """Tests for ToolDiagnosticItem, ToolDiagnosticReport, and DiagnosticEngine."""

    def test_diagnostic_item_properties(self) -> None:
        item = ToolDiagnosticItem(
            name="curl",
            executable="curl",
            status=ToolStatus.AVAILABLE,
            path="/usr/bin/curl",
            version="curl 8.5.0",
        )
        assert item.is_healthy is True
        data = item.to_dict()
        assert data["name"] == "curl"
        assert data["status"] == "AVAILABLE"
        assert data["is_healthy"] is True

    def test_diagnostic_report_formatting(self) -> None:
        report = ToolDiagnosticReport(
            items=[
                ToolDiagnosticItem(
                    name="dig",
                    executable="dig",
                    status=ToolStatus.AVAILABLE,
                    path="/usr/bin/dig",
                    version="9.18.28",
                ),
                ToolDiagnosticItem(
                    name="nikto",
                    executable="nikto",
                    status=ToolStatus.MISSING,
                    path=None,
                    version="-",
                ),
                ToolDiagnosticItem(
                    name="sqlmap",
                    executable="sqlmap",
                    status=ToolStatus.BROKEN,
                    path="/usr/bin/sqlmap",
                    version="-",
                    error_message="Python syntax error in sqlmap",
                ),
            ]
        )

        assert report.total_tools == 3
        assert report.available_count == 1
        assert report.missing_count == 1
        assert report.broken_count == 1

        table = report.format_table()
        assert "Tool" in table
        assert "Status" in table
        assert "dig" in table
        assert "AVAILABLE" in table
        assert "nikto" in table
        assert "MISSING" in table
        assert "sqlmap" in table
        assert "BROKEN" in table
        assert "Summary: 3 tools checked" in table

    async def test_diagnostic_engine_detects_available_tool(self) -> None:
        registry = ToolRegistry()
        adapter = DummyDiagnosableAdapter(version_str="2.4.0")
        registry.register(adapter)

        engine = DiagnosticEngine(registry=registry)

        with patch("shutil.which", return_value="/usr/local/bin/dummytool"):
            item = await engine.check_tool(adapter)
            assert item.status == ToolStatus.AVAILABLE
            assert item.path == "/usr/local/bin/dummytool"
            assert item.version == "2.4.0"
            assert item.is_healthy is True

    async def test_diagnostic_engine_detects_missing_tool(self) -> None:
        registry = ToolRegistry()
        adapter = DummyDiagnosableAdapter()
        registry.register(adapter)

        engine = DiagnosticEngine(registry=registry)

        with patch("shutil.which", return_value=None):
            item = await engine.check_tool(adapter)
            assert item.status == ToolStatus.MISSING
            assert item.path is None
            assert item.is_healthy is False
            assert "not found" in (item.error_message or "")

    async def test_diagnostic_engine_detects_broken_tool(self) -> None:
        registry = ToolRegistry()
        adapter = DummyDiagnosableAdapter(should_error=True)
        registry.register(adapter)

        engine = DiagnosticEngine(registry=registry)

        with patch("shutil.which", return_value="/usr/bin/dummytool"):
            item = await engine.check_tool(adapter)
            assert item.status == ToolStatus.BROKEN
            assert item.path == "/usr/bin/dummytool"
            assert item.is_healthy is False
            assert "Version probe failed" in (item.error_message or "")

    async def test_diagnostic_engine_run_diagnostics_filter(self) -> None:
        registry = ToolRegistry()
        tool1 = DummyDiagnosableAdapter(version_str="1.0.0")
        tool1.name = "tool1"
        tool1.executable = "tool1"
        tool2 = DummyDiagnosableAdapter(version_str="2.0.0")
        tool2.name = "tool2"
        tool2.executable = "tool2"

        registry.register(tool1)
        registry.register(tool2)

        engine = DiagnosticEngine(registry=registry)

        with patch("shutil.which", return_value="/usr/bin/tool"):
            report = await engine.run_diagnostics(tool_names=["tool1"])
            assert report.total_tools == 1
            assert report.items[0].name == "tool1"
