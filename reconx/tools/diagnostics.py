"""External tool diagnostics and system availability checker (Phase 14).

Strictly adheres to Section 31 of Implementation.md:
- Tool availability check ('reconx tools check')
- Status classification: AVAILABLE, MISSING, BROKEN, UNKNOWN
- Diagnostic reporting with version and executable path detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import shutil
from typing import Any, Sequence

from reconx.core.runner import CommandRunner
from reconx.tools.base import ToolAdapter
from reconx.tools.registry import ToolRegistry, get_default_registry


class ToolStatus(str, Enum):
    """Status classification for external tools per Section 31."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    BROKEN = "BROKEN"
    UNKNOWN = "UNKNOWN"


@dataclass
class ToolDiagnosticItem:
    """Diagnostic details for a single tool adapter."""

    name: str
    executable: str
    status: ToolStatus
    path: str | None = None
    version: str = "-"
    error_message: str | None = None

    @property
    def is_healthy(self) -> bool:
        """True if the tool is ready for production execution."""
        return self.status == ToolStatus.AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        """Convert item to dictionary representation."""
        return {
            "name": self.name,
            "executable": self.executable,
            "status": self.status.value,
            "path": self.path,
            "version": self.version,
            "error_message": self.error_message,
            "is_healthy": self.is_healthy,
        }


@dataclass
class ToolDiagnosticReport:
    """Consolidated diagnostic report of all registered tools."""

    items: list[ToolDiagnosticItem] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_tools(self) -> int:
        return len(self.items)

    @property
    def available_count(self) -> int:
        return sum(1 for item in self.items if item.status == ToolStatus.AVAILABLE)

    @property
    def missing_count(self) -> int:
        return sum(1 for item in self.items if item.status == ToolStatus.MISSING)

    @property
    def broken_count(self) -> int:
        return sum(1 for item in self.items if item.status == ToolStatus.BROKEN)

    @property
    def unknown_count(self) -> int:
        return sum(1 for item in self.items if item.status == ToolStatus.UNKNOWN)

    def get_item(self, tool_name: str) -> ToolDiagnosticItem | None:
        """Lookup diagnostic item by tool name."""
        name_lower = tool_name.strip().lower()
        for item in self.items:
            if item.name.lower() == name_lower:
                return item
        return None

    def format_table(self) -> str:
        """Format the report into an aligned text table conforming to Section 31."""
        lines = [
            f"{'Tool':<12} {'Status':<12} {'Version':<22} {'Path'}",
            "-" * 72,
        ]

        # Sort alphabetically by tool name
        for item in sorted(self.items, key=lambda x: x.name.lower()):
            path_display = item.path or "-"
            lines.append(
                f"{item.name:<12} {item.status.value:<12} {item.version:<22} {path_display}"
            )

        lines.append("-" * 72)
        lines.append(
            f"Summary: {self.total_tools} tools checked "
            f"({self.available_count} AVAILABLE, "
            f"{self.missing_count} MISSING, "
            f"{self.broken_count} BROKEN)"
        )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to structured dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_tools": self.total_tools,
            "available_count": self.available_count,
            "missing_count": self.missing_count,
            "broken_count": self.broken_count,
            "unknown_count": self.unknown_count,
            "tools": [item.to_dict() for item in self.items],
        }


class DiagnosticEngine:
    """Performs system diagnostics on registered tools."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.registry = registry if registry is not None else get_default_registry()
        self.runner = runner if runner is not None else CommandRunner()

    async def check_tool(self, adapter: ToolAdapter) -> ToolDiagnosticItem:
        """Perform comprehensive availability and version diagnostics on a tool."""
        # 1. Resolve executable on system PATH
        resolved_path = shutil.which(adapter.executable)
        if not resolved_path:
            return ToolDiagnosticItem(
                name=adapter.name,
                executable=adapter.executable,
                status=ToolStatus.MISSING,
                path=None,
                version="-",
                error_message=f"Executable '{adapter.executable}' not found in system PATH",
            )

        # 2. Query version string safely
        try:
            version_str = await adapter.version()
            version_clean = version_str.strip() if version_str else "Unknown"

            # Check if version query indicated an error
            if "not installed" in version_clean.lower() or "not found" in version_clean.lower():
                return ToolDiagnosticItem(
                    name=adapter.name,
                    executable=adapter.executable,
                    status=ToolStatus.MISSING,
                    path=resolved_path,
                    version="-",
                    error_message=version_clean,
                )

            return ToolDiagnosticItem(
                name=adapter.name,
                executable=adapter.executable,
                status=ToolStatus.AVAILABLE,
                path=resolved_path,
                version=version_clean,
                error_message=None,
            )
        except Exception as exc:
            return ToolDiagnosticItem(
                name=adapter.name,
                executable=adapter.executable,
                status=ToolStatus.BROKEN,
                path=resolved_path,
                version="-",
                error_message=f"Version probe failed: {exc}",
            )

    async def run_diagnostics(
        self,
        tool_names: Sequence[str] | None = None,
    ) -> ToolDiagnosticReport:
        """Run diagnostics on all or specified tools."""
        selected_adapters: list[ToolAdapter] = []

        if tool_names:
            requested = {n.strip().lower() for n in tool_names}
            for adapter in self.registry:
                if adapter.name.lower() in requested:
                    selected_adapters.append(adapter)
        else:
            selected_adapters = list(self.registry)

        # Diagnose tools
        items: list[ToolDiagnosticItem] = []
        for adapter in selected_adapters:
            item = await self.check_tool(adapter)
            items.append(item)

        return ToolDiagnosticReport(items=items)
