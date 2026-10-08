"""Registry for discovering, retrieving, and validating tool adapters."""

from __future__ import annotations

import logging
from typing import Iterator

from reconx.tools.base import ToolAdapter

logger = logging.getLogger("reconx.tools.registry")


class ToolRegistry:
    """Central registry for managing external tool adapters."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        """Register a tool adapter under its canonical name."""
        self._tools[adapter.name.lower()] = adapter

    def get(self, name: str) -> ToolAdapter | None:
        """Retrieve an adapter by name, or None if not registered."""
        return self._tools.get(name.lower())

    def require(self, name: str) -> ToolAdapter:
        """Retrieve an adapter by name, raising KeyError if not found."""
        tool = self.get(name)
        if tool is None:
            raise KeyError(f"Tool '{name}' is not registered")
        return tool

    def list_tools(self) -> list[str]:
        """Return a sorted list of registered tool names."""
        return sorted(self._tools.keys())

    def check_all(self) -> dict[str, bool]:
        """Check system availability for all registered tools."""
        return {name: adapter.check_available() for name, adapter in self._tools.items()}

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._tools

    def __iter__(self) -> Iterator[ToolAdapter]:
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)


def get_default_registry() -> ToolRegistry:
    """Construct and return a ToolRegistry pre-populated with default Phase 4-8 tools."""
    from reconx.tools.curl import CurlAdapter
    from reconx.tools.dig import DigAdapter
    from reconx.tools.dirb import DirbAdapter
    from reconx.tools.ffuf import FFUFAdapter
    from reconx.tools.gobuster import GobusterAdapter
    from reconx.tools.host import HostAdapter
    from reconx.tools.nikto import NiktoAdapter
    from reconx.tools.nmap import NmapAdapter
    from reconx.tools.nslookup import NslookupAdapter
    from reconx.tools.openssl import OpenSSLAdapter
    from reconx.tools.ping import PingAdapter
    from reconx.tools.sqlmap import SqlmapAdapter
    from reconx.tools.wget import WgetAdapter
    from reconx.tools.whois import WhoisAdapter

    registry = ToolRegistry()
    registry.register(DigAdapter())
    registry.register(HostAdapter())
    registry.register(NslookupAdapter())
    registry.register(WhoisAdapter())
    registry.register(PingAdapter())
    registry.register(OpenSSLAdapter())
    registry.register(NmapAdapter())
    registry.register(CurlAdapter())
    registry.register(WgetAdapter())
    registry.register(GobusterAdapter())
    registry.register(FFUFAdapter())
    registry.register(DirbAdapter())
    registry.register(NiktoAdapter())
    registry.register(SqlmapAdapter())
    return registry

