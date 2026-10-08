"""External reconnaissance tool adapters and registry."""

from reconx.tools.base import DNSToolAdapter, ToolAdapter
from reconx.tools.curl import CurlAdapter
from reconx.tools.dig import DigAdapter
from reconx.tools.diagnostics import (
    DiagnosticEngine,
    ToolDiagnosticItem,
    ToolDiagnosticReport,
    ToolStatus,
)
from reconx.tools.dirb import DirbAdapter
from reconx.tools.ffuf import FFUFAdapter
from reconx.tools.gobuster import GobusterAdapter
from reconx.tools.host import HostAdapter
from reconx.tools.http_engine import BaselineDetector, HTTPEngine
from reconx.tools.nikto import NiktoAdapter
from reconx.tools.nmap import NmapAdapter, generate_downstream_http_tasks
from reconx.tools.nslookup import NslookupAdapter
from reconx.tools.openssl import OpenSSLAdapter
from reconx.tools.ping import PingAdapter
from reconx.tools.registry import ToolRegistry, get_default_registry
from reconx.tools.sqlmap import SqlmapAdapter
from reconx.tools.wget import WgetAdapter
from reconx.tools.whois import WhoisAdapter

__all__ = [
    "BaselineDetector",
    "CurlAdapter",
    "DNSToolAdapter",
    "DiagnosticEngine",
    "DigAdapter",
    "DirbAdapter",
    "FFUFAdapter",
    "GobusterAdapter",
    "HTTPEngine",
    "HostAdapter",
    "NiktoAdapter",
    "NmapAdapter",
    "NslookupAdapter",
    "OpenSSLAdapter",
    "PingAdapter",
    "SqlmapAdapter",
    "ToolAdapter",
    "ToolDiagnosticItem",
    "ToolDiagnosticReport",
    "ToolRegistry",
    "ToolStatus",
    "WgetAdapter",
    "WhoisAdapter",
    "generate_downstream_http_tasks",
    "get_default_registry",
]

