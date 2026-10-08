"""Parser for Nmap XML and standard text output."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from reconx.core.runner import CommandResult
from reconx.models.network import (
    HostNetworkInfo,
    NmapResult,
    Port,
    ServiceInfo,
)

_RE_NMAP_REPORT = re.compile(r"^Nmap scan report for\s+(?:(\S+)\s+\(([\d\.]+)\)|(\S+))")
_RE_IPV4_ADDR = re.compile(r"^[\d\.]+$")
_RE_PORT_LINE = re.compile(r"^(\d+)/([a-z]+)\s+([a-z\|]+)\s+([^\s]+)(?:\s+(.*))?$", re.IGNORECASE)


class NmapParser:
    """Parses Nmap scan outputs into normalized NmapResult data structures."""

    def parse(self, output: CommandResult | str, target: str = "") -> NmapResult:
        """Parse Nmap output (XML format preferred, fallback to text)."""
        raw_text = output.stdout if isinstance(output, CommandResult) else str(output)
        clean = raw_text.strip()
        if not clean:
            return NmapResult(
                target=target,
                errors=("Empty Nmap output",),
                raw_output=raw_text,
            )

        # Detect XML format
        if clean.startswith("<?xml") or "<nmaprun" in clean:
            try:
                return self._parse_xml(clean, target=target)
            except ET.ParseError as pe:
                res = self._parse_text(clean, target=target)
                return NmapResult(
                    target=res.target or target,
                    hosts=res.hosts,
                    errors=res.errors + (f"XML parse error: {pe}",),
                    raw_output=raw_text,
                    scan_args=res.scan_args,
                )

        return self._parse_text(clean, target=target)

    def _parse_xml(self, xml_content: str, target: str = "") -> NmapResult:
        root = ET.fromstring(xml_content)
        scan_args = root.attrib.get("args", "")
        hosts: list[HostNetworkInfo] = []
        errors: list[str] = []

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            status = status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"

            hostname_val = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    h_name = hn.attrib.get("name")
                    if h_name:
                        hostname_val = h_name
                        break

            ipv4_val: str | None = None
            ipv6_val: str | None = None
            for addr_elem in host_elem.findall("address"):
                addr_type = addr_elem.attrib.get("addrtype")
                addr_str = addr_elem.attrib.get("addr")
                if addr_type == "ipv4":
                    ipv4_val = addr_str
                elif addr_type == "ipv6":
                    ipv6_val = addr_str

            host_ident = hostname_val or ipv4_val or ipv6_val or target or "unknown"

            # Parse ports
            ports_elem = host_elem.find("ports")
            port_records: list[Port] = []
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_id = int(port_elem.attrib.get("portid", 0))
                    protocol = port_elem.attrib.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    state = state_elem.attrib.get("state", "closed") if state_elem is not None else "closed"
                    reason = state_elem.attrib.get("reason") if state_elem is not None else None

                    # Service info
                    svc_elem = port_elem.find("service")
                    svc_info: ServiceInfo | None = None
                    if svc_elem is not None:
                        svc_name = svc_elem.attrib.get("name", "unknown")
                        product = svc_elem.attrib.get("product")
                        version = svc_elem.attrib.get("version")
                        extra_info = svc_elem.attrib.get("extrainfo")
                        tunnel = svc_elem.attrib.get("tunnel")
                        cpes = tuple(c.text for c in svc_elem.findall("cpe") if c.text)

                        svc_info = ServiceInfo(
                            name=svc_name,
                            product=product,
                            version=version,
                            extra_info=extra_info,
                            tunnel=tunnel,
                            cpe=cpes,
                        )

                    port_records.append(
                        Port(
                            port=port_id,
                            protocol=protocol,
                            state=state,
                            service=svc_info,
                            reason=reason,
                        )
                    )

            # OS match
            os_elem = host_elem.find("os")
            os_match_val: str | None = None
            if os_elem is not None:
                osmatch_elem = os_elem.find("osmatch")
                if osmatch_elem is not None:
                    os_match_val = osmatch_elem.attrib.get("name")

            hosts.append(
                HostNetworkInfo(
                    host=host_ident,
                    status=status,
                    ports=tuple(port_records),
                    ipv4=ipv4_val,
                    ipv6=ipv6_val,
                    os_match=os_match_val,
                )
            )

        return NmapResult(
            target=target or (hosts[0].host if hosts else ""),
            hosts=tuple(hosts),
            errors=tuple(errors),
            raw_output=xml_content,
            scan_args=scan_args,
        )

    def _parse_text(self, text_content: str, target: str = "") -> NmapResult:
        hosts: list[HostNetworkInfo] = []
        errors: list[str] = []
        current_host: str | None = None
        current_ipv4: str | None = None
        current_status: str = "up"
        current_ports: list[Port] = []

        for line in text_content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            if "Failed to resolve" in line_str or "QUITTING!" in line_str:
                errors.append(line_str)
                continue

            # Nmap scan report for example.com (93.184.216.34)
            # or: Nmap scan report for 93.184.216.34
            m_report = _RE_NMAP_REPORT.match(line_str)
            if m_report:
                if current_host is not None:
                    hosts.append(
                        HostNetworkInfo(
                            host=current_host,
                            status=current_status,
                            ports=tuple(current_ports),
                            ipv4=current_ipv4,
                        )
                    )
                    current_ports = []
                    current_status = "up"
                    current_ipv4 = None
                if m_report.group(1):
                    current_host = m_report.group(1)
                    current_ipv4 = m_report.group(2)
                else:
                    current_host = m_report.group(3)
                    if _RE_IPV4_ADDR.match(current_host):
                        current_ipv4 = current_host
                continue

            # Host is up (0.015s latency)
            if "Host is up" in line_str:
                current_status = "up"
                continue

            # PORT STATE SERVICE VERSION
            # 80/tcp open http Apache httpd 2.4.51
            # 443/tcp open ssl/http nginx 1.18.0
            m_port = _RE_PORT_LINE.match(line_str)
            if m_port:
                port_id = int(m_port.group(1))
                proto = m_port.group(2).lower()
                state = m_port.group(3).lower()
                raw_svc = m_port.group(4)
                version_info = m_port.group(5) or ""

                tunnel: str | None = None
                svc_name = raw_svc
                if "ssl/" in raw_svc.lower():
                    tunnel = "ssl"
                    svc_name = raw_svc.split("/")[-1]

                product: str | None = None
                version: str | None = None
                if version_info:
                    parts = version_info.split(maxsplit=1)
                    product = parts[0]
                    if len(parts) > 1:
                        version = parts[1]

                svc = ServiceInfo(
                    name=svc_name,
                    product=product,
                    version=version,
                    tunnel=tunnel,
                )
                current_ports.append(
                    Port(
                        port=port_id,
                        protocol=proto,
                        state=state,
                        service=svc,
                    )
                )

        if current_host is not None:
            hosts.append(
                HostNetworkInfo(
                    host=current_host,
                    status=current_status,
                    ports=tuple(current_ports),
                    ipv4=current_ipv4,
                )
            )
        elif current_ports:
            hosts.append(
                HostNetworkInfo(
                    host=target or "unknown",
                    status=current_status,
                    ports=tuple(current_ports),
                    ipv4=current_ipv4,
                )
            )

        return NmapResult(
            target=target or (hosts[0].host if hosts else ""),
            hosts=tuple(hosts),
            errors=tuple(errors),
            raw_output=text_content,
        )
