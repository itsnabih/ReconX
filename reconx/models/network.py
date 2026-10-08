"""Normalized network service, port, ping, and TLS data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reconx.models.observation import Observation


class PortState(str, Enum):
    """Port state classification."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class TransportProtocol(str, Enum):
    """Transport layer protocol."""

    TCP = "tcp"
    UDP = "udp"


# Common HTTP/HTTPS service names and products
_HTTP_SERVICE_NAMES = frozenset({
    "http",
    "https",
    "http-proxy",
    "http-alt",
    "calibre-http",
    "web",
    "http-mgmt",
})
_HTTP_PRODUCTS = frozenset({
    "apache",
    "nginx",
    "iis",
    "lighttpd",
    "caddy",
    "envoy",
    "cloudflare",
    "gunicorn",
    "uvicorn",
    "express",
    "node.js",
    "tomcat",
    "jetty",
    "traefik",
})
_HTTP_DEFAULT_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 9443})


@dataclass(frozen=True)
class ServiceInfo:
    """Service details discovered on an open port."""

    name: str
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None
    cpe: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "tunnel": self.tunnel,
            "cpe": list(self.cpe),
        }


@dataclass(frozen=True)
class Port:
    """Network port scan result."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: ServiceInfo | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "protocol", self.protocol.strip().lower())
        object.__setattr__(self, "state", self.state.strip().lower())

    @property
    def is_http(self) -> bool:
        """Return True if this port runs an HTTP or HTTPS service."""
        if self.state != "open":
            return False

        if self.service is not None:
            svc_name = self.service.name.lower()
            if svc_name in _HTTP_SERVICE_NAMES:
                return True
            if self.service.tunnel and "ssl" in self.service.tunnel.lower() and "http" in svc_name:
                return True
            if self.service.product:
                prod_lower = self.service.product.lower()
                if any(p in prod_lower for p in _HTTP_PRODUCTS):
                    return True

        # Fallback for well-known web ports when service detection is inconclusive
        if self.service is None or self.service.name in ("unknown", ""):
            if self.port in _HTTP_DEFAULT_PORTS:
                return True

        return False

    @property
    def http_scheme(self) -> str:
        """Return 'https' if TLS is indicated, otherwise 'http'."""
        if self.service is not None:
            if self.service.name.lower() == "https":
                return "https"
            if self.service.tunnel and "ssl" in self.service.tunnel.lower():
                return "https"
        if self.port in (443, 8443, 9443):
            return "https"
        return "http"

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service.to_dict() if self.service else None,
            "reason": self.reason,
            "is_http": self.is_http,
            "http_scheme": self.http_scheme if self.is_http else None,
        }


@dataclass(frozen=True)
class HostNetworkInfo:
    """Host-level network scan results."""

    host: str
    status: str = "up"
    ports: tuple[Port, ...] = ()
    ipv4: str | None = None
    ipv6: str | None = None
    os_match: str | None = None

    @property
    def open_ports(self) -> tuple[Port, ...]:
        return tuple(p for p in self.ports if p.state == "open")

    @property
    def http_ports(self) -> tuple[Port, ...]:
        return tuple(p for p in self.open_ports if p.is_http)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "status": self.status,
            "ports": [p.to_dict() for p in self.ports],
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "os_match": self.os_match,
        }


@dataclass(frozen=True)
class NmapResult:
    """Structured result of an Nmap port and service scan."""

    target: str
    hosts: tuple[HostNetworkInfo, ...] = ()
    errors: tuple[str, ...] = ()
    raw_output: str = ""
    scan_args: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "hosts": [h.to_dict() for h in self.hosts],
            "errors": list(self.errors),
            "scan_args": self.scan_args,
        }

    def get_http_targets(self) -> list[dict[str, Any]]:
        """Extract all verified HTTP/HTTPS endpoints detected across all scanned hosts."""
        http_targets: list[dict[str, Any]] = []
        for host_info in self.hosts:
            host_val = host_info.ipv4 or host_info.host
            for port in host_info.http_ports:
                scheme = port.http_scheme
                http_targets.append({
                    "host": host_val,
                    "port": port.port,
                    "scheme": scheme,
                    "url": f"{scheme}://{host_val}:{port.port}" if port.port not in (80, 443) else f"{scheme}://{host_val}",
                    "service": port.service.name if port.service else scheme,
                })
        return http_targets

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert detected open ports and services into Phase 3 Observation models."""
        from reconx.models.observation import Observation

        observations: list[Observation] = []
        for host in self.hosts:
            for port in host.open_ports:
                # 1. Port observation
                observations.append(
                    Observation(
                        type="open_port",
                        asset_id=asset_id,
                        source="nmap",
                        data={
                            "host": host.host,
                            "port": port.port,
                            "protocol": port.protocol,
                            "state": port.state,
                            "service": port.service.name if port.service else "unknown",
                        },
                        task_id=task_id,
                    )
                )
                # 2. Service details observation
                if port.service:
                    observations.append(
                        Observation(
                            type="service",
                            asset_id=asset_id,
                            source="nmap",
                            data={
                                "host": host.host,
                                "port": port.port,
                                "service": port.service.name,
                                "product": port.service.product,
                                "version": port.service.version,
                                "extra_info": port.service.extra_info,
                                "cpe": list(port.service.cpe),
                            },
                            task_id=task_id,
                        )
                    )
        return observations


@dataclass(frozen=True)
class PingResult:
    """Result of an ICMP ping reachability check."""

    target: str
    is_alive: bool
    packets_transmitted: int = 0
    packets_received: int = 0
    packet_loss: float = 0.0
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    rtt_max_ms: float | None = None
    rtt_mdev_ms: float | None = None
    errors: tuple[str, ...] = ()
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "is_alive": self.is_alive,
            "packets_transmitted": self.packets_transmitted,
            "packets_received": self.packets_received,
            "packet_loss": self.packet_loss,
            "rtt_min_ms": self.rtt_min_ms,
            "rtt_avg_ms": self.rtt_avg_ms,
            "rtt_max_ms": self.rtt_max_ms,
            "rtt_mdev_ms": self.rtt_mdev_ms,
            "errors": list(self.errors),
        }

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert reachability check into an Observation model."""
        from reconx.models.observation import Observation

        return [
            Observation(
                type="host_status",
                asset_id=asset_id,
                source="ping",
                data={
                    "status": "alive" if self.is_alive else "unreachable",
                    "rtt_avg_ms": self.rtt_avg_ms,
                    "packet_loss": self.packet_loss,
                },
                task_id=task_id,
            )
        ]


@dataclass(frozen=True)
class TLSCertificate:
    """Normalized TLS certificate details."""

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    common_name: str | None = None
    san: tuple[str, ...] = ()
    valid_from: str | None = None
    valid_to: str | None = None
    is_expired: bool | None = None
    serial_number: str | None = None
    fingerprint_sha256: str | None = None
    signature_algorithm: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "san": list(self.san),
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "is_expired": self.is_expired,
            "serial_number": self.serial_number,
            "fingerprint_sha256": self.fingerprint_sha256,
            "signature_algorithm": self.signature_algorithm,
        }


@dataclass(frozen=True)
class TLSResult:
    """Result of an OpenSSL TLS connection probing."""

    target: str
    port: int = 443
    certificate: TLSCertificate | None = None
    protocol_version: str | None = None
    cipher: str | None = None
    errors: tuple[str, ...] = ()
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "protocol_version": self.protocol_version,
            "cipher": self.cipher,
            "errors": list(self.errors),
        }

    def to_observations(self, asset_id: str, task_id: str | None = None) -> list[Observation]:
        """Convert TLS certificate details into an Observation model."""
        from reconx.models.observation import Observation

        data: dict[str, Any] = {
            "port": self.port,
            "protocol_version": self.protocol_version,
            "cipher": self.cipher,
        }
        if self.certificate:
            data.update(self.certificate.to_dict())

        return [
            Observation(
                type="tls_certificate",
                asset_id=asset_id,
                source="openssl",
                data=data,
                task_id=task_id,
            )
        ]
