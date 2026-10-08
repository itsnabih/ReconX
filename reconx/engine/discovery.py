"""Discovery intelligence engine for ReconX.

Synthesizes multi-source discovery observations (ports, services, DNS, endpoints)
into structured domain inventories:
- Deduplicated web endpoints across gobuster, ffuf, dirb, curl
- Open ports and services across nmap, openssl
- Discovered hosts and DNS records across dig, host, nslookup, whois
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from reconx.engine.deduplication import normalize_url
from reconx.models.observation import Observation


@dataclass(frozen=True)
class DiscoveredEndpointSummary:
    """Canonical discovered endpoint aggregated across tools."""

    url: str
    path: str
    status_code: int | None
    content_length: int | None
    sources: tuple[str, ...]
    observation_ids: tuple[str, ...]


@dataclass(frozen=True)
class DiscoveredServiceSummary:
    """Canonical discovered network service on an asset."""

    port: int
    protocol: str
    service: str
    state: str
    sources: tuple[str, ...]
    observation_ids: tuple[str, ...]


@dataclass
class DiscoveryInventory:
    """Aggregated discovery inventory for an asset or scan."""

    endpoints: dict[str, DiscoveredEndpointSummary] = field(default_factory=dict)
    services: dict[int, DiscoveredServiceSummary] = field(default_factory=dict)
    subdomains: set[str] = field(default_factory=set)


class DiscoveryEngine:
    """Processes and correlates discovery observations into canonical inventories."""

    def process(self, observations: Sequence[Observation]) -> DiscoveryInventory:
        """Process discovery observations and produce deduplicated inventories."""
        inventory = DiscoveryInventory()

        # Temporary groupings for endpoints: canonical_url -> list[obs]
        endpoint_groups: dict[str, list[Observation]] = {}
        # Temporary groupings for services: port -> list[obs]
        service_groups: dict[int, list[Observation]] = {}

        for obs in observations:
            data = obs.data or {}
            obs_type = obs.type

            # 1. Endpoint discovery
            if obs_type in ("endpoint_discovery", "http_endpoint"):
                raw_url = data.get("url") or data.get("path") or ""
                target = data.get("target") or ""
                norm_url = normalize_url(raw_url, base_target=target)
                if norm_url:
                    endpoint_groups.setdefault(norm_url, []).append(obs)

            # 2. Port / service discovery
            elif obs_type == "open_port":
                port = data.get("port")
                if isinstance(port, int):
                    service_groups.setdefault(port, []).append(obs)

            # 3. DNS / subdomain discovery
            elif obs_type in ("dns_record", "subdomain_discovery"):
                host = data.get("host") or data.get("subdomain") or data.get("domain")
                if host and isinstance(host, str):
                    inventory.subdomains.add(host.lower().strip())

        # Synthesize endpoint summaries
        for norm_url, obs_list in endpoint_groups.items():
            sources = tuple(sorted({o.source for o in obs_list if o.source}))
            obs_ids = tuple(o.id for o in obs_list)
            first_data = obs_list[0].data or {}
            path = first_data.get("path") or norm_url
            status_code = first_data.get("status_code")
            content_length = first_data.get("content_length")

            inventory.endpoints[norm_url] = DiscoveredEndpointSummary(
                url=norm_url,
                path=path,
                status_code=status_code,
                content_length=content_length,
                sources=sources,
                observation_ids=obs_ids,
            )

        # Synthesize service summaries
        for port, obs_list in service_groups.items():
            sources = tuple(sorted({o.source for o in obs_list if o.source}))
            obs_ids = tuple(o.id for o in obs_list)
            first_data = obs_list[0].data or {}
            proto = first_data.get("protocol") or "tcp"
            svc = first_data.get("service") or "unknown"
            state = first_data.get("state") or "open"

            inventory.services[port] = DiscoveredServiceSummary(
                port=port,
                protocol=proto,
                service=svc,
                state=state,
                sources=sources,
                observation_ids=obs_ids,
            )

        return inventory
