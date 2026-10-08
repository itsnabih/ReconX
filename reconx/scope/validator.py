"""Central scope enforcement for targets, redirects, and discovered assets.

Matching semantics:
- "example.com" matches exactly that host, not its subdomains.
- "*.example.com" matches any subdomain of example.com, not example.com itself.
- IP entries are single addresses or CIDR networks.
- Exclusions always take precedence over allowed entries.
- Hostnames are not resolved; domain rules apply to hostnames and IP rules to IP addresses.

The validator is immutable after construction, so discovered data can never expand scope.
Anything that cannot be parsed unambiguously is rejected (fail closed).
"""

from __future__ import annotations

from collections.abc import Iterable
import ipaddress
import re
from urllib.parse import urljoin, urlsplit

from reconx.scope.models import ScopeDecision, ScopeReason

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# Final labels that system resolvers may read as legacy numeric IPv4 forms ("127.1", "0x7f000001").
_NUMERIC_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")
_UNSAFE_CHARS_RE = re.compile(r"[\s\\\x00-\x1f\x7f]")
_REDIRECT_SCHEMES = frozenset({"http", "https"})


def _normalize_hostname(value: str) -> str:
    host = value[:-1] if value.endswith(".") else value
    host = host.lower()
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"invalid internationalized hostname {value!r}") from exc
    if not host or len(host) > 253:
        raise ValueError(f"invalid hostname length {value!r}")
    labels = host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ValueError(f"invalid hostname {value!r}")
    if _NUMERIC_LABEL_RE.match(labels[-1]):
        raise ValueError(f"ambiguous numeric hostname {value!r}")
    return host


def _parse_ip(value: str) -> IPAddress | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id is not None:
            raise ValueError(f"scoped IPv6 addresses are not supported {value!r}")
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
    return ip


def _host_from_url(url: str, original: str) -> str:
    parts = urlsplit(url)
    _ = parts.port  # raises ValueError for malformed or out-of-range ports
    if not parts.hostname:
        raise ValueError(f"no host in target {original!r}")
    return parts.hostname


def _parse_host(target: str) -> IPAddress | str:
    """Extract the host from a hostname, IP, host:port, or absolute URL."""
    candidate = target.strip()
    if not candidate:
        raise ValueError("empty target")
    if _UNSAFE_CHARS_RE.search(candidate):
        raise ValueError(f"target contains whitespace, backslash or control characters {target!r}")

    if "://" in candidate:
        host = _host_from_url(candidate, target)
    else:
        ip = _parse_ip(candidate)
        if ip is not None:
            return ip
        # Paths, CIDR ranges and userinfo are ambiguous without a scheme.
        if any(char in candidate for char in "/?#@"):
            raise ValueError(f"target must be a host, host:port or absolute URL {target!r}")
        host = _host_from_url("//" + candidate, target)

    ip = _parse_ip(host)
    if ip is not None:
        return ip
    return _normalize_hostname(host)


def _compile_domains(patterns: Iterable[str]) -> tuple[frozenset[str], frozenset[str]]:
    exact: set[str] = set()
    wildcard_suffixes: set[str] = set()
    for raw in patterns:
        pattern = raw.strip()
        try:
            if pattern.startswith("*."):
                wildcard_suffixes.add(_normalize_hostname(pattern[2:]))
            elif "*" in pattern:
                raise ValueError("only a leading '*.' wildcard is supported")
            else:
                exact.add(_normalize_hostname(pattern))
        except ValueError as exc:
            raise ValueError(f"invalid scope domain {raw!r}: {exc}") from exc
    return frozenset(exact), frozenset(wildcard_suffixes)


def _compile_networks(entries: Iterable[str]) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []
    for raw in entries:
        try:
            networks.append(ipaddress.ip_network(raw.strip(), strict=True))
        except ValueError as exc:
            raise ValueError(f"invalid scope IP/CIDR {raw!r}: {exc}") from exc
    return tuple(networks)


def _match_domain(host: str, exact: frozenset[str], suffixes: frozenset[str]) -> str | None:
    if host in exact:
        return host
    labels = host.split(".")
    for index in range(1, len(labels)):
        suffix = ".".join(labels[index:])
        if suffix in suffixes:
            return f"*.{suffix}"
    return None


def _match_ip(ip: IPAddress, networks: tuple[IPNetwork, ...]) -> str | None:
    for network in networks:
        if ip.version == network.version and ip in network:
            return str(network)
    return None


class ScopeValidator:
    """Immutable, centrally enforced scope policy."""

    def __init__(
        self,
        allowed_domains: Iterable[str] = (),
        allowed_ips: Iterable[str] = (),
        excluded_domains: Iterable[str] = (),
        excluded_ips: Iterable[str] = (),
    ) -> None:
        self._allowed_exact, self._allowed_suffixes = _compile_domains(allowed_domains)
        self._excluded_exact, self._excluded_suffixes = _compile_domains(excluded_domains)
        self._allowed_networks = _compile_networks(allowed_ips)
        self._excluded_networks = _compile_networks(excluded_ips)
        if not (self._allowed_exact or self._allowed_suffixes or self._allowed_networks):
            raise ValueError("scope must define at least one allowed domain or IP")

    def check(self, target: str) -> ScopeDecision:
        """Validate a user-provided or discovered target before any active interaction."""
        try:
            host = _parse_host(target)
        except ValueError as exc:
            return ScopeDecision(target, False, ScopeReason.INVALID_TARGET, detail=str(exc))

        if isinstance(host, str):
            rule = _match_domain(host, self._excluded_exact, self._excluded_suffixes)
            if rule is not None:
                return ScopeDecision(target, False, ScopeReason.EXCLUDED_DOMAIN, host, rule)
            rule = _match_domain(host, self._allowed_exact, self._allowed_suffixes)
            if rule is not None:
                return ScopeDecision(target, True, ScopeReason.ALLOWED_DOMAIN, host, rule)
            return ScopeDecision(target, False, ScopeReason.NOT_IN_SCOPE, host)

        host_text = str(host)
        rule = _match_ip(host, self._excluded_networks)
        if rule is not None:
            return ScopeDecision(target, False, ScopeReason.EXCLUDED_IP, host_text, rule)
        rule = _match_ip(host, self._allowed_networks)
        if rule is not None:
            return ScopeDecision(target, True, ScopeReason.ALLOWED_IP, host_text, rule)
        return ScopeDecision(target, False, ScopeReason.NOT_IN_SCOPE, host_text)

    def check_redirect(self, source_url: str, location: str) -> ScopeDecision:
        """Validate an HTTP redirect target, resolving relative Location values against the source."""
        if _UNSAFE_CHARS_RE.search(source_url) or _UNSAFE_CHARS_RE.search(location):
            return ScopeDecision(
                location, False, ScopeReason.INVALID_TARGET,
                detail="redirect contains whitespace, backslash or control characters",
            )
        if urlsplit(source_url).scheme.lower() not in _REDIRECT_SCHEMES:
            return ScopeDecision(
                location, False, ScopeReason.INVALID_TARGET,
                detail=f"redirect source is not an absolute http(s) URL {source_url!r}",
            )
        try:
            resolved = urljoin(source_url, location)
        except ValueError as exc:
            return ScopeDecision(location, False, ScopeReason.INVALID_TARGET, detail=str(exc))
        scheme = urlsplit(resolved).scheme.lower()
        if scheme not in _REDIRECT_SCHEMES:
            return ScopeDecision(
                resolved, False, ScopeReason.DISALLOWED_SCHEME,
                detail=f"redirect scheme {scheme!r} is not http(s)",
            )
        return self.check(resolved)
