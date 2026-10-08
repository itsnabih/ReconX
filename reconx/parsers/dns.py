"""Parsers for DNS and WHOIS tools (dig, host, nslookup, whois)."""

from __future__ import annotations

import re

from reconx.models.dns import DNSRecord, DNSResult, WhoisRecord

# Standard supported DNS record types
_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR"})


def _clean_quotes(text: str) -> str:
    cleaned = text.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ):
        return cleaned[1:-1]
    return cleaned


class DigParser:
    """Parses standard DiG output into normalized DNSResult."""

    def parse(self, output: str, target: str = "") -> DNSResult:
        records: list[DNSRecord] = []
        errors: list[str] = []

        # Check for server or status error
        for line in output.splitlines():
            line_str = line.strip()
            if "status: NXDOMAIN" in line_str:
                errors.append(f"Domain '{target}' does not exist (NXDOMAIN)")
            elif "status: SERVFAIL" in line_str:
                errors.append("Server failure (SERVFAIL)")
            elif "status: REFUSED" in line_str:
                errors.append("Query refused (REFUSED)")
            elif line_str.startswith(";;") and ("connection timed out" in line_str.lower() or "no servers could be reached" in line_str.lower()):
                errors.append(line_str.lstrip(";").strip())

        # Regex for dig answer lines: <name> <ttl>? <class>? <type> <rest...>
        # Example: example.com. 300 IN A 93.184.216.34
        # or: example.com. IN A 93.184.216.34
        for line in output.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith(";"):
                continue

            parts = line_str.split()
            if len(parts) < 3:
                continue

            name = parts[0]
            ttl: int | None = None
            type_idx = 1

            # Check if second token is numeric TTL
            if parts[1].isdigit():
                ttl = int(parts[1])
                type_idx = 2

            # Check if class is present (usually IN, CH, etc.)
            if type_idx < len(parts) and parts[type_idx].upper() in ("IN", "CH", "HS"):
                type_idx += 1

            if type_idx >= len(parts):
                continue

            record_type = parts[type_idx].upper()
            if record_type not in _RECORD_TYPES:
                continue

            rest = parts[type_idx + 1 :]
            if not rest:
                continue

            if record_type == "MX":
                priority: int | None = None
                if rest[0].isdigit():
                    priority = int(rest[0])
                    val = " ".join(rest[1:])
                else:
                    val = " ".join(rest)
                records.append(DNSRecord(name=name, record_type=record_type, value=val, ttl=ttl, priority=priority))
            elif record_type == "TXT":
                raw_txt = " ".join(rest)
                # Dig can split TXT into multiple quoted segments e.g. "seg1" "seg2"
                txt_segments = re.findall(r'"([^"]*)"', raw_txt)
                val = "".join(txt_segments) if txt_segments else _clean_quotes(raw_txt)
                records.append(DNSRecord(name=name, record_type=record_type, value=val, ttl=ttl))
            elif record_type == "SOA":
                val = " ".join(rest)
                records.append(DNSRecord(name=name, record_type=record_type, value=val, ttl=ttl))
            else:
                val = rest[0]
                records.append(DNSRecord(name=name, record_type=record_type, value=val, ttl=ttl))

        return DNSResult(
            tool="dig",
            target=target,
            records=tuple(records),
            errors=tuple(errors),
            raw_output=output,
        )


class HostParser:
    """Parses standard `host` utility output into normalized DNSResult."""

    def parse(self, output: str, target: str = "") -> DNSResult:
        records: list[DNSRecord] = []
        errors: list[str] = []

        for line in output.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith(";"):
                continue

            if "not found:" in line_str or "no servers could be reached" in line_str.lower():
                errors.append(line_str)
                continue

            # 1. <name> has address <ip>
            m_a = re.match(r"^(\S+)\s+has address\s+(\S+)$", line_str, re.IGNORECASE)
            if m_a:
                records.append(DNSRecord(name=m_a.group(1), record_type="A", value=m_a.group(2)))
                continue

            # 2. <name> has IPv6 address <ip>
            m_aaaa = re.match(r"^(\S+)\s+has IPv6 address\s+(\S+)$", line_str, re.IGNORECASE)
            if m_aaaa:
                records.append(DNSRecord(name=m_aaaa.group(1), record_type="AAAA", value=m_aaaa.group(2)))
                continue

            # 3. <name> mail is handled by <prio> <host>
            m_mx = re.match(r"^(\S+)\s+mail is handled by\s+(\d+)\s+(\S+)$", line_str, re.IGNORECASE)
            if m_mx:
                records.append(
                    DNSRecord(
                        name=m_mx.group(1),
                        record_type="MX",
                        value=m_mx.group(3),
                        priority=int(m_mx.group(2)),
                    )
                )
                continue

            # 4. <name> name server <host>
            m_ns = re.match(r"^(\S+)\s+name server\s+(\S+)$", line_str, re.IGNORECASE)
            if m_ns:
                records.append(DNSRecord(name=m_ns.group(1), record_type="NS", value=m_ns.group(2)))
                continue

            # 5. <name> descriptive text <txt>
            m_txt = re.match(r"^(\S+)\s+descriptive text\s+(.+)$", line_str, re.IGNORECASE)
            if m_txt:
                records.append(
                    DNSRecord(name=m_txt.group(1), record_type="TXT", value=_clean_quotes(m_txt.group(2)))
                )
                continue

            # 6. <name> is an alias for <host>
            m_cname = re.match(r"^(\S+)\s+is an alias for\s+(\S+)$", line_str, re.IGNORECASE)
            if m_cname:
                records.append(DNSRecord(name=m_cname.group(1), record_type="CNAME", value=m_cname.group(2)))
                continue

            # 7. <name> has SOA record <soa...>
            m_soa = re.match(r"^(\S+)\s+has SOA record\s+(.+)$", line_str, re.IGNORECASE)
            if m_soa:
                records.append(DNSRecord(name=m_soa.group(1), record_type="SOA", value=m_soa.group(2)))
                continue

            # 8. <name> domain name pointer <host> (PTR)
            m_ptr = re.match(r"^(\S+)\s+domain name pointer\s+(\S+)$", line_str, re.IGNORECASE)
            if m_ptr:
                records.append(DNSRecord(name=m_ptr.group(1), record_type="PTR", value=m_ptr.group(2)))
                continue

        return DNSResult(
            tool="host",
            target=target,
            records=tuple(records),
            errors=tuple(errors),
            raw_output=output,
        )


class NslookupParser:
    """Parses standard `nslookup` utility output into normalized DNSResult."""

    def parse(self, output: str, target: str = "") -> DNSResult:
        records: list[DNSRecord] = []
        errors: list[str] = []

        lines = output.splitlines()
        in_answer_section = False
        current_name: str | None = None

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            if "can't find" in line_str or "server can't find" in line_str or "no servers could be reached" in line_str.lower():
                errors.append(line_str)
                continue

            if line_str.startswith("Server:") or line_str.startswith("Address:") and not in_answer_section:
                continue

            if "Non-authoritative answer:" in line_str or "Authoritative answers can be found from:" in line_str:
                in_answer_section = True
                continue

            # Canonical name / CNAME: <name> canonical name = <host>
            m_cname = re.match(r"^(\S+)\s+canonical name\s*=\s*(\S+)$", line_str, re.IGNORECASE)
            if m_cname:
                records.append(DNSRecord(name=m_cname.group(1), record_type="CNAME", value=m_cname.group(2)))
                continue

            # Mail exchanger / MX: <name> mail exchanger = <prio> <host>
            m_mx = re.match(r"^(\S+)\s+mail exchanger\s*=\s*(\d+)\s+(\S+)$", line_str, re.IGNORECASE)
            if m_mx:
                records.append(
                    DNSRecord(
                        name=m_mx.group(1),
                        record_type="MX",
                        value=m_mx.group(3),
                        priority=int(m_mx.group(2)),
                    )
                )
                continue

            # Nameserver / NS: <name> nameserver = <host>
            m_ns = re.match(r"^(\S+)\s+nameserver\s*=\s*(\S+)$", line_str, re.IGNORECASE)
            if m_ns:
                records.append(DNSRecord(name=m_ns.group(1), record_type="NS", value=m_ns.group(2)))
                continue

            # TXT: <name> text = <txt>
            m_txt = re.match(r"^(\S+)\s+text\s*=\s*(.+)$", line_str, re.IGNORECASE)
            if m_txt:
                records.append(
                    DNSRecord(name=m_txt.group(1), record_type="TXT", value=_clean_quotes(m_txt.group(2)))
                )
                continue

            # PTR: <name> name = <host>
            m_ptr = re.match(r"^(\S+)\s+name\s*=\s*(\S+)$", line_str, re.IGNORECASE)
            if m_ptr:
                records.append(DNSRecord(name=m_ptr.group(1), record_type="PTR", value=m_ptr.group(2)))
                continue

            # SOA origin: origin = <host>
            m_origin = re.match(r"^origin\s*=\s*(\S+)$", line_str, re.IGNORECASE)
            if m_origin and current_name:
                records.append(DNSRecord(name=current_name, record_type="SOA", value=m_origin.group(1)))
                continue

            # Standard Address format:
            # Name: example.com
            # Address: 93.184.216.34
            m_name = re.match(r"^Name:\s*(\S+)$", line_str, re.IGNORECASE)
            if m_name:
                current_name = m_name.group(1)
                continue

            m_addr = re.match(r"^Address:\s*(\S+)(?:#\d+)?$", line_str, re.IGNORECASE)
            if m_addr and current_name:
                addr_val = m_addr.group(1)
                rtype = "AAAA" if ":" in addr_val else "A"
                records.append(DNSRecord(name=current_name, record_type=rtype, value=addr_val))
                continue

        return DNSResult(
            tool="nslookup",
            target=target,
            records=tuple(records),
            errors=tuple(errors),
            raw_output=output,
        )


class WhoisParser:
    """Parses WHOIS lookup output into normalized WhoisRecord."""

    def parse(self, output: str, query: str = "") -> DNSResult:
        domain: str | None = None
        registrar: str | None = None
        organization: str | None = None
        asn: str | None = None
        created_date: str | None = None
        expires_date: str | None = None
        name_servers: list[str] = []
        status: list[str] = []
        errors: list[str] = []

        if not output.strip():
            errors.append("Empty WHOIS response")

        for line in output.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("%") or line_str.startswith("#"):
                continue

            if ":" not in line_str:
                continue

            key, _, val = line_str.partition(":")
            key = key.strip().lower()
            val = val.strip()

            if not val:
                continue

            if key in ("domain name", "domain"):
                if domain is None:
                    domain = val.lower()
            elif key in ("registrar", "sponsoring registrar"):
                if registrar is None:
                    registrar = val
            elif key in ("organization", "org-name", "orgname", "registrant organization"):
                if organization is None:
                    organization = val
            elif key in ("originas", "origin", "aut-num"):
                if asn is None:
                    asn = val
            elif key in ("creation date", "created", "regdate", "registered"):
                if created_date is None:
                    created_date = val
            elif key in ("registry expiry date", "registrar registration expiration date", "paid-till", "expires"):
                if expires_date is None:
                    expires_date = val
            elif key in ("name server", "nserver"):
                # Extract host token (e.g. "ns1.example.com 192.0.2.1" -> "ns1.example.com")
                ns_host = val.split()[0].lower().rstrip(".")
                if ns_host not in name_servers:
                    name_servers.append(ns_host)
            elif key in ("domain status", "status"):
                status_code = val.split()[0]
                if status_code not in status:
                    status.append(status_code)

        whois_rec = WhoisRecord(
            query=query,
            domain=domain,
            registrar=registrar,
            organization=organization,
            asn=asn,
            created_date=created_date,
            expires_date=expires_date,
            name_servers=tuple(name_servers),
            status=tuple(status),
            raw_text=output,
        )

        return DNSResult(
            tool="whois",
            target=query,
            records=(),
            whois=whois_rec,
            errors=tuple(errors),
            raw_output=output,
        )
