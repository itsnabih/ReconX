"""Unit tests for DNS parsers (dig, host, nslookup, whois) and normalization."""

from __future__ import annotations

from reconx.models.dns import DNSRecord
from reconx.parsers.dns import DigParser, HostParser, NslookupParser, WhoisParser


# Deterministic test fixture outputs for example.com
DIG_OUTPUT_EXAMPLE = """
; <<>> DiG 9.20.27-2-Debian <<>> example.com ANY
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
example.com.		300	IN	A	93.184.216.34
example.com.		300	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
example.com.		300	IN	MX	10 mail.example.com.
example.com.		300	IN	NS	ns1.example.com.
example.com.		300	IN	TXT	"v=spf1 -all" "google-site-verification=xyz"

;; Query time: 15 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
"""

HOST_OUTPUT_EXAMPLE = """
example.com has address 93.184.216.34
example.com has IPv6 address 2606:2800:220:1:248:1893:25c8:1946
example.com mail is handled by 10 mail.example.com.
example.com name server ns1.example.com.
example.com descriptive text "v=spf1 -allgoogle-site-verification=xyz"
"""

NSLOOKUP_OUTPUT_EXAMPLE = """
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
Name:	example.com
Address: 93.184.216.34
Name:	example.com
Address: 2606:2800:220:1:248:1893:25c8:1946
example.com	mail exchanger = 10 mail.example.com.
example.com	nameserver = ns1.example.com.
example.com	text = "v=spf1 -allgoogle-site-verification=xyz"
"""

WHOIS_OUTPUT_EXAMPLE = """
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar IANA ID: 376
Registrant Organization: Internet Assigned Numbers Authority
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
"""


class TestDNSRecordNormalization:
    """Tests that DNSRecord correctly normalizes domains, records, and formatting."""

    def test_name_and_target_normalized_lowercase_no_dot(self) -> None:
        rec = DNSRecord(
            name="EXAMPLE.COM.",
            record_type="cname",
            value="Target.Host.COM.",
            ttl=300,
        )
        assert rec.name == "example.com"
        assert rec.record_type == "CNAME"
        assert rec.value == "target.host.com"
        assert rec.ttl == 300

    def test_txt_record_unquotes(self) -> None:
        rec1 = DNSRecord(name="example.com", record_type="TXT", value='"v=spf1 -all"')
        assert rec1.value == "v=spf1 -all"

        rec2 = DNSRecord(name="example.com", record_type="TXT", value="'v=spf1 -all'")
        assert rec2.value == "v=spf1 -all"

    def test_to_dict(self) -> None:
        rec = DNSRecord(name="example.com", record_type="A", value="1.2.3.4", ttl=60)
        assert rec.to_dict() == {
            "name": "example.com",
            "record_type": "A",
            "value": "1.2.3.4",
            "ttl": 60,
            "priority": None,
        }


class TestDigParser:
    """Tests parsing of dig utility output."""

    def test_parse_success(self) -> None:
        parser = DigParser()
        result = parser.parse(DIG_OUTPUT_EXAMPLE, target="example.com")

        assert result.tool == "dig"
        assert result.target == "example.com"
        assert len(result.errors) == 0
        assert len(result.records) == 5

        record_types = [r.record_type for r in result.records]
        assert record_types == ["A", "AAAA", "MX", "NS", "TXT"]

        # Verify MX priority and target
        mx_record = next(r for r in result.records if r.record_type == "MX")
        assert mx_record.priority == 10
        assert mx_record.value == "mail.example.com"

        # Verify multi-segment TXT concatenation
        txt_record = next(r for r in result.records if r.record_type == "TXT")
        assert txt_record.value == "v=spf1 -allgoogle-site-verification=xyz"

    def test_parse_nxdomain(self) -> None:
        parser = DigParser()
        output = """
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 321
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
"""
        result = parser.parse(output, target="nonexistent.example")
        assert any("NXDOMAIN" in err for err in result.errors)
        assert len(result.records) == 0

    def test_parse_servfail(self) -> None:
        parser = DigParser()
        output = ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 999"
        result = parser.parse(output, target="broken.example")
        assert any("SERVFAIL" in err for err in result.errors)


class TestHostParser:
    """Tests parsing of host utility output."""

    def test_parse_success(self) -> None:
        parser = HostParser()
        result = parser.parse(HOST_OUTPUT_EXAMPLE, target="example.com")

        assert result.tool == "host"
        assert result.target == "example.com"
        assert len(result.errors) == 0
        assert len(result.records) == 5

        record_types = [r.record_type for r in result.records]
        assert record_types == ["A", "AAAA", "MX", "NS", "TXT"]

        mx = next(r for r in result.records if r.record_type == "MX")
        assert mx.priority == 10
        assert mx.value == "mail.example.com"

    def test_parse_not_found(self) -> None:
        parser = HostParser()
        output = "Host nonexistent.example not found: 3(NXDOMAIN)"
        result = parser.parse(output, target="nonexistent.example")
        assert len(result.errors) == 1
        assert "not found" in result.errors[0]
        assert len(result.records) == 0

    def test_parse_cname_and_soa(self) -> None:
        parser = HostParser()
        output = """
www.example.com is an alias for example.com.
example.com has SOA record ns1.example.com. admin.example.com. 2026100701 7200 3600 1209600 3600
"""
        result = parser.parse(output, target="www.example.com")
        assert len(result.records) == 2
        assert result.records[0].record_type == "CNAME"
        assert result.records[0].value == "example.com"
        assert result.records[1].record_type == "SOA"

    def test_parse_ptr(self) -> None:
        parser = HostParser()
        output = "34.216.184.93.in-addr.arpa domain name pointer example.com."
        result = parser.parse(output, target="34.216.184.93.in-addr.arpa")
        assert len(result.records) == 1
        assert result.records[0].record_type == "PTR"
        assert result.records[0].name == "34.216.184.93.in-addr.arpa"
        assert result.records[0].value == "example.com"


class TestNslookupParser:
    """Tests parsing of nslookup utility output."""

    def test_parse_success(self) -> None:
        parser = NslookupParser()
        result = parser.parse(NSLOOKUP_OUTPUT_EXAMPLE, target="example.com")

        assert result.tool == "nslookup"
        assert result.target == "example.com"
        assert len(result.errors) == 0
        assert len(result.records) == 5

        record_types = [r.record_type for r in result.records]
        assert record_types == ["A", "AAAA", "MX", "NS", "TXT"]

        mx = next(r for r in result.records if r.record_type == "MX")
        assert mx.priority == 10
        assert mx.value == "mail.example.com"

    def test_parse_server_cant_find(self) -> None:
        parser = NslookupParser()
        output = """
Server:		8.8.8.8
Address:	8.8.8.8#53

** server can't find nonexistent.example: NXDOMAIN
"""
        result = parser.parse(output, target="nonexistent.example")
        assert len(result.errors) == 1
        assert "can't find" in result.errors[0]

    def test_parse_ptr(self) -> None:
        parser = NslookupParser()
        output = """
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
34.216.184.93.in-addr.arpa	name = example.com.
"""
        result = parser.parse(output, target="34.216.184.93.in-addr.arpa")
        assert len(result.records) == 1
        assert result.records[0].record_type == "PTR"
        assert result.records[0].name == "34.216.184.93.in-addr.arpa"
        assert result.records[0].value == "example.com"


class TestPhase4AcceptanceCriteria:
    """Strict test verifying Phase 4 Acceptance Criteria:
    'All DNS tools produce the same normalized data structures.'
    """

    def test_dig_host_nslookup_produce_identical_normalized_records(self) -> None:
        dig_res = DigParser().parse(DIG_OUTPUT_EXAMPLE, target="example.com")
        host_res = HostParser().parse(HOST_OUTPUT_EXAMPLE, target="example.com")
        ns_res = NslookupParser().parse(NSLOOKUP_OUTPUT_EXAMPLE, target="example.com")

        # Strip TTL because host and nslookup standard outputs do not expose TTL
        def normalize_for_comparison(records: tuple[DNSRecord, ...]) -> set[tuple[str, str, str, int | None]]:
            return {(r.name, r.record_type, r.value, r.priority) for r in records}

        dig_normalized = normalize_for_comparison(dig_res.records)
        host_normalized = normalize_for_comparison(host_res.records)
        ns_normalized = normalize_for_comparison(ns_res.records)

        assert dig_normalized == host_normalized
        assert host_normalized == ns_normalized

        # Expected normalized tuples
        expected = {
            ("example.com", "A", "93.184.216.34", None),
            ("example.com", "AAAA", "2606:2800:220:1:248:1893:25c8:1946", None),
            ("example.com", "MX", "mail.example.com", 10),
            ("example.com", "NS", "ns1.example.com", None),
            ("example.com", "TXT", "v=spf1 -allgoogle-site-verification=xyz", None),
        }
        assert dig_normalized == expected

    def test_observation_conversion(self) -> None:
        dig_res = DigParser().parse(DIG_OUTPUT_EXAMPLE, target="example.com")
        observations = dig_res.to_observations(asset_id="asset-123", task_id="task-456")

        assert len(observations) == 5
        types = [obs.type for obs in observations]
        assert types == ["dns_a", "dns_aaaa", "dns_mx", "dns_ns", "dns_txt"]
        assert all(obs.asset_id == "asset-123" for obs in observations)
        assert all(obs.source == "dig" for obs in observations)
        assert all(obs.task_id == "task-456" for obs in observations)


class TestWhoisParser:
    """Tests parsing of whois registration output."""

    def test_parse_success(self) -> None:
        parser = WhoisParser()
        result = parser.parse(WHOIS_OUTPUT_EXAMPLE, query="example.com")

        assert result.tool == "whois"
        assert result.target == "example.com"
        assert result.whois is not None
        assert result.whois.domain == "example.com"
        assert result.whois.organization == "Internet Assigned Numbers Authority"
        assert result.whois.created_date == "1995-08-14T04:00:00Z"
        assert result.whois.expires_date == "2027-08-13T04:00:00Z"
        assert "a.iana-servers.net" in result.whois.name_servers
        assert "b.iana-servers.net" in result.whois.name_servers
        assert "clientDeleteProhibited" in result.whois.status

    def test_whois_to_observation(self) -> None:
        parser = WhoisParser()
        result = parser.parse(WHOIS_OUTPUT_EXAMPLE, query="example.com")
        observations = result.to_observations(asset_id="asset-999")

        assert len(observations) == 1
        obs = observations[0]
        assert obs.type == "whois"
        assert obs.asset_id == "asset-999"
        assert obs.source == "whois"
        assert obs.data["domain"] == "example.com"
