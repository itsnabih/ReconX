"""Unit tests for network models and parsers (ping, tls, nmap)."""

from __future__ import annotations

from reconx.models.network import Port, ServiceInfo
from reconx.parsers.nmap import NmapParser
from reconx.parsers.ping import PingParser
from reconx.parsers.tls import TLSParser
from reconx.tools.nmap import NmapAdapter

# Deterministic Ping Fixture
PING_SUCCESS_OUTPUT = """
PING example.com (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=11.6 ms
64 bytes from 93.184.216.34: icmp_seq=2 ttl=56 time=11.7 ms
64 bytes from 93.184.216.34: icmp_seq=3 ttl=56 time=11.9 ms

--- example.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.590/11.750/11.950/0.147 ms
"""

PING_FAILURE_OUTPUT = """
PING nonexistent.example (192.0.2.1) 56(84) bytes of data.

--- nonexistent.example ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2048ms
"""

# Deterministic OpenSSL s_client Fixture
OPENSSL_S_CLIENT_OUTPUT = """
CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
verify return:1
---
Certificate chain
 0 s:CN = example.com
   i:C = US, O = DigiCert Inc, CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIQBAz5r2t56P+fF...
-----END CERTIFICATE-----
subject=C = US, ST = California, L = Los Angeles, O = Internet Assigned Numbers Authority, CN = example.com
issuer=C = US, O = DigiCert Inc, CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 3145 bytes and written 397 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
"""

# Deterministic Nmap XML Fixture
NMAP_XML_OUTPUT = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - example.com" start="1728290000">
<host starttime="1728290000" endtime="1728290005">
<status state="up" reason="syn-ack"/>
<address addr="93.184.216.34" addrtype="ipv4"/>
<hostnames>
<hostname name="example.com" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
  <state state="open" reason="syn-ack"/>
  <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux" method="probed"/>
</port>
<port protocol="tcp" portid="80">
  <state state="open" reason="syn-ack"/>
  <service name="http" product="Apache httpd" version="2.4.51" method="probed">
    <cpe>cpe:/a:apache:http_server:2.4.51</cpe>
  </service>
</port>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https" tunnel="ssl" product="Apache httpd" version="2.4.51" method="probed">
    <cpe>cpe:/a:apache:http_server:2.4.51</cpe>
  </service>
</port>
<port protocol="tcp" portid="3306">
  <state state="open" reason="syn-ack"/>
  <service name="mysql" product="MySQL" version="8.0.30" method="probed"/>
</port>
<port protocol="tcp" portid="8080">
  <state state="open" reason="syn-ack"/>
  <service name="http-proxy" product="Squid" version="4.13" method="probed"/>
</port>
</ports>
</host>
</nmaprun>
"""

# Deterministic Nmap Text Fixture
NMAP_TEXT_OUTPUT = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-07 10:00 UTC
Nmap scan report for example.com (93.184.216.34)
Host is up (0.015s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1
80/tcp   open  http       Apache httpd 2.4.51
443/tcp  open  ssl/http   nginx 1.18.0
3306/tcp open  mysql      MySQL 8.0.30
8080/tcp open  http-proxy Squid 4.13
"""


class TestPortAndServiceModel:
    """Tests for Port and ServiceInfo HTTP detection classification."""

    def test_http_service_classification(self) -> None:
        p_http = Port(port=80, service=ServiceInfo(name="http"))
        assert p_http.is_http is True
        assert p_http.http_scheme == "http"

        p_https = Port(port=443, service=ServiceInfo(name="https"))
        assert p_https.is_http is True
        assert p_https.http_scheme == "https"

        p_ssl_tunnel = Port(port=8443, service=ServiceInfo(name="http", tunnel="ssl"))
        assert p_ssl_tunnel.is_http is True
        assert p_ssl_tunnel.http_scheme == "https"

        p_alt = Port(port=8080, service=ServiceInfo(name="http-proxy"))
        assert p_alt.is_http is True

        p_product = Port(port=5000, service=ServiceInfo(name="unknown", product="Werkzeug/2.0 Python"))
        assert p_product.is_http is False  # not matching web server list

        p_nginx = Port(port=5000, service=ServiceInfo(name="custom", product="nginx 1.20"))
        assert p_nginx.is_http is True

    def test_non_http_services_rejected(self) -> None:
        p_ssh = Port(port=22, service=ServiceInfo(name="ssh", product="OpenSSH"))
        assert p_ssh.is_http is False

        p_dns = Port(port=53, protocol="udp", service=ServiceInfo(name="domain"))
        assert p_dns.is_http is False

        p_mysql = Port(port=3306, service=ServiceInfo(name="mysql"))
        assert p_mysql.is_http is False

        p_closed = Port(port=80, state="closed", service=ServiceInfo(name="http"))
        assert p_closed.is_http is False


class TestPingParser:
    """Tests for PingParser."""

    def test_parse_success(self) -> None:
        parser = PingParser()
        result = parser.parse(PING_SUCCESS_OUTPUT, target="example.com")

        assert result.target == "example.com"
        assert result.is_alive is True
        assert result.packets_transmitted == 3
        assert result.packets_received == 3
        assert result.packet_loss == 0.0
        assert result.rtt_min_ms == 11.590
        assert result.rtt_avg_ms == 11.750
        assert result.rtt_max_ms == 11.950
        assert result.rtt_mdev_ms == 0.147
        assert len(result.errors) == 0

    def test_parse_failure(self) -> None:
        parser = PingParser()
        result = parser.parse(PING_FAILURE_OUTPUT, target="nonexistent.example")

        assert result.target == "nonexistent.example"
        assert result.is_alive is False
        assert result.packets_transmitted == 3
        assert result.packets_received == 0
        assert result.packet_loss == 100.0
        assert result.rtt_avg_ms is None

    def test_to_observation(self) -> None:
        parser = PingParser()
        result = parser.parse(PING_SUCCESS_OUTPUT, target="example.com")
        observations = result.to_observations(asset_id="asset-1", task_id="task-10")

        assert len(observations) == 1
        obs = observations[0]
        assert obs.type == "host_status"
        assert obs.asset_id == "asset-1"
        assert obs.source == "ping"
        assert obs.data["status"] == "alive"
        assert obs.data["rtt_avg_ms"] == 11.750


class TestTLSParser:
    """Tests for TLSParser."""

    def test_parse_success(self) -> None:
        parser = TLSParser()
        result = parser.parse(OPENSSL_S_CLIENT_OUTPUT, target="example.com", port=443)

        assert result.target == "example.com"
        assert result.port == 443
        assert result.protocol_version == "TLSv1.3"
        assert result.cipher == "TLS_AES_256_GCM_SHA384"
        assert result.certificate is not None
        assert result.certificate.common_name == "example.com"
        assert result.certificate.issuer.get("O") == "DigiCert Inc"
        assert len(result.errors) == 0

    def test_parse_connection_refused(self) -> None:
        parser = TLSParser()
        output = "connect:errno=111\nconnect: Connection refused"
        result = parser.parse(output, target="127.0.0.1", port=443)

        assert len(result.errors) >= 1
        assert "Connection refused" in result.errors
        assert result.certificate is None

    def test_to_observation(self) -> None:
        parser = TLSParser()
        result = parser.parse(OPENSSL_S_CLIENT_OUTPUT, target="example.com", port=443)
        observations = result.to_observations(asset_id="asset-2")

        assert len(observations) == 1
        obs = observations[0]
        assert obs.type == "tls_certificate"
        assert obs.source == "openssl"
        assert obs.data["protocol_version"] == "TLSv1.3"
        assert obs.data["common_name"] == "example.com"


class TestNmapParser:
    """Tests for NmapParser."""

    def test_parse_xml_success(self) -> None:
        parser = NmapParser()
        result = parser.parse(NMAP_XML_OUTPUT, target="example.com")

        assert result.target == "example.com"
        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert host.host == "example.com"
        assert host.ipv4 == "93.184.216.34"
        assert host.status == "up"

        # 5 ports: 22, 80, 443, 3306, 8080
        assert len(host.ports) == 5
        assert len(host.open_ports) == 5

        # Check HTTP classification
        http_ports = host.http_ports
        assert len(http_ports) == 3
        port_numbers = [p.port for p in http_ports]
        assert port_numbers == [80, 443, 8080]

    def test_parse_text_fallback(self) -> None:
        parser = NmapParser()
        result = parser.parse(NMAP_TEXT_OUTPUT, target="example.com")

        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert len(host.ports) == 5
        assert len(host.http_ports) == 3

    def test_to_observations(self) -> None:
        parser = NmapParser()
        result = parser.parse(NMAP_XML_OUTPUT, target="example.com")
        observations = result.to_observations(asset_id="asset-web", task_id="task-nmap-1")

        # 5 open_port observations + 5 service observations = 10 observations
        assert len(observations) == 10
        types = [obs.type for obs in observations]
        assert types.count("open_port") == 5
        assert types.count("service") == 5


class TestPhase5AcceptanceCriteria:
    """Strict verification of Phase 5 Acceptance Criteria:
    'Nmap output can generate downstream HTTP tasks only when appropriate services are detected.'
    """

    def test_nmap_generates_downstream_http_tasks_only_when_appropriate_services_detected(self) -> None:
        parser = NmapParser()
        result = parser.parse(NMAP_XML_OUTPUT, target="example.com")

        adapter = NmapAdapter()
        downstream_tasks = adapter.generate_downstream_http_tasks(
            result=result,
            parent_task_id="task_nmap_scan_01",
            priority=15,
        )

        # Expected: exactly 3 tasks for ports 80, 443, 8080. Zero for 22 (ssh) or 3306 (mysql)!
        assert len(downstream_tasks) == 3

        task_ids = [t.id for t in downstream_tasks]
        assert "http_probe_93.184.216.34_80" in task_ids
        assert "http_probe_93.184.216.34_443" in task_ids
        assert "http_probe_93.184.216.34_8080" in task_ids
        assert not any("22" in tid for tid in task_ids)
        assert not any("3306" in tid for tid in task_ids)

        # Verify task properties
        for task in downstream_tasks:
            assert task.type == "http_probe"
            assert task.resource_class == "http"
            assert task.dependencies == {"task_nmap_scan_01"}
            assert task.priority == 15
            assert task.target.startswith(("http://", "https://"))

    def test_no_http_services_generates_zero_downstream_tasks(self) -> None:
        non_http_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="1728290000">
<host>
<status state="up"/>
<address addr="192.0.2.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="25"><state state="open"/><service name="smtp"/></port>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
</ports>
</host>
</nmaprun>
"""
        parser = NmapParser()
        result = parser.parse(non_http_xml, target="192.0.2.1")

        adapter = NmapAdapter()
        downstream_tasks = adapter.generate_downstream_http_tasks(result=result)

        assert len(downstream_tasks) == 0
