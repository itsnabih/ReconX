"""Parser for OpenSSL TLS connection and certificate outputs."""

from __future__ import annotations

import re

from reconx.models.network import TLSCertificate, TLSResult


def _parse_dn(dn_str: str) -> dict[str, str]:
    """Parse Distinguished Name string like 'C = US, O = Example, CN = host.com' into dict."""
    parts: dict[str, str] = {}
    for item in dn_str.split(","):
        if "=" in item:
            k, _, v = item.partition("=")
            parts[k.strip()] = v.strip()
    return parts


class TLSParser:
    """Parses `openssl s_client` output into normalized TLSResult."""

    def parse(self, output: str, target: str = "", port: int = 443) -> TLSResult:
        errors: list[str] = []
        subject_dict: dict[str, str] = {}
        issuer_dict: dict[str, str] = {}
        common_name: str | None = None
        sans: list[str] = []
        protocol_version: str | None = None
        cipher: str | None = None
        valid_from: str | None = None
        valid_to: str | None = None

        if not output.strip():
            errors.append("Empty OpenSSL output")
            return TLSResult(
                target=target,
                port=port,
                errors=tuple(errors),
                raw_output=output,
            )

        for line in output.splitlines():
            line_str = line.strip()

            # Error detection
            if "Connection refused" in line_str or "connect:errno=" in line_str:
                errors.append("Connection refused")
            elif "handshake failure" in line_str.lower():
                errors.append("TLS handshake failure")
            elif "no peer certificate available" in line_str.lower():
                errors.append("No peer certificate available")

            # Protocol and Cipher lines:
            # Protocol  : TLSv1.3
            # Cipher    : TLS_AES_256_GCM_SHA384
            # or: New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
            m_proto = re.match(r"^Protocol\s*:\s*(\S+)$", line_str, re.IGNORECASE)
            if m_proto:
                protocol_version = m_proto.group(1)

            m_cipher = re.match(r"^Cipher\s*:\s*(\S+)$", line_str, re.IGNORECASE)
            if m_cipher and m_cipher.group(1) != "0000":
                cipher = m_cipher.group(1)

            m_new = re.search(r"New,\s*(\S+),\s*Cipher is\s*(\S+)", line_str, re.IGNORECASE)
            if m_new:
                if not protocol_version:
                    protocol_version = m_new.group(1)
                if not cipher and m_new.group(2) != "0000":
                    cipher = m_new.group(2)

            # Subject line:
            # subject=C = US, ST = California, O = Example, CN = example.com
            # or: subject=CN = example.com
            m_subj = re.match(r"^subject\s*=\s*(.+)$", line_str, re.IGNORECASE)
            if m_subj:
                subject_dict = _parse_dn(m_subj.group(1))
                if "CN" in subject_dict and not common_name:
                    common_name = subject_dict["CN"]

            # Issuer line:
            # issuer=C = US, O = DigiCert Inc, CN = DigiCert Global Root G2
            m_iss = re.match(r"^issuer\s*=\s*(.+)$", line_str, re.IGNORECASE)
            if m_iss:
                issuer_dict = _parse_dn(m_iss.group(1))

            # SANs line (if present e.g. from x509 text or s_client extension dump):
            # DNS:example.com, DNS:www.example.com
            if "DNS:" in line_str:
                extracted_sans = re.findall(r"DNS:([a-zA-Z0-9\.\-\*]+)", line_str)
                for s in extracted_sans:
                    if s not in sans:
                        sans.append(s)

            # Validity lines:
            # notBefore=Aug 14 00:00:00 2026 GMT
            # notAfter=Aug 14 23:59:59 2027 GMT
            m_nb = re.match(r"^notBefore\s*=\s*(.+)$", line_str, re.IGNORECASE)
            if m_nb:
                valid_from = m_nb.group(1).strip()
            m_na = re.match(r"^notAfter\s*=\s*(.+)$", line_str, re.IGNORECASE)
            if m_na:
                valid_to = m_na.group(1).strip()

        cert: TLSCertificate | None = None
        if subject_dict or issuer_dict or common_name or sans or valid_to:
            cert = TLSCertificate(
                subject=subject_dict,
                issuer=issuer_dict,
                common_name=common_name,
                san=tuple(sans),
                valid_from=valid_from,
                valid_to=valid_to,
            )

        return TLSResult(
            target=target,
            port=port,
            certificate=cert,
            protocol_version=protocol_version,
            cipher=cipher,
            errors=tuple(errors),
            raw_output=output,
        )
