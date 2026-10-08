"""Parser for ICMP ping command outputs."""

from __future__ import annotations

import re

from reconx.models.network import PingResult


class PingParser:
    """Parses standard Linux `ping` command output into normalized PingResult."""

    def parse(self, output: str, target: str = "") -> PingResult:
        is_alive = False
        transmitted = 0
        received = 0
        packet_loss = 100.0
        rtt_min: float | None = None
        rtt_avg: float | None = None
        rtt_max: float | None = None
        rtt_mdev: float | None = None
        errors: list[str] = []

        if not output.strip():
            errors.append("Empty ping output")
            return PingResult(
                target=target,
                is_alive=False,
                packet_loss=100.0,
                errors=tuple(errors),
                raw_output=output,
            )

        for line in output.splitlines():
            line_str = line.strip()

            # Error conditions
            if "Name or service not known" in line_str or "unknown host" in line_str.lower():
                errors.append(line_str)
            elif "Destination Host Unreachable" in line_str:
                errors.append("Destination Host Unreachable")
            elif "Network is unreachable" in line_str:
                errors.append("Network is unreachable")

            # Statistics line:
            # 3 packets transmitted, 3 received, 0% packet loss, time 2003ms
            # or: 3 packets transmitted, 0 received, +3 errors, 100% packet loss
            m_stats = re.search(
                r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received.*?(?:,\s*(\d+(?:\.\d+)?)%\s+packet loss)",
                line_str,
                re.IGNORECASE,
            )
            if m_stats:
                transmitted = int(m_stats.group(1))
                received = int(m_stats.group(2))
                packet_loss = float(m_stats.group(3))
                if received > 0:
                    is_alive = True
                continue

            # RTT summary line:
            # rtt min/avg/max/mdev = 0.035/0.051/0.082/0.019 ms
            # or: round-trip min/avg/max/stddev = ...
            m_rtt = re.search(
                r"(?:rtt|round-trip)\s+(?:min/avg/max/(?:mdev|stddev))\s*=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)",
                line_str,
                re.IGNORECASE,
            )
            if m_rtt:
                rtt_min = float(m_rtt.group(1))
                rtt_avg = float(m_rtt.group(2))
                rtt_max = float(m_rtt.group(3))
                rtt_mdev = float(m_rtt.group(4))
                continue

        # If packets were received, target is alive
        if received > 0 and packet_loss < 100.0:
            is_alive = True

        return PingResult(
            target=target,
            is_alive=is_alive,
            packets_transmitted=transmitted,
            packets_received=received,
            packet_loss=packet_loss,
            rtt_min_ms=rtt_min,
            rtt_avg_ms=rtt_avg,
            rtt_max_ms=rtt_max,
            rtt_mdev_ms=rtt_mdev,
            errors=tuple(errors),
            raw_output=output,
        )
