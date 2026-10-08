"""Markdown report renderer for ReconX.

Produces clean, human-readable GitHub Flavored Markdown security reports.
"""

from __future__ import annotations

from reconx.reporting.model import ReportModel


class MarkdownReportRenderer:
    """Renders a ReportModel into formatted Markdown."""

    def render(self, model: ReportModel) -> str:
        """Render ReportModel as Markdown document."""
        lines: list[str] = [
            f"# {model.title}",
            "",
            "> Automated reconnaissance and vulnerability assessment conducted by ReconX framework.",
            "",
            f"- **Target:** `{model.target}`",
            f"- **Scan ID:** `{model.scan_id}`",
            f"- **Generated At:** {model.generated_at}",
            f"- **ReconX Version:** `{model.appendix.reconx_version}`",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| **Target** | `{model.executive_summary.target}` |",
            f"| **Scan Date** | {model.executive_summary.scan_date} |",
            f"| **Duration** | {model.executive_summary.duration_seconds:.2f} seconds |",
            f"| **Scope** | {model.executive_summary.scope_summary} |",
            f"| **Total Assets Discovered** | {model.executive_summary.total_assets} |",
            f"| **Total Findings** | {model.executive_summary.total_findings} |",
            f"| **Risk Overview** | {model.executive_summary.risk_score_summary} |",
            "",
            "### Severity Distribution",
            "",
            "| Severity | Findings Count |",
            "|---|---|",
        ]

        sev_dist = model.executive_summary.severity_distribution
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = sev_dist.get(sev, 0)
            lines.append(f"| **{sev}** | {count} |")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Attack Surface Inventory",
            "",
            f"### Discovered Domains ({len(model.attack_surface.domains)})",
            "",
        ])

        if model.attack_surface.domains:
            for d in model.attack_surface.domains:
                lines.append(f"- `{d}`")
        else:
            lines.append("_No hostnames or domains discovered._")

        lines.extend([
            "",
            f"### Discovered IP Addresses ({len(model.attack_surface.ip_addresses)})",
            "",
        ])

        if model.attack_surface.ip_addresses:
            for ip in model.attack_surface.ip_addresses:
                lines.append(f"- `{ip}`")
        else:
            lines.append("_No IP addresses discovered._")

        lines.extend([
            "",
            f"### Open Ports & Services ({len(model.attack_surface.ports)})",
            "",
        ])

        if model.attack_surface.ports:
            lines.append("| Port / Protocol | Service |")
            lines.append("|---|---|")
            for i, p in enumerate(model.attack_surface.ports):
                svc = model.attack_surface.services[i] if i < len(model.attack_surface.services) else "unknown"
                lines.append(f"| `{p}` | `{svc}` |")
        else:
            lines.append("_No open ports recorded._")

        lines.extend([
            "",
            f"### Web Endpoints & URLs ({len(model.attack_surface.endpoints)})",
            "",
        ])

        if model.attack_surface.endpoints:
            # Show up to 50 endpoints in markdown to prevent runaway report size
            for ep in model.attack_surface.endpoints[:50]:
                lines.append(f"- `{ep}`")
            if len(model.attack_surface.endpoints) > 50:
                lines.append(f"- _...and {len(model.attack_surface.endpoints) - 50} more endpoints._")
        else:
            lines.append("_No web endpoints discovered._")

        if model.attack_surface.technologies:
            lines.extend([
                "",
                f"### Technologies Detected ({len(model.attack_surface.technologies)})",
                "",
            ])
            for t in model.attack_surface.technologies:
                lines.append(f"- `{t}`")

        lines.extend([
            "",
            "---",
            "",
            f"## 3. Findings ({len(model.findings)})",
            "",
        ])

        if not model.findings:
            lines.append("No security findings were identified during this assessment.")
        else:
            for i, f in enumerate(model.findings, start=1):
                cvss_str = f"{f.cvss_score:.1f} ({f.severity})" if f.cvss_score is not None else "Requires Review"
                lines.extend([
                    f"### {i}. [{f.severity}] {f.title}",
                    "",
                    "| Attribute | Detail |",
                    "|---|---|",
                    f"| **Finding ID** | `{f.id}` |",
                    f"| **Severity** | **{f.severity}** |",
                    f"| **Confidence** | {f.confidence:.2f} ({f.confidence_level}) |",
                    f"| **CVSS Version** | {f.cvss_version or 'N/A'} |",
                    f"| **CVSS Base Score** | {cvss_str} |",
                    f"| **CVSS Vector** | `{f.cvss_vector or 'N/A'}` |",
                    f"| **Review Status** | `{f.cvss_status}` |",
                    f"| **Affected Asset** | `{f.affected_asset}` |",
                ])

                if f.endpoint:
                    lines.append(f"| **Endpoint** | `{f.endpoint}` |")

                lines.extend([
                    "",
                    "#### Description",
                    "",
                    f.description or "_No description provided._",
                    "",
                    "#### Impact",
                    "",
                    f.impact or "_Standard security impact._",
                    "",
                    "#### Scoring Rationale",
                    "",
                    f.cvss_rationale or "_Automated archetype assignment._",
                    "",
                    "#### Evidence",
                    "",
                ])

                if f.evidence:
                    lines.append("```text")
                    for ev in f.evidence:
                        lines.append(ev)
                    lines.append("```")
                else:
                    lines.append("_No raw evidence snippets attached._")

                lines.extend([
                    "",
                    "#### Remediation",
                    "",
                    f.remediation or "Consult vendor guidance and implement secure configuration.",
                    "",
                ])

                if f.references:
                    lines.append("#### References")
                    lines.append("")
                    for ref in f.references:
                        lines.append(f"- `{ref}`")
                    lines.append("")

                lines.append("---")
                lines.append("")

        lines.extend([
            "## 4. Technical Appendix",
            "",
            "### Scan Configuration",
            "",
            f"- **Scan ID:** `{model.appendix.scan_configuration.get('scan_id', model.scan_id)}`",
            f"- **Execution Status:** `{model.appendix.scan_configuration.get('status', 'COMPLETED')}`",
            f"- **Target List:** `{', '.join(model.appendix.scan_configuration.get('targets', [model.target]))}`",
            "",
            "### Tool Executions & Versions",
            "",
        ])

        if model.appendix.tool_versions:
            lines.append("| Tool Binary | Detected Version |")
            lines.append("|---|---|")
            for tool, ver in sorted(model.appendix.tool_versions.items()):
                lines.append(f"| `{tool}` | `{ver}` |")
        else:
            lines.append(f"Executed modules: `{', '.join(model.appendix.executed_modules) or 'None'}`")

        if model.appendix.incomplete_tasks:
            lines.extend([
                "",
                "### Incomplete Tasks",
                "",
            ])
            for it in model.appendix.incomplete_tasks:
                lines.append(f"- {it}")

        if model.appendix.errors:
            lines.extend([
                "",
                "### Diagnostic Errors",
                "",
            ])
            for err in model.appendix.errors:
                lines.append(f"- `{err}`")

        lines.extend([
            "",
            "---",
            "_Report generated autonomously by ReconX Security Orchestration Platform._",
            "",
        ])

        return "\n".join(lines)
