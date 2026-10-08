"""HTML report renderer for ReconX.

Produces self-contained, responsive HTML5 technical reports with modern styling.
All dynamic values are HTML-escaped for safety per Implementation.md Section 26.
"""

from __future__ import annotations

import html

from reconx.reporting.model import ReportModel


class HTMLReportRenderer:
    """Renders a ReportModel into a self-contained, responsive HTML5 document."""

    def render(self, model: ReportModel) -> str:
        """Render ReportModel as HTML5 string."""
        sev_dist = model.executive_summary.severity_distribution

        # Escape all high-level model strings
        esc_target = html.escape(model.target)
        esc_title = html.escape(model.title)
        esc_scan_id = html.escape(model.scan_id)
        esc_date = html.escape(model.executive_summary.scan_date)
        esc_scope = html.escape(model.executive_summary.scope_summary)
        esc_risk = html.escape(model.executive_summary.risk_score_summary)
        esc_version = html.escape(model.appendix.reconx_version)

        # Build findings HTML
        findings_html_list: list[str] = []
        if not model.findings:
            findings_html_list.append(
                "<div class='empty-state'><p>No security findings were identified during this assessment.</p></div>"
            )
        else:
            for i, f in enumerate(model.findings, start=1):
                sev_cls = f.severity.lower()
                esc_f_title = html.escape(f.title)
                esc_f_id = html.escape(f.id)
                esc_f_sev = html.escape(f.severity)
                esc_f_conf_level = html.escape(f.confidence_level)
                esc_f_asset = html.escape(f.affected_asset)
                esc_f_ep = html.escape(f.endpoint) if f.endpoint else None
                esc_f_desc = html.escape(f.description).replace("\n", "<br>")
                esc_f_impact = html.escape(f.impact)
                esc_f_rationale = html.escape(f.cvss_rationale)
                esc_f_remediation = html.escape(f.remediation).replace("\n", "<br>")
                esc_f_vector = html.escape(f.cvss_vector) if f.cvss_vector else "N/A"
                esc_f_status = html.escape(f.cvss_status)

                cvss_badge_str = (
                    f"CVSS {f.cvss_version or '3.1'}: <strong>{f.cvss_score:.1f}</strong>"
                    if f.cvss_score is not None
                    else "CVSS: <em>Requires Review</em>"
                )

                endpoint_row = (
                    f"<div class='meta-item'><strong>Endpoint:</strong> <code>{esc_f_ep}</code></div>"
                    if esc_f_ep
                    else ""
                )

                evidence_block = ""
                if f.evidence:
                    ev_items = "\n".join(html.escape(e) for e in f.evidence)
                    evidence_block = (
                        f"<div class='sub-section'><h4>Evidence</h4>"
                        f"<pre class='code-box'><code>{ev_items}</code></pre></div>"
                    )

                refs_block = ""
                if f.references:
                    ref_items = "".join(f"<li><code>{html.escape(r)}</code></li>" for r in f.references)
                    refs_block = (
                        f"<div class='sub-section'><h4>References</h4>"
                        f"<ul class='ref-list'>{ref_items}</ul></div>"
                    )

                finding_card = f"""
                <div class="finding-card border-{sev_cls}">
                    <div class="finding-header">
                        <div class="finding-title-group">
                            <span class="badge badge-{sev_cls}">{esc_f_sev}</span>
                            <h3 class="finding-title">#{i}. {esc_f_title}</h3>
                        </div>
                        <div class="cvss-pill">{cvss_badge_str}</div>
                    </div>
                    <div class="finding-meta-grid">
                        <div class="meta-item"><strong>ID:</strong> <code>{esc_f_id}</code></div>
                        <div class="meta-item"><strong>Asset:</strong> <code>{esc_f_asset}</code></div>
                        <div class="meta-item"><strong>Confidence:</strong> {f.confidence:.2f} ({esc_f_conf_level})</div>
                        <div class="meta-item"><strong>Status:</strong> <span class="status-tag">{esc_f_status}</span></div>
                        {endpoint_row}
                    </div>
                    <div class="finding-vector">
                        <strong>Vector:</strong> <code>{esc_f_vector}</code>
                    </div>
                    <div class="finding-body">
                        <div class="sub-section">
                            <h4>Description</h4>
                            <p>{esc_f_desc}</p>
                        </div>
                        <div class="sub-section">
                            <h4>Security Impact</h4>
                            <p>{esc_f_impact}</p>
                        </div>
                        <div class="sub-section">
                            <h4>Scoring Rationale</h4>
                            <p>{esc_f_rationale}</p>
                        </div>
                        {evidence_block}
                        <div class="sub-section">
                            <h4>Remediation Guidance</h4>
                            <p>{esc_f_remediation}</p>
                        </div>
                        {refs_block}
                    </div>
                </div>
                """
                findings_html_list.append(finding_card)

        findings_html = "\n".join(findings_html_list)

        # Attack surface ports & services
        ports_rows: list[str] = []
        if model.attack_surface.ports:
            for i, p in enumerate(model.attack_surface.ports):
                svc = model.attack_surface.services[i] if i < len(model.attack_surface.services) else "unknown"
                ports_rows.append(f"<tr><td><code>{html.escape(p)}</code></td><td>{html.escape(svc)}</td></tr>")
        ports_table_html = "\n".join(ports_rows) if ports_rows else "<tr><td colspan='2'>No open ports recorded.</td></tr>"

        # Domains list
        domains_html = "".join(f"<li><code>{html.escape(d)}</code></li>" for d in model.attack_surface.domains) or "<li><em>None</em></li>"
        ips_html = "".join(f"<li><code>{html.escape(ip)}</code></li>" for ip in model.attack_surface.ip_addresses) or "<li><em>None</em></li>"
        endpoints_html = "".join(f"<li><code>{html.escape(ep)}</code></li>" for ep in model.attack_surface.endpoints[:40]) or "<li><em>None</em></li>"
        techs_html = "".join(f"<span class='tech-tag'>{html.escape(t)}</span> " for t in model.attack_surface.technologies) or "<em>None detected</em>"

        # Tool versions table
        tool_rows: list[str] = []
        for tool, ver in sorted(model.appendix.tool_versions.items()):
            tool_rows.append(f"<tr><td><code>{html.escape(tool)}</code></td><td>{html.escape(ver)}</td></tr>")
        tools_table_html = "\n".join(tool_rows) if tool_rows else "<tr><td colspan='2'>No tool version metadata recorded.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc_title}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --crit: #ef4444;
            --high: #f97316;
            --med: #f59e0b;
            --low: #06b6d4;
            --info: #64748b;
            --accent: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        .header-top {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 1rem; }}
        h1 {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
        .header-subtitle {{ color: var(--text-secondary); margin-bottom: 1.5rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }}
        .stat-card {{
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .stat-value {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }}
        .severity-bar-container {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .sev-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        .sev-box {{
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        .sev-box.critical {{ background: rgba(239, 68, 68, 0.15); border: 1px solid var(--crit); color: var(--crit); }}
        .sev-box.high {{ background: rgba(249, 115, 22, 0.15); border: 1px solid var(--high); color: var(--high); }}
        .sev-box.medium {{ background: rgba(245, 158, 11, 0.15); border: 1px solid var(--med); color: var(--med); }}
        .sev-box.low {{ background: rgba(6, 182, 212, 0.15); border: 1px solid var(--low); color: var(--low); }}
        .sev-box.info {{ background: rgba(100, 116, 139, 0.15); border: 1px solid var(--info); color: var(--info); }}
        .sev-box-count {{ font-size: 1.8rem; font-weight: 700; }}
        .sev-box-label {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }}
        section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        h2 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.75rem; }}
        .surface-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
        }}
        .surface-box {{ background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem; }}
        .surface-box h3 {{ font-size: 1rem; margin-bottom: 0.75rem; color: #fff; }}
        .surface-list {{ list-style-type: none; max-height: 250px; overflow-y: auto; }}
        .surface-list li {{ padding: 0.35rem 0; font-size: 0.9rem; border-bottom: 1px solid rgba(255,255,255,0.05); }}
        code {{ background: rgba(0, 0, 0, 0.3); padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.88em; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; }}
        th {{ background: rgba(0,0,0,0.2); color: var(--text-secondary); }}
        .tech-tag {{ display: inline-block; background: #0284c7; color: #fff; border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.8rem; margin: 0.2rem; }}
        .finding-card {{
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .finding-card.border-critical {{ border-left: 5px solid var(--crit); }}
        .finding-card.border-high {{ border-left: 5px solid var(--high); }}
        .finding-card.border-medium {{ border-left: 5px solid var(--med); }}
        .finding-card.border-low {{ border-left: 5px solid var(--low); }}
        .finding-card.border-info {{ border-left: 5px solid var(--info); }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.75rem; }}
        .finding-title-group {{ display: flex; align-items: center; gap: 0.75rem; }}
        .badge {{
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            color: #fff;
        }}
        .badge-critical {{ background: var(--crit); }}
        .badge-high {{ background: var(--high); }}
        .badge-medium {{ background: var(--med); color: #000; }}
        .badge-low {{ background: var(--low); color: #000; }}
        .badge-info {{ background: var(--info); }}
        .cvss-pill {{ background: rgba(59, 130, 246, 0.2); border: 1px solid var(--accent); color: #60a5fa; padding: 0.3rem 0.75rem; border-radius: 20px; font-size: 0.85rem; }}
        .finding-meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem; font-size: 0.85rem; margin-bottom: 1rem; }}
        .meta-item {{ color: var(--text-secondary); }}
        .meta-item strong {{ color: var(--text-primary); }}
        .status-tag {{ background: rgba(255,255,255,0.1); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8em; }}
        .finding-vector {{ background: rgba(0,0,0,0.3); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; margin-bottom: 1.25rem; word-break: break-all; }}
        .sub-section {{ margin-bottom: 1.25rem; }}
        .sub-section h4 {{ font-size: 0.95rem; font-weight: 600; color: #cbd5e1; margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 0.04em; }}
        .sub-section p {{ font-size: 0.95rem; color: #e2e8f0; }}
        .code-box {{ background: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 0.75rem; font-size: 0.85rem; overflow-x: auto; color: #f1f5f9; }}
        .ref-list {{ list-style-type: none; }}
        .ref-list li {{ padding: 0.2rem 0; font-size: 0.85rem; }}
        footer {{ text-align: center; color: var(--text-secondary); font-size: 0.85rem; margin-top: 3rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <h1>{esc_title}</h1>
                <span class="badge" style="background:#2563eb;">ReconX v{esc_version}</span>
            </div>
            <h2 style="border:none; margin-bottom:0.5rem; font-size:1.3rem;">Executive Summary</h2>
            <p class="header-subtitle">Target: <code>{esc_target}</code> &bull; Scan ID: <code>{esc_scan_id}</code> &bull; Date: {esc_date}</p>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Execution Duration</div>
                    <div class="stat-value">{model.executive_summary.duration_seconds:.2f}s</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Assets Discovered</div>
                    <div class="stat-value">{model.executive_summary.total_assets}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Findings</div>
                    <div class="stat-value">{model.executive_summary.total_findings}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Authorized Scope</div>
                    <div class="stat-value" style="font-size:1.1rem; line-height:1.4;">{esc_scope}</div>
                </div>
            </div>
        </header>

        <div class="severity-bar-container">
            <h2>Severity Distribution</h2>
            <div class="sev-grid">
                <div class="sev-box critical">
                    <div class="sev-box-count">{sev_dist.get('CRITICAL', 0)}</div>
                    <div class="sev-box-label">Critical</div>
                </div>
                <div class="sev-box high">
                    <div class="sev-box-count">{sev_dist.get('HIGH', 0)}</div>
                    <div class="sev-box-label">High</div>
                </div>
                <div class="sev-box medium">
                    <div class="sev-box-count">{sev_dist.get('MEDIUM', 0)}</div>
                    <div class="sev-box-label">Medium</div>
                </div>
                <div class="sev-box low">
                    <div class="sev-box-count">{sev_dist.get('LOW', 0)}</div>
                    <div class="sev-box-label">Low</div>
                </div>
                <div class="sev-box info">
                    <div class="sev-box-count">{sev_dist.get('INFO', 0)}</div>
                    <div class="sev-box-label">Info</div>
                </div>
            </div>
            <p style="margin-top:1rem; font-size:0.9rem; color:var(--text-secondary); text-align:center;">
                {esc_risk}
            </p>
        </div>

        <section>
            <h2>Attack Surface Inventory</h2>
            <div class="surface-grid">
                <div class="surface-box">
                    <h3>Domains & Hostnames ({len(model.attack_surface.domains)})</h3>
                    <ul class="surface-list">{domains_html}</ul>
                </div>
                <div class="surface-box">
                    <h3>IP Addresses ({len(model.attack_surface.ip_addresses)})</h3>
                    <ul class="surface-list">{ips_html}</ul>
                </div>
                <div class="surface-box">
                    <h3>Web Endpoints ({len(model.attack_surface.endpoints)})</h3>
                    <ul class="surface-list">{endpoints_html}</ul>
                </div>
            </div>
            <div style="margin-top: 1.5rem;">
                <h3>Open Ports & Services ({len(model.attack_surface.ports)})</h3>
                <table>
                    <thead>
                        <tr><th>Port / Protocol</th><th>Service Detected</th></tr>
                    </thead>
                    <tbody>
                        {ports_table_html}
                    </tbody>
                </table>
            </div>
            <div style="margin-top: 1.5rem;">
                <h3>Detected Technologies</h3>
                <p>{techs_html}</p>
            </div>
        </section>

        <section>
            <h2>Vulnerability Findings ({len(model.findings)})</h2>
            {findings_html}
        </section>

        <section>
            <h2>Technical Appendix</h2>
            <h3>Tool Versions</h3>
            <table>
                <thead>
                    <tr><th>Binary</th><th>Version Output</th></tr>
                </thead>
                <tbody>
                    {tools_table_html}
                </tbody>
            </table>
            <div style="margin-top: 1.5rem;">
                <p><strong>Executed Modules:</strong> <code>{html.escape(', '.join(model.appendix.executed_modules) or 'None')}</code></p>
            </div>
        </section>

        <footer>
            <p>Generated autonomously by ReconX Framework. Confidential Security Assessment Document.</p>
        </footer>
    </div>
</body>
</html>
"""
