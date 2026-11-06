"""Interactive HTML Audit Report Generator with modern dark styling and interactive filtering."""
import html
from pathlib import Path
from audit_agent.models import AuditSummary, VerificationStatus, Severity


class HTMLReportGenerator:
    """Generates a standalone, dependency-free interactive HTML security audit report."""

    @staticmethod
    def generate(summary: AuditSummary, output_path: str) -> None:
        confirmed_findings = [f for f in summary.findings if f.verification.status == VerificationStatus.CONFIRMED]
        pruned_findings = [f for f in summary.findings if f.verification.status == VerificationStatus.REFUTED]

        critical_count = sum(1 for f in confirmed_findings if f.hypothesis.severity == Severity.CRITICAL)
        high_count = sum(1 for f in confirmed_findings if f.hypothesis.severity == Severity.HIGH)
        med_count = sum(1 for f in confirmed_findings if f.hypothesis.severity == Severity.MEDIUM)
        low_count = sum(1 for f in confirmed_findings if f.hypothesis.severity in [Severity.LOW, Severity.INFO])

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {html.escape(summary.target_path)}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent-red: #f85149;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --accent-purple: #bc8cff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ font-size: 2rem; display: flex; align-items: center; gap: 0.5rem; }}
        .meta {{ color: var(--text-secondary); margin-top: 0.5rem; font-size: 0.95rem; }}

        /* Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
        }}
        .stat-val {{ font-size: 2.2rem; font-weight: 700; }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .val-red {{ color: var(--accent-red); }}
        .val-green {{ color: var(--accent-green); }}
        .val-yellow {{ color: var(--accent-yellow); }}
        .val-blue {{ color: var(--accent-blue); }}

        /* Filter Tabs */
        .tabs {{
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }}
        .tab-btn {{
            background: none;
            border: 1px solid transparent;
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s ease;
        }}
        .tab-btn.active {{
            background: var(--bg-card);
            color: var(--text-primary);
            border-color: var(--border-color);
        }}

        /* Findings Cards */
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .finding-card.confirmed {{ border-left: 4px solid var(--accent-red); }}
        .finding-card.pruned {{ border-left: 4px solid var(--accent-green); opacity: 0.85; }}
        .card-header {{
            padding: 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        .card-title {{ font-size: 1.15rem; font-weight: 600; display: flex; align-items: center; gap: 0.75rem; }}
        .badge {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-high {{ background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .badge-confirmed {{ background: var(--accent-red); color: #fff; }}
        .badge-pruned {{ background: var(--accent-green); color: #fff; }}

        .card-body {{
            padding: 0 1.25rem 1.25rem 1.25rem;
            border-top: 1px solid var(--border-color);
            background: var(--bg-primary);
        }}
        .section-title {{ font-size: 0.9rem; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; margin-top: 1rem; margin-bottom: 0.4rem; }}
        pre {{
            background: #000;
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 0.88rem;
            color: #d1d5db;
        }}
        .diff-add {{ color: #7ee787; }}
        .diff-del {{ color: #ffa198; }}
        .diff-header {{ color: #79c0ff; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security & Compliance Audit Report</h1>
            <div class="meta">
                Target: <strong>{html.escape(summary.target_path)}</strong> | Type: <strong>{summary.target_type.value}</strong>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val val-blue">{summary.total_hypotheses}</div>
                <div class="stat-label">Hypotheses Evaluated</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-red">{summary.confirmed_bugs}</div>
                <div class="stat-label">Confirmed Vulnerabilities (PoC Proven)</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-green">{summary.false_positives_pruned}</div>
                <div class="stat-label">False Positives Pruned</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-yellow">{summary.pruning_efficiency_pct}%</div>
                <div class="stat-label">False Positive Pruning Rate</div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="filterFindings('all')">All Findings ({len(summary.findings)})</button>
            <button class="tab-btn" onclick="filterFindings('confirmed')">Confirmed Bugs ({len(confirmed_findings)})</button>
            <button class="tab-btn" onclick="filterFindings('pruned')">Pruned False Positives ({len(pruned_findings)})</button>
        </div>

        <div id="findings-container">
"""
        for finding in summary.findings:
            hyp = finding.hypothesis
            ver = finding.verification
            is_confirmed = (ver.status == VerificationStatus.CONFIRMED)
            type_class = "confirmed" if is_confirmed else "pruned"
            badge_class = "badge-confirmed" if is_confirmed else "badge-pruned"
            status_label = "CONFIRMED BUG" if is_confirmed else "PRUNED FALSE POSITIVE"
            sev_class = f"badge-{hyp.severity.value.lower()}" if hyp.severity.value.lower() in ["critical", "high"] else "badge-high"

            # Colorize diff for display
            diff_html = ""
            if finding.remediation_patch:
                formatted_lines = []
                for line in html.escape(finding.remediation_patch).splitlines():
                    if line.startswith("+") and not line.startswith("+++"):
                        formatted_lines.append(f'<span class="diff-add">{line}</span>')
                    elif line.startswith("-") and not line.startswith("---"):
                        formatted_lines.append(f'<span class="diff-del">{line}</span>')
                    elif line.startswith("@@"):
                        formatted_lines.append(f'<span class="diff-header">{line}</span>')
                    else:
                        formatted_lines.append(line)
                diff_html = "\n".join(formatted_lines)

            html_content += f"""
            <div class="finding-card {type_class}">
                <div class="card-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                    <div class="card-title">
                        <span class="badge {badge_class}">{status_label}</span>
                        <span class="badge {sev_class}">{hyp.severity.value.upper()}</span>
                        <span>{html.escape(hyp.id)}: {html.escape(hyp.title)}</span>
                    </div>
                    <div>▼</div>
                </div>
                <div class="card-body">
                    <div class="section-title">Description & Preconditions</div>
                    <p>{html.escape(hyp.description)}</p>
                    <p style="margin-top:0.3rem;"><em>Preconditions:</em> {html.escape(hyp.preconditions)}</p>

                    <div class="section-title">Expected Invariant Breach</div>
                    <p>{html.escape(hyp.expected_invariant_breach)}</p>

                    <div class="section-title">Empirical Verification Log / PoC Trace</div>
                    <pre><code>{html.escape(ver.output_log)}</code></pre>
            """
            if diff_html:
                html_content += f"""
                    <div class="section-title">Automated Remediation Patch</div>
                    <pre><code>{diff_html}</code></pre>
                """

            html_content += """
                </div>
            </div>
            """

        html_content += """
        </div>
    </div>

    <script>
        function filterFindings(type) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                if (type === 'all') {
                    card.style.display = 'block';
                } else if (type === 'confirmed') {
                    card.style.display = card.classList.contains('confirmed') ? 'block' : 'none';
                } else if (type === 'pruned') {
                    card.style.display = card.classList.contains('pruned') ? 'block' : 'none';
                }
            });
        }
    </script>
</body>
</html>
"""
        Path(output_path).write_text(html_content, encoding="utf-8")
