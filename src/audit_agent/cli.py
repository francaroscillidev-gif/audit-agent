"""CLI interface for AuditAgent with Rich formatting."""
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich import print as rprint

from audit_agent.models import VerificationStatus
from audit_agent.orchestrator import AuditOrchestrator
from audit_agent.reporting.html_report import HTMLReportGenerator

app = typer.Typer(
    name="audit-agent",
    help="Autonomous Security & Compliance Agent with Empirical Proof-of-Concept Verification."
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to smart contract, API source file, or project folder"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="Optional LLM API key"),
    output_report: Optional[str] = typer.Option(None, "--output", "-o", help="Save markdown audit report to file"),
    html_report: Optional[str] = typer.Option(None, "--html", help="Save interactive HTML audit dashboard"),
):
    """Scan a target file or project, formulate semantic hypotheses, and verify invariants empirically."""
    console.rule("[bold cyan]🛡️  AuditAgent: Empirical Security & Compliance Scanner[/bold cyan]")
    console.print(f"[bold]Target:[/bold] [yellow]{target}[/yellow]\n")

    orchestrator = AuditOrchestrator(api_key=api_key)

    with console.status("[bold green]Executing AST heuristics, semantic reasoning, and invariant tests...[/bold green]", spinner="dots"):
        try:
            summary = orchestrator.run_audit(target)
        except Exception as e:
            console.print(f"[bold red]Scan failed:[/bold red] {e}")
            raise typer.Exit(code=1)

    # Print Results Table
    table = Table(title="[bold]Hypothesis Verification & False Positive Pruning[/bold]", expand=True)
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Title", style="white")
    table.add_column("Severity", width=10)
    table.add_column("Status", width=16)
    table.add_column("Latency", justify="right", width=10)

    for finding in summary.findings:
        hyp = finding.hypothesis
        ver = finding.verification

        if ver.status == VerificationStatus.CONFIRMED:
            status_text = Text("CONFIRMED", style="bold red")
        elif ver.status == VerificationStatus.REFUTED:
            status_text = Text("PRUNED (FP)", style="bold green")
        else:
            status_text = Text("UNVERIFIED", style="yellow")

        sev_style = "bold red" if hyp.severity.value in ["critical", "high"] else "yellow"
        table.add_row(
            hyp.id,
            hyp.title,
            Text(hyp.severity.value.upper(), style=sev_style),
            status_text,
            f"{ver.duration_ms:.1f}ms"
        )

    console.print(table)
    console.print()

    # Metrics Summary Box
    metrics_text = (
        f"[bold]Total Hypotheses Evaluated:[/bold] {summary.total_hypotheses}\n"
        f"[bold red]Verified Vulnerabilities (PoC Confirmed):[/bold red] {summary.confirmed_bugs}\n"
        f"[bold green]False Positives Pruned:[/bold green] {summary.false_positives_pruned}\n"
        f"[bold cyan]False Positive Pruning Efficiency:[/bold cyan] {summary.pruning_efficiency_pct}%\n"
    )
    console.print(Panel(metrics_text, title="[bold]Audit Metrics[/bold]", border_style="cyan"))

    # Print details and patches for confirmed bugs
    for finding in summary.findings:
        hyp = finding.hypothesis
        ver = finding.verification

        if ver.status == VerificationStatus.CONFIRMED:
            console.rule(f"[bold red]🚨 Confirmed Bug: {hyp.id} - {hyp.title}[/bold red]")
            console.print(f"[bold]Invariant Breach:[/bold] {hyp.expected_invariant_breach}")
            console.print(f"[bold]Exploit Proof Output:[/bold]")
            console.print(Panel(ver.output_log, border_style="red", expand=False))

            if finding.remediation_patch:
                console.print("[bold green]🛠️  Automated Remediation Patch (Unified Diff):[/bold green]")
                diff_syntax = Syntax(finding.remediation_patch, "diff", theme="monokai", line_numbers=False)
                console.print(diff_syntax)
            console.print()

    # Markdown export
    if output_report:
        _export_markdown_report(summary, output_report)
        console.print(f"[bold green]✅ Markdown report saved to:[/bold green] [underline]{output_report}[/underline]")

    # HTML export
    if html_report:
        HTMLReportGenerator.generate(summary, html_report)
        console.print(f"[bold green]🌐 Interactive HTML report saved to:[/bold green] [underline]{html_report}[/underline]")


@app.command()
def demo():
    """Run an automated demonstration on example vulnerable Solidity contract."""
    example_path = Path("examples/VulnerableVault.sol")
    if not example_path.exists():
        console.print("[red]Example contract not found![/red]")
        raise typer.Exit(code=1)

    console.print("[bold yellow]Running live demonstration on example Smart Contract with real and safe patterns...[/bold yellow]\n")
    scan(str(example_path), api_key=None, output_report="audit_report_demo.md", html_report="audit_report_demo.html")


@app.command("init-ci")
def init_ci(
    output_dir: str = typer.Option(".github/workflows", "--dir", "-d", help="Directory for CI workflow file")
):
    """Generate GitHub Actions CI/CD workflow to audit pull requests automatically."""
    ci_path = Path(output_dir)
    ci_path.mkdir(parents=True, exist_ok=True)
    workflow_file = ci_path / "security-audit.yml"

    workflow_content = """name: Security & Compliance Self-Audit

on:
  pull_request:
    branches: [main, master, dev]
  push:
    branches: [main, master]

jobs:
  audit:
    name: Run Empirical Security Agent
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          version: "latest"

      - name: Set up Python
        run: uv python install 3.12

      - name: Install dependencies
        run: uv sync

      - name: Run Empirical Audit
        run: |
          uv run audit-agent scan . --output audit-summary.md --html audit-dashboard.html

      - name: Upload Audit Dashboard
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-dashboard
          path: audit-dashboard.html
"""
    workflow_file.write_text(workflow_content, encoding="utf-8")
    console.print(f"[bold green]✅ Generated GitHub Actions CI/CD workflow at:[/bold green] [underline]{workflow_file}[/underline]")


def _export_markdown_report(summary, output_path: str):
    """Generate structured markdown report."""
    md = []
    md.append(f"# Security & Compliance Audit Report\n")
    md.append(f"- **Target**: `{summary.target_path}`")
    md.append(f"- **Type**: `{summary.target_type.value}`")
    md.append(f"- **Total Hypotheses**: {summary.total_hypotheses}")
    md.append(f"- **Confirmed Vulnerabilities**: {summary.confirmed_bugs}")
    md.append(f"- **False Positives Pruned**: {summary.false_positives_pruned} ({summary.pruning_efficiency_pct}%)\n")

    md.append("## 1. Confirmed Vulnerabilities\n")
    confirmed = [f for f in summary.findings if f.verification.status == VerificationStatus.CONFIRMED]
    if not confirmed:
        md.append("No confirmed vulnerabilities found.\n")
    for f in confirmed:
        md.append(f"### [{f.hypothesis.severity.value.upper()}] {f.hypothesis.id}: {f.hypothesis.title}\n")
        md.append(f"- **Category**: {f.hypothesis.category.value}")
        md.append(f"- **Preconditions**: {f.hypothesis.preconditions}")
        md.append(f"- **Expected Invariant Breach**: {f.hypothesis.expected_invariant_breach}")
        md.append(f"\n**Execution Trace / Proof:**\n```text\n{f.verification.output_log}\n```\n")
        if f.remediation_patch:
            md.append(f"**Suggested Patch:**\n```diff\n{f.remediation_patch}\n```\n")

    md.append("## 2. Pruned False Positives\n")
    pruned = [f for f in summary.findings if f.verification.status == VerificationStatus.REFUTED]
    for f in pruned:
        md.append(f"### [PRUNED] {f.hypothesis.id}: {f.hypothesis.title}\n")
        md.append(f"- **Reason**: {f.verification.details}")
        md.append(f"- **Verification Log**: `{f.verification.output_log.replace(chr(10), ' | ')}`\n")

    Path(output_path).write_text("\n".join(md), encoding="utf-8")


def main():
    app()


if __name__ == "__main__":
    main()
