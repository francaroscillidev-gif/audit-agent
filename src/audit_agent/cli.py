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

from audit_agent.models import VerificationStatus, VulnerabilityCategory
from audit_agent.orchestrator import AuditOrchestrator
from audit_agent.reporting.html_report import HTMLReportGenerator
from audit_agent.reporting.sarif_report import SARIFReportGenerator
from audit_agent.reporting.test_exporter import TestExporter
from audit_agent.compliance.registry import ComplianceRegistry
from audit_agent.compliance.cvss import CVSSScorer
from audit_agent.fuzzing.invariants import StatefulInvariantFuzzer
from audit_agent.watcher import SecurityWatcher
from audit_agent.remediation.applier import PatchApplier
from audit_agent.analysis.cfg import CFGBuilder
from audit_agent.analysis.taint import TaintAnalyzer
from audit_agent.analysis.callgraph import CallGraphResolver
from audit_agent.analysis.gas_mev import GasMEVAnalyzer
from audit_agent.server import DashboardServer

app = typer.Typer(
    name="audit-agent",
    help="Autonomous Security & Compliance Agent with Empirical Proof-of-Concept Verification."
)
console = Console()

__version__ = "1.0.0"


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]AuditAgent[/bold cyan] version [bold green]{__version__}[/bold green] (Enterprise Edition)")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show the application version and exit.", callback=version_callback, is_eager=True
    ),
):
    """Autonomous Security & Compliance Agent with Empirical Proof-of-Concept Verification."""
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to smart contract, API source file, or project folder"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="Optional LLM API key"),
    provider: str = typer.Option("offline_expert", "--provider", "-p", help="LLM Provider: offline_expert, gemini, openai, anthropic, ollama"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Specific model identifier"),
    output_report: Optional[str] = typer.Option(None, "--output", "-o", help="Save markdown audit report to file"),
    html_report: Optional[str] = typer.Option(None, "--html", help="Save interactive HTML audit dashboard"),
    sarif_report: Optional[str] = typer.Option(None, "--sarif", help="Save OASIS SARIF v2.1.0 file for GitHub Security"),
):
    """Scan a target file or project, formulate semantic hypotheses, and verify invariants empirically."""
    console.rule("[bold cyan]🛡️  AuditAgent: Empirical Security & Compliance Scanner[/bold cyan]")
    console.print(f"[bold]Target:[/bold] [yellow]{target}[/yellow] | [bold]Provider:[/bold] [cyan]{provider}[/cyan]\n")

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
    table.add_column("Standard", style="magenta", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=16)
    table.add_column("Latency", justify="right", width=10)

    for finding in summary.findings:
        hyp = finding.hypothesis
        ver = finding.verification
        comp = ComplianceRegistry.get_compliance_info(hyp.category)
        std_tag = comp["swc_id"] if comp["swc_id"] != "N/A" else comp["cwe_id"]

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
            std_tag,
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
            comp = ComplianceRegistry.get_compliance_info(hyp.category)
            console.rule(f"[bold red]🚨 Confirmed Bug: {hyp.id} - {hyp.title}[/bold red]")
            console.print(f"[bold]Compliance Standard:[/bold] {comp['swc_id']} / {comp['cwe_id']} ({comp['owasp_category']})")
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

    # SARIF export
    if sarif_report:
        SARIFReportGenerator.generate(summary, sarif_report)
        console.print(f"[bold green]📊 OASIS SARIF report saved to:[/bold green] [underline]{sarif_report}[/underline]")


@app.command()
def fix(
    target: str = typer.Argument(..., help="Path to smart contract or API source file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview patch without modifying target file"),
):
    """Automatically apply verified security patches and re-verify invariant holding."""
    console.rule("[bold green]🛠️  AuditAgent: Automated Remediation Engine[/bold green]")
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit(target)

    confirmed = [f for f in summary.findings if f.verification.status == VerificationStatus.CONFIRMED]
    if not confirmed:
        console.print("[green]No confirmed vulnerabilities to fix![/green]")
        return

    console.print(f"Found [bold red]{len(confirmed)}[/bold red] confirmed vulnerabilities.")

    for finding in confirmed:
        hyp = finding.hypothesis
        console.print(f"\nProcessing [bold cyan]{hyp.id}[/bold cyan]: {hyp.title}")

        if dry_run:
            console.print("[yellow][DRY RUN] Would apply patch:[/yellow]")
            if finding.remediation_patch:
                console.print(Syntax(finding.remediation_patch, "diff", theme="monokai"))
            continue

        verifier = orchestrator.solidity_verifier if summary.target_type.value == "smart_contract" else orchestrator.webapp_verifier
        success, msg = PatchApplier.apply_and_verify(finding, verifier, orchestrator.reasoner)

        if success:
            console.print(f"[bold green]✔ {msg}[/bold green]")
        else:
            console.print(f"[bold red]✖ {msg}[/bold red]")


@app.command("export-tests")
def export_tests(
    target: str = typer.Argument(..., help="Path to smart contract or API file"),
    outdir: str = typer.Option("tests/security", "--outdir", "-o", help="Directory where regression tests will be created"),
):
    """Export verified exploits as permanent regression test files (Foundry / Pytest)."""
    console.rule("[bold cyan]🧪 AuditAgent: Exploit-to-Test Transpiler[/bold cyan]")
    orchestrator = AuditOrchestrator()
    summary = orchestrator.run_audit(target)

    files = TestExporter.export(summary, outdir)
    console.print(f"Exported [bold green]{len(files)}[/bold green] regression test file(s) into [underline]{outdir}[/underline]:")
    for f in files:
        console.print(f"  • [yellow]{f.name}[/yellow]")


@app.command()
def watch(
    target: str = typer.Argument(..., help="Path to file or folder to monitor"),
    interval: float = typer.Option(1.0, "--interval", "-i", help="Polling interval in seconds"),
):
    """Live watch daemon: continuously re-audit codebase on file save."""
    watcher = SecurityWatcher(target, console=console)
    watcher.watch(interval=interval)


@app.command()
def inspect(
    target: str = typer.Argument(..., help="Path to smart contract or API file to deeply analyze"),
):
    """Deep inspection: Control Flow Graph (CFG), Taint Data-Flow, Call Graph, and CVSS Risk Scoring."""
    console.rule("[bold cyan]🔍 AuditAgent: Deep Code & Security Inspector[/bold cyan]")
    path = Path(target)
    if not path.exists():
        console.print(f"[red]Target file not found: {target}[/red]")
        raise typer.Exit(code=1)

    source_code = path.read_text(encoding="utf-8")
    is_solidity = path.suffix == ".sol"

    # 1. Multi-Contract Call Graph & Hierarchy
    if is_solidity:
        call_graph = CallGraphResolver.resolve_contracts(source_code)
        console.print(f"\n[bold]1. Contract Architecture & Inheritance Graph:[/bold]")
        for name, node in call_graph.contracts.items():
            chain = call_graph.get_inheritance_tree(name)
            parents = f" -> [green]{', '.join(chain)}[/green]" if chain else ""
            calls = f" | Calls: [magenta]{', '.join(node.external_calls_to)}[/magenta]" if node.external_calls_to else ""
            console.print(f"  • [yellow]{node.kind} {name}[/yellow]{parents}{calls} (Functions: {len(node.functions)})")

    # 2. Control Flow Graph (CFG) Analysis on Key Functions
    lines = source_code.splitlines()
    fn_name = "withdraw" if "withdraw" in source_code else ("setOwner" if "setOwner" in source_code else "main")
    
    # Extract lines for CFG
    fn_lines = [l for l in lines if not l.strip().startswith("//")]
    cfg = CFGBuilder.build(fn_name, fn_lines)
    inversions = cfg.find_checks_effects_inversion_paths()

    console.print(f"\n[bold]2. Control Flow Graph (CFG) Analysis on '{fn_name}':[/bold]")
    console.print(f"  Total Basic Blocks: [cyan]{len(cfg.blocks)}[/cyan]")
    for b_id, block in cfg.blocks.items():
        call_flag = " [red][EXTERNAL CALL][/red]" if block.has_external_call else ""
        write_flag = " [yellow][STATE WRITE][/yellow]" if block.has_state_write else ""
        console.print(f"  [{b_id}] Lines {block.start_line}-{block.end_line}: {len(block.statements)} stmts{call_flag}{write_flag} -> {block.successors}")

    if inversions:
        console.print(f"  [bold red]⚠️  CFG Inversion Detected: Path {inversions[0]} violates Checks-Effects-Interactions![/bold red]")

    # 3. Data-Flow Taint Analysis
    console.print(f"\n[bold]3. Data-Flow Taint Tracking (Sources -> Sinks):[/bold]")
    if is_solidity:
        taints = TaintAnalyzer.analyze_solidity_function(fn_name, lines)
    else:
        taints = TaintAnalyzer.analyze_web_api_function(fn_name, lines)

    if taints:
        t_table = Table(expand=True)
        t_table.add_column("Source", style="cyan")
        t_table.add_column("Sink Expression", style="white")
        t_table.add_column("Line", justify="right", width=6)
        t_table.add_column("Sanitized", width=12)
        t_table.add_column("Risk Severity", width=12)

        for t in taints:
            san_text = Text("YES", style="green") if t.is_sanitized else Text("NO", style="bold red")
            sev_text = Text(t.severity, style="bold red" if t.severity == "CRITICAL" else "yellow")
            t_table.add_row(t.source_name, t.sink_expression[:40], str(t.sink_line), san_text, sev_text)
        console.print(t_table)
    else:
        console.print("  [green]No unconstrained taint flows reaching sensitive sinks.[/green]")

    # 4. Threat & Financial Exposure Risk Evaluation
    console.print(f"\n[bold]4. Quantitative Threat & CVSS v3.1 Exposure Matrix:[/bold]")
    category = VulnerabilityCategory.REENTRANCY if is_solidity else VulnerabilityCategory.IDOR
    score, vector, tier = CVSSScorer.calculate_score(category)
    console.print(Panel(
        f"[bold]CVSS v3.1 Base Score:[/bold] [bold red]{score} / 10.0[/bold red]\n"
        f"[bold]CVSS Vector:[/bold] [cyan]{vector}[/cyan]\n"
        f"[bold]Financial Exposure Tier:[/bold] [bold red]{tier}[/bold red]",
        title="Enterprise Risk Assessment",
        border_style="red"
    ))


@app.command()
def fuzz(
    target: str = typer.Argument(..., help="Path to smart contract .sol file"),
    runs: int = typer.Option(100, "--runs", "-r", help="Number of stateful fuzzing permutations"),
):
    """Run stateful property-based invariant fuzzing on a smart contract."""
    console.rule("[bold magenta]🎲 AuditAgent: Stateful Property & Invariant Fuzzer[/bold magenta]")
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Target file not found: {target}[/red]")
        raise typer.Exit(code=1)

    source_code = target_path.read_text(encoding="utf-8")
    fuzzer = StatefulInvariantFuzzer(source_code, iterations=runs)

    with console.status(f"[bold yellow]Fuzzing state invariants across {runs} call sequences...[/bold yellow]"):
        results = fuzzer.run_fuzzing()

    for res in results:
        status_style = "bold green" if res.passed else "bold red"
        status_label = "PASSED" if res.passed else "FAILED / BREACHED"

        console.print(Panel(
            f"[bold]Invariant:[/bold] {res.invariant_name}\n"
            f"[bold]Description:[/bold] {res.property_description}\n"
            f"[bold]Status:[/bold] [{status_style}]{status_label}[/{status_style}] (after {res.iterations_run} sequences)\n\n"
            f"{res.log}",
            title=f"Property: {res.invariant_name}",
            border_style="green" if res.passed else "red"
        ))

        if not res.passed and res.failure_counterexample:
            console.print("[bold yellow]💥 Minimal Fuzz Counterexample Sequence:[/bold yellow]")
            step_table = Table(expand=True)
            step_table.add_column("Step", width=6)
            step_table.add_column("Actor", style="cyan")
            step_table.add_column("Call", style="white")
            step_table.add_column("Value (ETH)", justify="right")

            for step in res.failure_counterexample:
                step_table.add_row(
                    str(step.step_number),
                    step.actor,
                    f"{step.function_name}({step.args if step.args else ''})",
                    f"{step.value_eth:.1f}"
                )
            console.print(step_table)
            console.print()


@app.command()
def compliance():
    """Display the SWC Registry, CWE, and OWASP compliance mapping table."""
    console.rule("[bold blue]📋 Security & Compliance Taxonomy Matrix[/bold blue]")
    table = Table(title="Standards & Classifications Mapping", expand=True)
    table.add_column("Category", style="cyan")
    table.add_column("SWC (Web3)", style="magenta")
    table.add_column("CWE (Universal)", style="yellow")
    table.add_column("OWASP", style="blue")
    table.add_column("Remediation Guideline", style="white")

    for cat, info in ComplianceRegistry.REGISTRY.items():
        table.add_row(
            cat.value,
            info["swc_id"],
            info["cwe_id"],
            info["owasp_category"],
            info["remediation_guideline"]
        )
    console.print(table)


@app.command("gas-audit")
def gas_audit(
    target: str = typer.Argument(..., help="Path to Solidity smart contract (.sol)"),
):
    """Analyze contract for MEV / front-running vulnerabilities and actionable Gas optimizations."""
    console.rule("[bold green]⛽ AuditAgent: MEV & Gas Optimization Engine[/bold green]")
    path = Path(target)
    if not path.exists():
        console.print(f"[red]Target file not found: {target}[/red]")
        raise typer.Exit(code=1)

    source_code = path.read_text(encoding="utf-8")
    items = GasMEVAnalyzer.analyze(source_code)

    if not items:
        console.print("[green]No obvious MEV vectors or gas optimizations detected.[/green]")
        return

    mev_items = [i for i in items if i.category == "MEV_VULNERABILITY"]
    gas_items = [i for i in items if i.category == "GAS_OPTIMIZATION"]

    if mev_items:
        console.print(f"\n[bold red]🚨 MEV & Front-Running Vulnerabilities ({len(mev_items)}):[/bold red]")
        m_table = Table(expand=True)
        m_table.add_column("Line", justify="right", width=6)
        m_table.add_column("Vulnerability Title", style="bold red")
        m_table.add_column("Severity", width=10)
        m_table.add_column("Impact & Recommendation", style="white")

        for m in mev_items:
            m_table.add_row(
                str(m.line_number),
                m.title,
                Text(m.severity, style="bold red"),
                f"{m.description}\n[green]Fix:[/green] {m.recommendation}"
            )
        console.print(m_table)

    if gas_items:
        console.print(f"\n[bold yellow]⚡ Gas Optimization Opportunities ({len(gas_items)}):[/bold yellow]")
        g_table = Table(expand=True)
        g_table.add_column("Line", justify="right", width=6)
        g_table.add_column("Optimization", style="yellow")
        g_table.add_column("Estimated Savings", style="bold green", width=22)
        g_table.add_column("Recommendation", style="white")

        for g in gas_items:
            g_table.add_row(
                str(g.line_number),
                g.title,
                g.estimated_gas_savings,
                f"{g.description}\n[green]Action:[/green] {g.recommendation}"
            )
        console.print(g_table)


@app.command()
def serve(
    report: str = typer.Argument("audit_report_demo.html", help="Path to generated HTML audit report"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to serve the dashboard on"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not automatically open browser"),
):
    """Launch local HTTP server to view the interactive HTML security dashboard."""
    DashboardServer.start(report_path=report, port=port, open_browser=not no_browser)


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
          uv run audit-agent scan . --output audit-summary.md --html audit-dashboard.html --sarif audit-results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit-results.sarif

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
        comp = ComplianceRegistry.get_compliance_info(f.hypothesis.category)
        md.append(f"### [{f.hypothesis.severity.value.upper()}] {f.hypothesis.id}: {f.hypothesis.title}\n")
        md.append(f"- **Standard**: `{comp['swc_id']}` / `{comp['cwe_id']}` ({comp['owasp_category']})")
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
