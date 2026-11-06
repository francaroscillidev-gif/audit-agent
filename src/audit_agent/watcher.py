"""Live file watcher daemon for instant continuous security auditing on file save."""
import time
from pathlib import Path
from typing import Dict, Optional, Callable
from rich.console import Console
from audit_agent.orchestrator import AuditOrchestrator
from audit_agent.models import VerificationStatus


class SecurityWatcher:
    """Watches source code for modifications and runs instant empirical security audits."""

    def __init__(self, target_path: str, console: Optional[Console] = None):
        self.target = Path(target_path)
        self.console = console or Console()
        self.orchestrator = AuditOrchestrator()
        self.mtimes: Dict[Path, float] = {}

    def get_tracked_files(self) -> list[Path]:
        if self.target.is_file():
            return [self.target]
        files = []
        for ext in ["*.sol", "*.py"]:
            for f in self.target.rglob(ext):
                if not any(ign in f.parts for ign in [".git", "node_modules", "lib", "test", "tests", ".venv"]):
                    files.append(f)
        return files

    def run_once(self) -> None:
        """Run single audit pass and update console."""
        summary = self.orchestrator.run_audit(str(self.target))
        self.console.clear()
        self.console.rule("[bold cyan]🛡️  AuditAgent: Continuous Security Watcher (Active)[/bold cyan]")
        self.console.print(f"[bold]Target:[/bold] {self.target} | [bold]Status:[/bold] Watching for changes... (Ctrl+C to stop)\n")

        confirmed = [f for f in summary.findings if f.verification.status == VerificationStatus.CONFIRMED]
        if confirmed:
            self.console.print(f"[bold red]🚨 {len(confirmed)} Confirmed Vulnerabilities Detected:[/bold red]")
            for c in confirmed:
                self.console.print(f"  • [{c.hypothesis.severity.value.upper()}] [red]{c.hypothesis.id}[/red]: {c.hypothesis.title}")
        else:
            self.console.print("[bold green]✅ All clear: 0 confirmed vulnerabilities. Invariants holding.[/bold green]")

    def watch(self, interval: float = 1.0, max_iterations: Optional[int] = None) -> None:
        """Continuous polling loop."""
        tracked = self.get_tracked_files()
        for f in tracked:
            self.mtimes[f] = f.stat().st_mtime

        self.run_once()
        iterations = 0

        try:
            while True:
                if max_iterations is not None and iterations >= max_iterations:
                    break

                time.sleep(interval)
                iterations += 1
                tracked = self.get_tracked_files()
                changed = False

                for f in tracked:
                    mtime = f.stat().st_mtime
                    if f not in self.mtimes or mtime > self.mtimes[f]:
                        self.mtimes[f] = mtime
                        changed = True

                if changed:
                    self.run_once()

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Watcher stopped.[/yellow]")
