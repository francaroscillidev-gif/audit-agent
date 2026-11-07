"""Local HTTP server for interactive security dashboard visualization."""
import http.server
import socketserver
import webbrowser
from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()


class DashboardServer:
    """Serves the interactive HTML audit report over local HTTP."""

    @staticmethod
    def start(report_path: str = "audit_report_demo.html", port: int = 8080, open_browser: bool = True) -> None:
        path = Path(report_path)
        if not path.exists():
            console.print(f"[bold red]Report file not found:[/bold red] {report_path}")
            console.print("[yellow]Hint: Run 'audit-agent scan <target> --html report.html' first, or 'audit-agent demo'.[/yellow]")
            return

        report_dir = path.resolve().parent
        report_filename = path.name

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(report_dir), **kwargs)

            def log_message(self, format, *args):
                pass  # Suppress default server noise

        with socketserver.TCPServer(("", port), Handler) as httpd:
            url = f"http://localhost:{port}/{report_filename}"
            console.rule("[bold cyan]🌐 AuditAgent Live Dashboard Server[/bold cyan]")
            console.print(f"[bold green]Serving security dashboard at:[/bold green] [underline cyan]{url}[/underline cyan]")
            console.print("[dim]Press Ctrl+C to stop server[/dim]\n")

            if open_browser:
                webbrowser.open(url)

            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                console.print("\n[yellow]Dashboard server stopped.[/yellow]")
