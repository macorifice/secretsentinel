"""Colored console output built with Rich."""

from __future__ import annotations

from typing import IO, List, Optional

from rich.console import Console
from rich.table import Table

from ..engine.models import Finding

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}


def render_console(findings: List[Finding], file: Optional[IO[str]] = None) -> None:
    """Print findings as a table. Colors are disabled automatically when not a TTY."""
    console = Console(file=file, highlight=False)
    if not findings:
        console.print("[green]No secrets found.[/green]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule")
    table.add_column("Location", overflow="fold")
    table.add_column("Preview")
    table.add_column("CWE", no_wrap=True)
    for f in findings:
        location = f"{f.path}:{f.line}:{f.column}"
        if f.commit:
            location += f"\n(commit {f.commit})"
        table.add_row(
            f"[{SEVERITY_STYLE.get(f.severity, '')}]{f.severity.upper()}[/]",
            f.rule_id,
            location,
            f.redacted,
            f.cwe,
        )
    console.print(table)
    console.print(f"[bold]{len(findings)} potential secret(s) found.[/bold]")
