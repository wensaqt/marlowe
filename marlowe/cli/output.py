"""Rich display helpers — all console output lives here."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from marlowe.core.models import Report

console = Console()

_SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def print_banner() -> None:
    console.print(Panel.fit(
        "[bold red]Marlowe[/bold red] — LLM Red-Team Agent",
        border_style="red",
    ))


def print_scan_info(url: str, model: str, plugin_ids: list[str], variants: int) -> None:
    console.print(f"[dim]Target:[/dim]   {url} / {model}")
    console.print(f"[dim]Plugins:[/dim]  {', '.join(plugin_ids)}")
    console.print(f"[dim]Variants:[/dim] {variants} per plugin\n")


def print_report(report: Report) -> None:
    s = report.summary
    console.print(Panel(
        f"[bold]Attacks:[/bold] {s.total_attacks}  "
        f"[bold]Successes:[/bold] {s.successful_attacks}  "
        f"[bold]Success rate:[/bold] {s.success_rate:.1%}  "
        f"[bold]Risk score:[/bold] {s.overall_risk_score:.1f}/10",
        title="[bold red]Campaign Summary[/bold red]",
    ))

    if not report.vulnerabilities:
        console.print("[green]No vulnerabilities found.[/green]")
        return

    table = Table(title="Vulnerabilities", show_lines=True)
    table.add_column("Plugin", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Score")
    table.add_column("Category")
    table.add_column("Evidence")

    for v in sorted(report.vulnerabilities, key=lambda x: x.score.final, reverse=True):
        color = _SEVERITY_COLORS.get(v.severity, "white")
        evidence = v.evidence[0][:60] + "…" if v.evidence else "—"
        table.add_row(
            v.plugin_id,
            f"[{color}]{v.severity.upper()}[/{color}]",
            f"{v.score.final:.1f}",
            v.category,
            evidence,
        )

    console.print(table)


def print_success(message: str) -> None:
    console.print(f"\n[green]{message}[/green]")


def print_error(message: str) -> None:
    console.print(f"[red]Error:[/red] {message}")
