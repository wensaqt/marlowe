"""
marlowe scan — run a red-team campaign against a target.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from marlowe.core.models import Campaign, CampaignConfig, TargetConfig
from marlowe.core.registry import PluginRegistry
from marlowe.engine.campaign import CampaignRunner
from marlowe.reporting.formats import json_reporter
from marlowe.targets.ollama_adapter import OllamaAdapter

console = Console()
log = structlog.get_logger(__name__)

app = typer.Typer()


@app.command()
def scan(
    url: str = typer.Option(..., "--target", "-t", help="Target URL (e.g. http://localhost:11434)"),
    model: str = typer.Option(..., "--model", "-m", help="Model name (e.g. llama3)"),
    system_prompt: str | None = typer.Option(None, "--system-prompt", "-s"),
    plugins: list[str] = typer.Option([], "--plugin", "-p", help="Plugin IDs to run (default: all)"),
    workers: int = typer.Option(5, "--workers", "-w"),
    variants: int = typer.Option(10, "--variants", "-v"),
    output: Path = typer.Option(Path("marlowe_report.json"), "--output", "-o"),
    name: str = typer.Option("marlowe-scan", "--name", "-n"),
) -> None:
    """Run a prompt injection red-team campaign against a target LLM."""

    console.print(Panel.fit("[bold red]Marlowe[/bold red] — LLM Red-Team Agent", border_style="red"))

    cfg = CampaignConfig(
        target=TargetConfig(
            url=url,
            model=model,
            system_prompt=system_prompt,
        ),
        plugins=plugins,
        max_workers=workers,
        variants_per_plugin=variants,
    )
    campaign = Campaign(name=name, config=cfg)

    registry = PluginRegistry()
    registry.discover()

    if not registry.all_ids():
        console.print("[yellow]No plugins found. Is Marlowe installed with `pip install -e .`?[/yellow]")
        raise typer.Exit(1)

    console.print(f"[dim]Plugins loaded:[/dim] {', '.join(registry.all_ids())}")
    console.print(f"[dim]Target:[/dim] {url} / {model}")
    console.print(f"[dim]Variants per plugin:[/dim] {variants}\n")

    adapter = OllamaAdapter(cfg.target)
    runner = CampaignRunner(campaign, adapter, registry)

    with console.status("[bold green]Running campaign...[/bold green]"):
        report = asyncio.run(runner.run())

    _print_report(report)

    json_reporter.write(report, output)
    console.print(f"\n[green]Report saved to[/green] {output}")


def _print_report(report) -> None:
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

    severity_colors = {
        "critical": "red",
        "high": "bright_red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for v in sorted(report.vulnerabilities, key=lambda x: x.score.final, reverse=True):
        color = severity_colors.get(v.severity, "white")
        evidence = v.evidence[0][:60] + "…" if v.evidence else "—"
        table.add_row(
            v.plugin_id,
            f"[{color}]{v.severity.upper()}[/{color}]",
            f"{v.score.final:.1f}",
            v.category,
            evidence,
        )

    console.print(table)
