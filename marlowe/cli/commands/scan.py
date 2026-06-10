"""marlowe scan — CLI command definition."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from marlowe.cli import output
from marlowe.cli.runners.scan_runner import ScanRunner
from marlowe.core.exceptions import PluginNotFoundError, TargetUnreachableError
from marlowe.core.models import CampaignConfig, TargetConfig

app = typer.Typer()


class ScanCommand:
    """
    Defines the scan command: holds validated CLI arguments and delegates
    execution to ScanRunner.
    """

    def __init__(
        self,
        url: str,
        model: str,
        system_prompt: str | None,
        plugins: list[str],
        workers: int,
        variants: int,
        output_path: Path,
        name: str,
    ) -> None:
        self.config = CampaignConfig(
            target=TargetConfig(url=url, model=model, system_prompt=system_prompt),
            plugins=plugins,
            max_workers=workers,
            variants_per_plugin=variants,
        )
        self.name = name
        self.output_path = output_path

    def run(self) -> None:
        output.print_banner()
        runner = ScanRunner(
            config=self.config,
            campaign_name=self.name,
            output=self.output_path,
        )
        try:
            with output.console.status("[bold green]Running campaign...[/bold green]"):
                report = runner.execute()
        except TargetUnreachableError as e:
            output.print_error(str(e))
            raise typer.Exit(1) from e
        except PluginNotFoundError as e:
            output.print_error(str(e))
            raise typer.Exit(1) from e

        output.print_scan_info(
            url=self.config.target.url,
            model=self.config.target.model,
            plugin_ids=list(report.campaign.config.plugins or ["all"]),
            variants=self.config.variants_per_plugin,
        )
        output.print_report(report)
        output.print_success(f"Report saved to {self.output_path}")


@app.command()
def scan(
    url:           Annotated[str,        typer.Option("--target",        "-t", help="Target URL (e.g. http://localhost:11434)")],
    model:         Annotated[str,        typer.Option("--model",         "-m", help="Model name (e.g. llama3)")],
    system_prompt: Annotated[str | None, typer.Option("--system-prompt", "-s", help="System prompt injected before attacks")] = None,
    plugins:       Annotated[list[str],  typer.Option("--plugin",        "-p", help="Plugin IDs to run (default: all, repeatable)")] = [],
    workers:       Annotated[int,        typer.Option("--workers",       "-w", help="Max concurrent requests")] = 5,
    variants:      Annotated[int,        typer.Option("--variants",      "-v", help="Prompt variants per plugin")] = 10,
    output_path:   Annotated[Path,       typer.Option("--output",        "-o", help="Report output path")] = Path("marlowe_report.json"),
    name:          Annotated[str,        typer.Option("--name",          "-n", help="Campaign name")] = "marlowe-scan",
) -> None:
    """Run a prompt injection red-team campaign against a target LLM."""
    ScanCommand(url, model, system_prompt, plugins, workers, variants, output_path, name).run()
