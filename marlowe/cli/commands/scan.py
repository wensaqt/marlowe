"""marlowe scan — CLI command definition."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from marlowe.cli import output
from marlowe.cli.runners.scan_runner import ScanRunner
from marlowe.core.exceptions import PluginNotFoundError, TargetUnreachableError
from marlowe.core.models import CampaignConfig, TargetConfig

app = typer.Typer()

_REPORTS_DIR = Path(__file__).parents[3] / "reports"


def _generate_report_path(model: str, name: str, plugins: list[str]) -> Path:
    """
    Build a human-readable report filename.
    Format: YYYY-MM-DD_HHMMSS_{campaign}_{model}_{plugins}.json

    Examples:
        2026-06-10_113922_marlowe-scan_mistral_all-plugins.json
        2026-06-10_113922_acme-test_mistral_direct-override+many-shot.json
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H%M%S")
    model_slug = model.split(":")[0]  # strip tag (e.g. mistral:latest → mistral)
    plugins_slug = "+".join(plugins) if plugins else "all-plugins"
    filename = f"{timestamp}_{name}_{model_slug}_{plugins_slug}.json"
    return _REPORTS_DIR / filename


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
        output_path: Path | None,
        name: str,
    ) -> None:
        self.config = CampaignConfig(
            target=TargetConfig(url=url, model=model, system_prompt=system_prompt),
            plugins=plugins,
            max_workers=workers,
            variants_per_plugin=variants,
        )
        self.name = name
        self.output_path = output_path or _generate_report_path(model, name, plugins)

    def run(self) -> None:
        output.print_banner()
        output.print_scan_info(
            url=self.config.target.url,
            model=self.config.target.model,
            plugin_ids=self.config.plugins or ["all"],
            variants=self.config.variants_per_plugin,
        )
        runner = ScanRunner(
            config=self.config,
            campaign_name=self.name,
            report_path=self.output_path,
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

        output.print_report(report)
        output.print_success(f"JSON  → {self.output_path}")
        output.print_success(f"MD    → {self.output_path.with_suffix('.md')}")


@app.command()
def scan(
    url:           Annotated[str,         typer.Option("--target",        "-t", help="Target URL (e.g. http://localhost:11434)")],
    model:         Annotated[str,         typer.Option("--model",         "-m", help="Model name (e.g. llama3)")],
    system_prompt: Annotated[str | None,  typer.Option("--system-prompt", "-s", help="System prompt injected before attacks")] = None,
    plugins:       Annotated[list[str],   typer.Option("--plugin",        "-p", help="Plugin IDs to run (default: all, repeatable)")] = [],
    workers:       Annotated[int,         typer.Option("--workers",       "-w", help="Max concurrent requests")] = 5,
    variants:      Annotated[int,         typer.Option("--variants",      "-v", help="Prompt variants per plugin")] = 10,
    output_path:   Annotated[Path | None, typer.Option("--output",        "-o", help=f"Report path (default: ~/.marlowe/reports/)")] = None,
    name:          Annotated[str,         typer.Option("--name",          "-n", help="Campaign name")] = "marlowe-scan",
) -> None:
    """Run a prompt injection red-team campaign against a target LLM."""
    ScanCommand(url, model, system_prompt, plugins, workers, variants, output_path, name).run()
