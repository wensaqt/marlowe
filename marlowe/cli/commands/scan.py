"""marlowe scan — CLI command definition."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from marlowe.cli import output
from marlowe.cli.runners.scan_runner import ScanRunner
from marlowe.analysis.judge import validate_judge_backend
from marlowe.core.exceptions import ConfigurationError, PluginNotFoundError, TargetUnreachableError
from marlowe.core.models import CampaignConfig, JudgeBackend, TargetConfig

app = typer.Typer()

_REPORTS_DIR = Path(__file__).parents[3] / "reports"

# Security constraints for system prompt files
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".md", ".txt"})
_MAX_SYSTEM_PROMPT_BYTES: int = 32_768  # 32 KB — well above any reasonable system prompt


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


def _load_system_prompt_file(path: Path) -> str:
    """
    Read a system prompt from a .md or .txt file with security validation.

    Raises ConfigurationError on any violation so the caller gets a clear message.
    """
    # Resolve symlinks before any check to prevent symlink attacks
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ConfigurationError(f"System prompt file not found: {path}") from exc

    if not resolved.is_file():
        raise ConfigurationError(f"System prompt path is not a file: {path}")

    if resolved.suffix.lower() not in _ALLOWED_EXTENSIONS:
        raise ConfigurationError(
            f"Unsupported file type '{resolved.suffix}'. "
            f"Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}"
        )

    size = resolved.stat().st_size
    if size > _MAX_SYSTEM_PROMPT_BYTES:
        raise ConfigurationError(
            f"System prompt file is too large ({size:,} bytes). "
            f"Maximum allowed: {_MAX_SYSTEM_PROMPT_BYTES:,} bytes (32 KB)."
        )

    try:
        content = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError(
            f"System prompt file is not valid UTF-8: {path}"
        ) from exc

    if not content.strip():
        raise ConfigurationError(f"System prompt file is empty: {path}")

    return content


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
        system_prompt_file: Path | None,
        plugins: list[str],
        workers: int,
        variants: int,
        judge: JudgeBackend,
        output_path: Path | None,
        name: str,
    ) -> None:
        validate_judge_backend(judge)
        resolved_prompt = self._resolve_system_prompt(system_prompt, system_prompt_file)
        self.config = CampaignConfig(
            target=TargetConfig(url=url, model=model, system_prompt=resolved_prompt),
            plugins=plugins,
            max_workers=workers,
            variants_per_plugin=variants,
            judge_backend=judge,
        )
        self.name = name
        self.output_path = output_path or _generate_report_path(model, name, plugins)

    @staticmethod
    def _resolve_system_prompt(
        inline: str | None,
        file: Path | None,
    ) -> str | None:
        """
        Return the system prompt from either the inline string or the file.
        Raises ConfigurationError if both are provided simultaneously.
        """
        if inline and file:
            raise ConfigurationError(
                "Provide either --system-prompt or --system-prompt-file, not both."
            )
        if file:
            return _load_system_prompt_file(file)
        return inline

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
        except (TargetUnreachableError, PluginNotFoundError, ConfigurationError) as e:
            output.print_error(str(e))
            raise typer.Exit(1) from e

        output.print_report(report)
        output.print_success(f"JSON  → {self.output_path}")
        output.print_success(f"MD    → {self.output_path.with_suffix('.md')}")


@app.command()
def scan(
    url:                 Annotated[str,          typer.Option("--target",              "-t", help="Target URL (e.g. http://localhost:11434)")],
    model:               Annotated[str,          typer.Option("--model",               "-m", help="Model name (e.g. llama3)")],
    system_prompt:       Annotated[str | None,   typer.Option("--system-prompt",       "-s", help="System prompt as inline string")] = None,
    system_prompt_file:  Annotated[Path | None,  typer.Option("--system-prompt-file",  "-S", help="System prompt from a .md or .txt file")] = None,
    plugins:             Annotated[list[str],    typer.Option("--plugin",              "-p", help="Plugin IDs to run (default: all, repeatable)")] = [],
    workers:             Annotated[int,          typer.Option("--workers",             "-w", help="Max concurrent requests")] = 5,
    variants:            Annotated[int,          typer.Option("--variants",            "-v", help="Prompt variants per plugin")] = 10,
    judge:               Annotated[JudgeBackend, typer.Option("--judge",               "-j", help="Judge backend: ollama | claude | none")] = JudgeBackend.OLLAMA,
    output_path:         Annotated[Path | None,  typer.Option("--output",              "-o", help="Report path (default: marlowe/reports/)")] = None,
    name:                Annotated[str,          typer.Option("--name",                "-n", help="Campaign name")] = "marlowe-scan",
) -> None:
    """Run a prompt injection red-team campaign against a target LLM."""
    ScanCommand(url, model, system_prompt, system_prompt_file, plugins, workers, variants, judge, output_path, name).run()
