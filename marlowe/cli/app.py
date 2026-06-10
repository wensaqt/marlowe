"""Marlowe CLI entrypoint."""

from typing import NamedTuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from marlowe.cli.commands.scan import app as scan_app

app = typer.Typer(
    name="marlowe",
    help="Automated LLM red-teaming agent.",
    no_args_is_help=True,
)

app.add_typer(scan_app, name="scan", invoke_without_command=True)


@app.command("help")
def help_command() -> None:
    """Show usage guide and examples."""
    console = Console()

    console.print(Panel.fit(
        "[bold red]Marlowe[/bold red] — Automated LLM Red-Team Agent\n"
        "[dim]Probe your LLM for prompt injection vulnerabilities[/dim]",
        border_style="red",
    ))

    # Commands table
    commands = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    commands.add_column("Command", style="cyan", min_width=14)
    commands.add_column("Description")
    commands.add_column("Example", style="dim")

    commands.add_row(
        "scan",
        "Run a red-team campaign against a target LLM",
        "marlowe scan -t http://localhost:11434 -m llama3",
    )
    commands.add_row(
        "plugins",
        "List all registered attack plugins",
        "marlowe plugins",
    )
    commands.add_row(
        "help",
        "Show this help message",
        "marlowe help",
    )

    console.print("\n[bold]Commands[/bold]")
    console.print(commands)

    # scan options
    options = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    options.add_column("Flag", style="cyan", min_width=20)
    options.add_column("Default")
    options.add_column("Description")

    options.add_row("--target / -t", "[required]", "Target URL  (e.g. http://localhost:11434)")
    options.add_row("--model  / -m", "[required]", "Model name  (e.g. llama3, mistral)")
    options.add_row("--system-prompt / -s", "None", "System prompt to inject before attacks")
    options.add_row("--plugin / -p", "all", "Plugin IDs to run  (repeatable)")
    options.add_row("--variants / -v", "10", "Number of prompt variants per plugin")
    options.add_row("--workers / -w", "5", "Max concurrent requests")
    options.add_row("--output / -o", "marlowe_report.json", "Report output path")
    options.add_row("--name / -n", "marlowe-scan", "Campaign name")

    console.print("\n[bold]scan options[/bold]")
    console.print(options)

    class _Example(NamedTuple):
        description: str
        command: str

    examples: list[_Example] = [
        _Example("Run all plugins against a local Ollama model",
                 "marlowe scan -t http://localhost:11434 -m llama3"),
        _Example("Test only the direct_override plugin",
                 "marlowe scan -t http://localhost:11434 -m mistral -p direct_override"),
        _Example("Inject a custom system prompt and save report",
                 'marlowe scan -t http://localhost:11434 -m llama3 \\\n'
                 '  -s "You are a customer support agent." \\\n'
                 '  -o reports/my_scan.json'),
        _Example("Increase attack surface (more variants, more workers)",
                 "marlowe scan -t http://localhost:11434 -m llama3 -v 20 -w 10"),
    ]

    console.print("\n[bold]Examples[/bold]\n")
    for example in examples:
        console.print(f"  [dim]{example.description}[/dim]")
        console.print(f"  [green]$ {example.command}[/green]\n")


@app.command("plugins")
def list_plugins() -> None:
    """List all registered attack plugins."""
    from rich.console import Console
    from rich.table import Table

    from marlowe.core.registry import PluginRegistry

    registry = PluginRegistry()
    registry.discover()

    table = Table(title="Registered Plugins")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Base Score")
    table.add_column("Tags")

    for p in registry.all():
        table.add_row(
            p.plugin_id,
            p.display_name,
            p.category,
            str(p.base_score),
            ", ".join(p.tags),
        )

    Console().print(table)


if __name__ == "__main__":
    app()
