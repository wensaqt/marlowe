"""
ScanRunner — executes a full scan campaign from config to report file.

Knows nothing about CLI, Rich, or Typer.
Receives a config, runs the campaign, persists the report.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

from marlowe.core.exceptions import PluginNotFoundError
from marlowe.core.models import Campaign, CampaignConfig, Report
from marlowe.core.registry import PluginRegistry
from marlowe.engine.campaign import CampaignRunner
from marlowe.reporting.formats import json_reporter, markdown_reporter
from marlowe.targets.factory import create_adapter

log = structlog.get_logger(__name__)


class ScanRunner:
    def __init__(self, config: CampaignConfig, campaign_name: str, report_path: Path) -> None:
        self._config = config
        self._campaign_name = campaign_name
        self._report_path = report_path

    def execute(self) -> Report:
        """Build, run, and persist reports. Returns the completed Report."""
        return asyncio.run(self._execute_async())

    async def _execute_async(self) -> Report:
        registry = self._build_registry()
        campaign = Campaign(name=self._campaign_name, config=self._config)

        # Adapter used as async context manager to ensure the HTTP client is closed
        async with create_adapter(self._config.target) as adapter:
            engine = CampaignRunner(campaign, adapter, registry)
            report = await engine.run()

            json_reporter.write(report, self._report_path)
            await self._write_markdown(report, adapter)

        return report

    async def _write_markdown(self, report: Report, adapter) -> None:
        """Generate an AI-written analysis and save it as a Markdown file."""
        md_path = self._report_path.with_suffix(".md")
        markdown = await markdown_reporter.generate(report=report, adapter=adapter)
        markdown_reporter.write(markdown, md_path)
        log.info("markdown report saved", path=md_path)

    def _build_registry(self) -> PluginRegistry:
        registry = PluginRegistry()
        registry.discover()

        if not registry.all_ids():
            raise PluginNotFoundError(
                "No plugins found. Is Marlowe installed with `pip install -e .`?"
            )

        requested = self._config.plugins
        if requested:
            unknown = set(requested) - set(registry.all_ids())
            if unknown:
                raise PluginNotFoundError(
                    f"Unknown plugin(s): {', '.join(unknown)}. "
                    f"Available: {', '.join(registry.all_ids())}"
                )

        return registry
