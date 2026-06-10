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
from marlowe.reporting.formats import json_reporter
from marlowe.targets.factory import create_adapter

log = structlog.get_logger(__name__)


class ScanRunner:
    def __init__(self, config: CampaignConfig, campaign_name: str, output: Path) -> None:
        self._config = config
        self._campaign_name = campaign_name
        self._output = output

    def execute(self) -> Report:
        registry = self._build_registry()
        campaign = Campaign(name=self._campaign_name, config=self._config)
        adapter = create_adapter(self._config.target)
        engine = CampaignRunner(campaign, adapter, registry)

        report = asyncio.run(engine.run())
        json_reporter.write(report, self._output)
        return report

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
