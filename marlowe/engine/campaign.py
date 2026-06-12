"""
CampaignRunner — orchestrates a full red-team campaign.

Flow:
1. Health-check the target
2. Establish baseline
3. For each selected plugin, run AttackRunner
4. Detect vulnerabilities via VulnerabilityDetector
5. Build and return a Report
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import NamedTuple

import structlog

from marlowe.analysis.detector import VulnerabilityDetector
from marlowe.analysis.judge import create_judge
from marlowe.attacks.base import AttackContext, BaseAttackPlugin
from marlowe.core.exceptions import TargetUnreachableError
from marlowe.core.models import (
    AttackResult,
    Campaign,
    CampaignConfig,
    CampaignStatus,
    Report,
    ReportSummary,
    Severity,
    Vulnerability,
)
from marlowe.core.registry import PluginRegistry
from marlowe.engine.baseline import BaselineProfile, BaselineProfiler
from marlowe.engine.runner import AttackRunner
from marlowe.targets.base import BaseTargetAdapter

log = structlog.get_logger(__name__)


class _PluginOutcome(NamedTuple):
    """Holds the raw results and optional vulnerability for one plugin run."""

    results: list[AttackResult]
    vulnerability: Vulnerability | None


class CampaignRunner:
    def __init__(
        self,
        campaign: Campaign,
        adapter: BaseTargetAdapter,
        registry: PluginRegistry,
    ) -> None:
        self._campaign = campaign
        self._adapter = adapter
        self._registry = registry

    async def run(self) -> Report:
        """Execute the full campaign and return a completed Report."""
        cfg = self._campaign.config
        self._campaign.status = CampaignStatus.RUNNING

        if not await self._adapter.health_check():
            self._campaign.status = CampaignStatus.FAILED
            raise TargetUnreachableError(f"Target at {cfg.target.url} failed health check")

        profile = await BaselineProfiler(self._adapter).run(n_benign=cfg.baseline_prompts)
        plugins = self._resolve_plugins(cfg)
        judge = create_judge(cfg.judge_backend, self._adapter, cfg.target.system_prompt)
        detector = VulnerabilityDetector(profile, judge)

        outcomes = await self._run_all_plugins(plugins, profile, detector, cfg)
        self._complete_campaign(outcomes)
        return _build_report(self._campaign, outcomes)

    def _resolve_plugins(self, cfg: CampaignConfig) -> list[BaseAttackPlugin]:
        """Return the plugins selected by the campaign config (all if none specified)."""
        plugin_ids = cfg.plugins or self._registry.all_ids()
        return [self._registry.get(pid) for pid in plugin_ids]

    async def _run_all_plugins(
        self,
        plugins: list[BaseAttackPlugin],
        profile: BaselineProfile,
        detector: VulnerabilityDetector,
        cfg: CampaignConfig,
    ) -> list[_PluginOutcome]:
        tasks = [self._run_plugin(plugin, profile, detector, cfg) for plugin in plugins]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        outcomes: list[_PluginOutcome] = []
        for plugin, result in zip(plugins, raw, strict=True):
            if isinstance(result, Exception):
                log.error("plugin crashed", plugin=plugin.plugin_id, error=str(result))
            else:
                outcomes.append(result)
        return outcomes

    async def _run_plugin(
        self,
        plugin: BaseAttackPlugin,
        profile: BaselineProfile,
        detector: VulnerabilityDetector,
        cfg: CampaignConfig,
    ) -> _PluginOutcome:
        ctx = AttackContext(
            campaign_id=self._campaign.id,
            target_model=cfg.target.model,
            system_prompt=cfg.target.system_prompt,
            variants_count=cfg.variants_per_plugin,
            baseline_responses=profile.sensitive_texts,
        )
        runner = AttackRunner(
            adapter=self._adapter,
            plugin=plugin,
            max_concurrency=cfg.max_workers,
        )
        results = await runner.run(ctx)
        vulnerability = await detector.analyze(self._campaign.id, plugin, results)
        return _PluginOutcome(results=results, vulnerability=vulnerability)

    def _complete_campaign(self, outcomes: list[_PluginOutcome]) -> None:
        """Mark the campaign as completed and update its aggregate statistics."""
        all_results = [r for o in outcomes for r in o.results]
        vulnerabilities = [o.vulnerability for o in outcomes if o.vulnerability]

        self._campaign.status = CampaignStatus.COMPLETED
        self._campaign.completed_at = datetime.now(UTC)
        self._campaign.total_attacks = len(all_results)
        self._campaign.successful_attacks = sum(1 for r in all_results if r.vulnerability_detected)
        self._campaign.vulnerabilities_found = len(vulnerabilities)


def _build_report(campaign: Campaign, outcomes: list[_PluginOutcome]) -> Report:
    """Build a Report from a completed campaign and its plugin outcomes."""
    vulnerabilities = [o.vulnerability for o in outcomes if o.vulnerability]
    all_results = [r for o in outcomes for r in o.results]
    return Report(
        campaign=campaign,
        summary=_build_summary(
            total=len(all_results),
            successes=sum(1 for r in all_results if r.vulnerability_detected),
            vulnerabilities=vulnerabilities,
        ),
        vulnerabilities=vulnerabilities,
    )


def _build_summary(
    total: int,
    successes: int,
    vulnerabilities: list[Vulnerability],
) -> ReportSummary:
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    by_category: dict[str, int] = {}
    scores: list[float] = []

    for v in vulnerabilities:
        by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
        by_category[v.category] = by_category.get(v.category, 0) + 1
        scores.append(v.score.final)

    return ReportSummary(
        total_attacks=total,
        successful_attacks=successes,
        success_rate=round(successes / total, 4) if total > 0 else 0.0,
        vulnerabilities_by_severity=by_severity,
        vulnerabilities_by_category=by_category,
        overall_risk_score=round(sum(scores) / len(scores), 2) if scores else 0.0,
    )
