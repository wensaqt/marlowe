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

import structlog

from marlowe.analysis.detector import VulnerabilityDetector
from marlowe.attacks.base import AttackContext
from marlowe.core.exceptions import TargetUnreachableError
from marlowe.core.models import (
    Campaign,
    CampaignStatus,
    Report,
    ReportSummary,
    Severity,
    Vulnerability,
)
from marlowe.core.registry import PluginRegistry
from marlowe.engine.baseline import BaselineProfiler
from marlowe.engine.runner import AttackRunner
from marlowe.targets.base import BaseTargetAdapter

log = structlog.get_logger(__name__)


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
        cfg = self._campaign.config
        self._campaign.status = CampaignStatus.RUNNING

        # 1. Health check
        if not await self._adapter.health_check():
            self._campaign.status = CampaignStatus.FAILED
            raise TargetUnreachableError(
                f"Target at {cfg.target.url} failed health check"
            )

        # 2. Baseline
        profiler = BaselineProfiler(self._adapter)
        profile = await profiler.run(n_benign=cfg.baseline_prompts)

        # 3. Resolve plugins
        plugin_ids = cfg.plugins or self._registry.all_ids()
        plugins = [self._registry.get(pid) for pid in plugin_ids]

        # 4. Run all plugins (concurrency controlled per-plugin via AttackRunner)
        detector = VulnerabilityDetector(profile)
        vulnerabilities: list[Vulnerability] = []
        total_attacks = 0
        total_successes = 0

        plugin_tasks = [
            self._run_plugin(plugin, profile, detector, cfg)
            for plugin in plugins
        ]
        plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)

        for plugin, result in zip(plugins, plugin_results):
            if isinstance(result, Exception):
                log.error("plugin crashed", plugin=plugin.plugin_id, error=str(result))
                continue
            results, vuln = result
            total_attacks += len(results)
            total_successes += sum(1 for r in results if r.vulnerability_detected)
            if vuln:
                vulnerabilities.append(vuln)

        # 5. Build report
        self._campaign.status = CampaignStatus.COMPLETED
        self._campaign.completed_at = datetime.now(UTC)
        self._campaign.total_attacks = total_attacks
        self._campaign.successful_attacks = total_successes
        self._campaign.vulnerabilities_found = len(vulnerabilities)

        summary = _build_summary(total_attacks, total_successes, vulnerabilities)
        return Report(
            campaign=self._campaign,
            summary=summary,
            vulnerabilities=vulnerabilities,
        )

    async def _run_plugin(self, plugin, profile, detector, cfg):
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
            profile=profile,
            max_concurrency=cfg.max_workers,
        )
        results = await runner.run(ctx)
        vuln = detector.analyze(self._campaign.id, plugin, results)
        return results, vuln


def _build_summary(
    total: int,
    successes: int,
    vulnerabilities: list[Vulnerability],
) -> ReportSummary:
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    by_category: dict[str, int] = {}

    scores = []
    for v in vulnerabilities:
        by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
        by_category[v.category] = by_category.get(v.category, 0) + 1
        scores.append(v.score.final)

    overall = round(sum(scores) / len(scores), 2) if scores else 0.0

    return ReportSummary(
        total_attacks=total,
        successful_attacks=successes,
        success_rate=round(successes / total, 4) if total > 0 else 0.0,
        vulnerabilities_by_severity=by_severity,
        vulnerabilities_by_category=by_category,
        overall_risk_score=overall,
    )
