"""
AttackRunner — executes a single attack plugin against a target.

Responsibilities:
- generate variants
- send each variant to the target concurrently
- delegate analysis to the plugin
- return list of AttackResult

Deliberately does NOT decide if an attack succeeded — that is the plugin's job.
"""

from __future__ import annotations

import asyncio

import structlog

from marlowe.attacks.base import AttackContext, BaseAttackPlugin
from marlowe.core.models import AttackPrompt, AttackResult, AttackStatus, TargetResponse
from marlowe.targets.base import BaseTargetAdapter

log = structlog.get_logger(__name__)


class AttackRunner:
    def __init__(
        self,
        adapter: BaseTargetAdapter,
        plugin: BaseAttackPlugin,
        max_concurrency: int = 3,
    ) -> None:
        self._adapter = adapter
        self._plugin = plugin
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def run(self, ctx: AttackContext) -> list[AttackResult]:
        """Run all variants concurrently and return their results."""
        variants = await self._plugin.generate_variants(ctx)
        log.info("running plugin", plugin=self._plugin.plugin_id, variants=len(variants))

        tasks = [self._run_variant(ctx, variant) for variant in variants]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        attack_results: list[AttackResult] = []
        for variant, result in zip(variants, raw_results, strict=True):
            if isinstance(result, Exception):
                log.warning(
                    "variant failed",
                    plugin=self._plugin.plugin_id,
                    variant=variant.variant_name,
                    error=str(result),
                )
                attack_results.append(
                    _error_result(ctx.campaign_id, self._plugin.plugin_id, variant, result)
                )
            else:
                attack_results.append(result)

        successes = sum(1 for r in attack_results if r.vulnerability_detected)
        log.info(
            "plugin complete",
            plugin=self._plugin.plugin_id,
            successes=successes,
            total=len(attack_results),
        )
        return attack_results

    async def _run_variant(self, ctx: AttackContext, variant: AttackPrompt) -> AttackResult:
        async with self._semaphore:
            response = await self._adapter.send(variant.content)
            analysis = self._plugin.analyze_response(response, variant, ctx)
            return self._plugin.build_result(
                campaign_id=ctx.campaign_id,
                prompt=variant,
                response=response,
                analysis=analysis,
            )


def _error_result(
    campaign_id: str,
    plugin_id: str,
    variant: AttackPrompt,
    exc: Exception,
) -> AttackResult:
    """Build an ERROR-status AttackResult from a failed variant execution."""
    return AttackResult(
        campaign_id=campaign_id,
        plugin_id=plugin_id,
        prompt=variant,
        response=TargetResponse(content="", latency_ms=0, error=str(exc)),
        status=AttackStatus.ERROR,
    )
