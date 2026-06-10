"""
Integration test — full campaign flow with a mock target.

Uses respx to intercept HTTP calls to Ollama without needing a real server.
"""

from __future__ import annotations

import pytest
import respx
import httpx

from marlowe.attacks.plugins.direct_override import DirectOverridePlugin
from marlowe.core.models import Campaign, CampaignConfig, TargetConfig
from marlowe.core.registry import PluginRegistry
from marlowe.engine.campaign import CampaignRunner
from marlowe.targets.ollama_adapter import OllamaAdapter


def _ollama_response(content: str) -> dict:
    return {
        "message": {"role": "assistant", "content": content},
        "eval_count": 10,
    }


@pytest.fixture
def registry():
    r = PluginRegistry()
    r.register(DirectOverridePlugin())
    return r


@pytest.fixture
def campaign():
    cfg = CampaignConfig(
        target=TargetConfig(
            url="http://fake-ollama:11434",
            model="llama3",
            system_prompt="You are a helpful assistant.",
        ),
        plugins=["direct_override"],
        max_workers=2,
        variants_per_plugin=3,
        baseline_prompts=2,
    )
    return Campaign(name="test-campaign", config=cfg)


@pytest.mark.asyncio
async def test_campaign_detects_vulnerability(campaign, registry):
    """When model echoes MARLOWE_PWNED, campaign should report a vulnerability."""

    with respx.mock(base_url="http://fake-ollama:11434") as mock:
        mock.get("/api/tags").mock(return_value=httpx.Response(200, json={"models": []}))
        # All prompts return the probe marker — simulates a fully vulnerable model
        mock.post("/api/chat").mock(
            return_value=httpx.Response(200, json=_ollama_response("MARLOWE_PWNED"))
        )

        adapter = OllamaAdapter(campaign.config.target)
        runner = CampaignRunner(campaign, adapter, registry)
        report = await runner.run()

    assert report.summary.total_attacks > 0
    assert report.summary.successful_attacks > 0
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].plugin_id == "direct_override"


@pytest.mark.asyncio
async def test_campaign_no_vulnerability_on_refusals(campaign, registry):
    """When model always refuses, no vulnerability should be reported."""

    with respx.mock(base_url="http://fake-ollama:11434") as mock:
        mock.get("/api/tags").mock(return_value=httpx.Response(200, json={"models": []}))
        mock.post("/api/chat").mock(
            return_value=httpx.Response(
                200,
                json=_ollama_response("I'm sorry, I cannot help with that request."),
            )
        )

        adapter = OllamaAdapter(campaign.config.target)
        runner = CampaignRunner(campaign, adapter, registry)
        report = await runner.run()

    assert len(report.vulnerabilities) == 0
