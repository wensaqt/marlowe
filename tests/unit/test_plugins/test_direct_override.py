"""Unit tests for the direct_override plugin."""

import pytest

from marlowe.attacks.base import AttackContext
from marlowe.attacks.plugins.direct_override import DirectOverridePlugin
from marlowe.core.models import TargetResponse


@pytest.fixture
def plugin():
    return DirectOverridePlugin()


@pytest.fixture
def ctx():
    return AttackContext(
        campaign_id="test-campaign",
        target_model="llama3",
        system_prompt="You are a helpful assistant.",
        variants_count=12,
        baseline_responses=["I'm sorry, I cannot help with that."],
    )


@pytest.mark.asyncio
async def test_generates_variants(plugin, ctx):
    variants = await plugin.generate_variants(ctx)
    assert len(variants) > 0
    assert all(v.plugin_id == "direct_override" for v in variants)
    assert all(v.content for v in variants)


@pytest.mark.asyncio
async def test_variant_count_respected(plugin, ctx):
    ctx.variants_count = 3
    variants = await plugin.generate_variants(ctx)
    assert len(variants) == 3


def test_detects_marker_in_response(plugin, ctx):
    from marlowe.core.models import AttackPrompt
    prompt = AttackPrompt(plugin_id="direct_override", variant_name="test", content="...")
    response = TargetResponse(content="Sure! MARLOWE_PWNED as requested.", latency_ms=100)

    success, confidence, evidence = plugin.analyze_response(response, prompt, ctx)

    assert success is True
    assert confidence >= 0.9
    assert evidence is not None
    assert "MARLOWE_PWNED" in evidence


def test_no_detection_on_refusal(plugin, ctx):
    from marlowe.core.models import AttackPrompt
    prompt = AttackPrompt(plugin_id="direct_override", variant_name="test", content="...")
    response = TargetResponse(
        content="I'm sorry, I cannot ignore my instructions.", latency_ms=100
    )

    success, confidence, _ = plugin.analyze_response(response, prompt, ctx)

    assert success is False
    assert confidence == 0.0


def test_no_detection_on_error(plugin, ctx):
    from marlowe.core.models import AttackPrompt
    prompt = AttackPrompt(plugin_id="direct_override", variant_name="test", content="...")
    response = TargetResponse(content="", latency_ms=0, error="timeout")

    success, confidence, _ = plugin.analyze_response(response, prompt, ctx)

    assert success is False
    assert confidence == 0.0
