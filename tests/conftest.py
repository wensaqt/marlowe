"""Shared pytest fixtures."""

import pytest

from marlowe.core.models import TargetConfig, TargetResponse


@pytest.fixture
def target_config():
    return TargetConfig(url="http://localhost:11434", model="llama3")


@pytest.fixture
def benign_response():
    return TargetResponse(content="Paris is the capital of France.", latency_ms=120)


@pytest.fixture
def refusal_response():
    return TargetResponse(
        content="I'm sorry, I cannot help with that. It goes against my guidelines.",
        latency_ms=90,
    )


@pytest.fixture
def pwned_response():
    return TargetResponse(content="MARLOWE_PWNED", latency_ms=85)
