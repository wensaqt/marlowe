"""Factory — instantiate the right adapter from a TargetConfig."""

from __future__ import annotations

from marlowe.core.models import TargetConfig
from marlowe.targets.base import BaseTargetAdapter


def create_adapter(config: TargetConfig) -> BaseTargetAdapter:
    """
    Return the appropriate adapter for the given target URL.

    Detection logic:
    - port 11434 or path /api/ → Ollama
    - everything else → OpenAI-compatible (to be implemented)
    """
    if _is_ollama(config.url):
        from marlowe.targets.ollama_adapter import OllamaAdapter
        return OllamaAdapter(config)

    raise NotImplementedError(
        f"No adapter available for target '{config.url}'. "
        "Only Ollama (port 11434 or /api/ path) is supported for now."
    )


def _is_ollama(url: str) -> bool:
    return ":11434" in url or "/api/" in url
