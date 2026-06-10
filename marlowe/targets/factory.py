"""Factory — instantiate the right target adapter from a TargetConfig."""

from __future__ import annotations

from urllib.parse import urlparse

from marlowe.core.exceptions import ConfigurationError
from marlowe.core.models import TargetConfig
from marlowe.targets.base import BaseTargetAdapter

_OLLAMA_DEFAULT_PORT = 11434


def create_adapter(config: TargetConfig) -> BaseTargetAdapter:
    """
    Return the appropriate adapter for the given target URL.

    Detection logic:
    - Port 11434 → Ollama
    - everything else → raises ConfigurationError until more adapters are implemented
    """
    if _is_ollama(config.url):
        from marlowe.targets.ollama_adapter import OllamaAdapter
        return OllamaAdapter(config)

    raise ConfigurationError(
        f"No adapter available for target '{config.url}'. "
        "Only Ollama (port 11434) is supported. "
        "Pass --target http://<host>:11434 or implement a custom adapter."
    )


def _is_ollama(url: str) -> bool:
    """Return True if the URL points to an Ollama instance (port 11434)."""
    return urlparse(url).port == _OLLAMA_DEFAULT_PORT
