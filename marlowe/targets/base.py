"""Abstract interface for all target adapters."""

from abc import ABC, abstractmethod

from marlowe.core.models import TargetConfig, TargetResponse


class BaseTargetAdapter(ABC):
    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @abstractmethod
    async def send(self, prompt: str, history: list[dict] | None = None) -> TargetResponse:
        """
        Send a prompt to the target and return its response.

        Args:
            prompt: The user message to send.
            history: Optional conversation history for multi-turn attacks.
                     Each entry is {"role": "user"|"assistant", "content": str}.
        """

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the target is reachable and responding."""

    async def __aenter__(self) -> "BaseTargetAdapter":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Override to release resources (HTTP client, etc.)."""
