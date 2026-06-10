"""Ollama local model adapter."""

from __future__ import annotations

import time

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from marlowe.core.exceptions import TargetTimeoutError, TargetUnreachableError
from marlowe.core.models import TargetConfig, TargetResponse
from marlowe.targets.base import BaseTargetAdapter

log = structlog.get_logger(__name__)


class OllamaAdapter(BaseTargetAdapter):
    """
    Adapter for Ollama's /api/chat endpoint.
    Compatible with any model pulled via `ollama pull <model>`.
    """

    def __init__(self, config: TargetConfig) -> None:
        super().__init__(config)
        self._client = httpx.AsyncClient(
            base_url=config.url,
            timeout=config.timeout,
            headers=config.headers,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def send(self, prompt: str, history: list[dict] | None = None) -> TargetResponse:
        messages: list[dict] = []

        if self.config.system_prompt:
            messages.append({"role": "system", "content": self.config.system_prompt})

        if history:
            messages.extend(history)

        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        log.debug("sending prompt", model=self.config.model, prompt_len=len(prompt))
        t0 = time.monotonic()

        try:
            resp = await self._client.post("/api/chat", json=payload)
            resp.raise_for_status()
        except httpx.TimeoutException as exc:
            raise TargetTimeoutError(f"Ollama timed out after {self.config.timeout}s") from exc
        except httpx.HTTPError as exc:
            raise TargetUnreachableError(f"Ollama request failed: {exc}") from exc

        latency_ms = (time.monotonic() - t0) * 1000
        data = resp.json()

        content = data.get("message", {}).get("content", "")
        tokens = data.get("eval_count")

        log.debug("response received", latency_ms=round(latency_ms), tokens=tokens)

        return TargetResponse(
            content=content,
            latency_ms=latency_ms,
            tokens_used=tokens,
            raw=data,
        )

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("/api/tags", timeout=5.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        await self._client.aclose()
