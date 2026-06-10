"""Abstract base class for all attack plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import NamedTuple

from marlowe.core.constants import ImpactCategory
from marlowe.core.models import (
    AttackPrompt,
    AttackResult,
    AttackStatus,
    OWASPCategory,
    TargetResponse,
)


@dataclass
class AttackContext:
    """Runtime context passed to each plugin during a campaign."""

    campaign_id: str
    target_model: str
    system_prompt: str | None
    variants_count: int          # how many variants to generate
    baseline_responses: list[str] = field(default_factory=list)


class AnalysisResult(NamedTuple):
    """
    Structured return value from BaseAttackPlugin.analyze_response.

    Attributes:
        success:    True if the attack appears to have bypassed the model's guardrails.
        confidence: Certainty score in [0.0, 1.0].
        evidence:   Relevant excerpt from the response, or None if unavailable.
    """

    success: bool
    confidence: float
    evidence: str | None


class BaseAttackPlugin(ABC):
    """
    Base class for all Marlowe attack plugins.

    Subclasses must:
    - Declare a unique non-empty `plugin_id`
    - Implement `generate_variants` to produce attack prompts
    - Implement `analyze_response` to detect successful attacks

    Registration:
        Add to pyproject.toml under [project.entry-points."marlowe.attacks"].
        The registry discovers plugins automatically — no core code changes needed.
    """

    plugin_id: str = ""
    display_name: str = ""
    description: str = ""
    category: OWASPCategory = OWASPCategory.LLM01_PROMPT_INJECTION
    base_score: float = 5.0          # CVSS base difficulty (0.0–10.0)
    impact_category: ImpactCategory = ImpactCategory.INSTRUCTION_BYPASS
    # Immutable tuple avoids the mutable class-attribute shared-state bug
    tags: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.plugin_id:
            raise TypeError(f"{cls.__name__} must define a non-empty plugin_id")
        if not cls.display_name:
            raise TypeError(f"{cls.__name__} must define a non-empty display_name")

    @abstractmethod
    async def generate_variants(self, ctx: AttackContext) -> list[AttackPrompt]:
        """
        Generate a list of prompt variants for this attack strategy.

        The implementation should aim to return roughly ctx.variants_count variants,
        capped by the number of available templates if fewer exist.
        """

    @abstractmethod
    def analyze_response(
        self,
        response: TargetResponse,
        prompt: AttackPrompt,
        ctx: AttackContext,
    ) -> AnalysisResult:
        """
        Analyse a target response and decide whether the attack succeeded.

        Returns an AnalysisResult with success flag, confidence score, and
        optional evidence excerpt from the response.
        """

    def build_result(
        self,
        campaign_id: str,
        prompt: AttackPrompt,
        response: TargetResponse,
        analysis: AnalysisResult,
    ) -> AttackResult:
        """Assemble an AttackResult from execution data and analysis output."""
        return AttackResult(
            campaign_id=campaign_id,
            plugin_id=self.plugin_id,
            prompt=prompt,
            response=response,
            status=AttackStatus.SUCCESS if analysis.success else AttackStatus.FAILURE,
            vulnerability_detected=analysis.success,
            confidence=analysis.confidence,
            evidence=analysis.evidence,
        )
