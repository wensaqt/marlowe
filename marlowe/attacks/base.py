"""Abstract base class for all attack plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

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


class BaseAttackPlugin(ABC):
    """
    Every attack plugin must inherit this class and implement two methods:
    - generate_variants: produce N prompt variants for this attack strategy
    - analyze_response: decide if a given response signals a successful attack

    Registration in pyproject.toml under [project.entry-points."marlowe.attacks"]
    is the only wiring needed — the registry discovers plugins automatically.
    """

    # --- Plugin metadata (override in subclasses) ---
    plugin_id: str = ""
    display_name: str = ""
    description: str = ""
    category: OWASPCategory = OWASPCategory.LLM01_PROMPT_INJECTION
    base_score: float = 5.0          # CVSS base difficulty (0.0–10.0)
    impact_category: str = "instruction_bypass"
    tags: list[str] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Enforce that subclasses declare plugin_id
        if cls.plugin_id == "":
            raise TypeError(f"{cls.__name__} must define a non-empty plugin_id")

    @abstractmethod
    async def generate_variants(self, ctx: AttackContext) -> list[AttackPrompt]:
        """
        Generate a list of prompt variants for this attack.
        The number of variants should be roughly ctx.variants_count.
        """

    @abstractmethod
    def analyze_response(
        self,
        response: TargetResponse,
        prompt: AttackPrompt,
        ctx: AttackContext,
    ) -> tuple[bool, float, str | None]:
        """
        Analyze a target response and return:
        - success: True if the attack appears successful
        - confidence: 0.0–1.0
        - evidence: relevant excerpt from the response (or None)
        """

    def build_result(
        self,
        campaign_id: str,
        prompt: AttackPrompt,
        response: TargetResponse,
        success: bool,
        confidence: float,
        evidence: str | None,
    ) -> AttackResult:
        return AttackResult(
            campaign_id=campaign_id,
            plugin_id=self.plugin_id,
            prompt=prompt,
            response=response,
            status=AttackStatus.SUCCESS if success else AttackStatus.FAILURE,
            vulnerability_detected=success,
            confidence=confidence,
            evidence=evidence,
        )
