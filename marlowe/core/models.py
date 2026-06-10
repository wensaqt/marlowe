"""
Core domain models for Marlowe.
These are the shared contracts between all modules — define them first.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(StrEnum):
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT = "LLM02"
    LLM06_SENSITIVE_INFO = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07"
    OTHER = "OTHER"


class AttackStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"  # attack succeeded (vulnerability confirmed)
    FAILURE = "failure"  # attack failed (model resisted)
    ERROR = "error"  # execution error (timeout, connection, etc.)


class CampaignStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    url: str
    model: str
    system_prompt: str | None = None
    temperature: float = 0.7
    max_tokens: int = 512
    timeout: float = 30.0
    headers: dict[str, str] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    content: str
    latency_ms: float
    tokens_used: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


# ---------------------------------------------------------------------------
# Attack
# ---------------------------------------------------------------------------


class AttackPrompt(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    variant_name: str  # e.g. "dan_13", "base64_encoded"
    content: str  # the actual prompt text
    seed: int | None = None  # for reproducibility
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str
    plugin_id: str
    prompt: AttackPrompt
    response: TargetResponse
    status: AttackStatus
    vulnerability_detected: bool = False
    confidence: float = 0.0  # 0.0 – 1.0
    evidence: str | None = None  # excerpt from response proving the finding
    timestamp: datetime = Field(default_factory=_now)


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------


class CVSSScore(BaseModel):
    """
    Simplified CVSS-inspired score.
    Final = base_score × exploitability × impact_multiplier
    """

    base_score: float  # from plugin definition (difficulty of the attack)
    exploitability: float  # observed success rate across variants (0.0–1.0)
    impact_multiplier: float  # based on impact category (1.0–3.0)
    final: float  # computed, 0.0–10.0

    @classmethod
    def compute(
        cls,
        base_score: float,
        exploitability: float,
        impact_multiplier: float,
    ) -> CVSSScore:
        raw = base_score * exploitability * impact_multiplier
        return cls(
            base_score=base_score,
            exploitability=exploitability,
            impact_multiplier=impact_multiplier,
            final=round(min(raw, 10.0), 2),
        )


class Vulnerability(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str
    plugin_id: str
    category: OWASPCategory
    severity: Severity
    title: str
    description: str
    score: CVSSScore
    evidence: list[str] = Field(default_factory=list)  # response excerpts
    successful_prompts: list[AttackPrompt] = Field(default_factory=list)
    remediation: str | None = None


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------


class CampaignConfig(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    target: TargetConfig
    plugins: list[str] = Field(default_factory=list)  # empty = all registered
    max_workers: int = 5
    variants_per_plugin: int = 10
    baseline_prompts: int = 5


class Campaign(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    config: CampaignConfig
    status: CampaignStatus = CampaignStatus.CREATED
    created_at: datetime = Field(default_factory=_now)
    completed_at: datetime | None = None
    total_attacks: int = 0
    successful_attacks: int = 0
    vulnerabilities_found: int = 0


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class ReportSummary(BaseModel):
    total_attacks: int
    successful_attacks: int
    success_rate: float
    vulnerabilities_by_severity: dict[str, int]
    vulnerabilities_by_category: dict[str, int]
    overall_risk_score: float  # weighted average of vuln CVSS scores


class Report(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign: Campaign
    summary: ReportSummary
    vulnerabilities: list[Vulnerability]
    generated_at: datetime = Field(default_factory=_now)
    marlowe_version: str = "0.1.0"
