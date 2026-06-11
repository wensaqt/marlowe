"""
CVSS-inspired scorer.

Score = base_score × exploitability × impact_multiplier, clamped to [0, 10].
Severity thresholds mirror CVSS v3.1 ranges.
"""

from __future__ import annotations

from marlowe.core.constants import IMPACT_MULTIPLIERS, SEVERITY_THRESHOLDS, ImpactCategory
from marlowe.core.models import AttackResult, CVSSScore, Severity


def compute_score(
    plugin_base_score: float,
    impact_category: ImpactCategory,
    results: list[AttackResult],
) -> CVSSScore:
    total = len(results)
    successes = sum(1 for r in results if r.vulnerability_detected)
    exploitability = successes / total if total > 0 else 0.0
    impact_multiplier = IMPACT_MULTIPLIERS.get(impact_category, 1.0)

    return CVSSScore.compute(
        base_score=plugin_base_score,
        exploitability=exploitability,
        impact_multiplier=impact_multiplier,
    )


def score_to_severity(score: CVSSScore) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score.final >= threshold:
            return severity
    return Severity.INFO
