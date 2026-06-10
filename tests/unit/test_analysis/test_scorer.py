"""Unit tests for the CVSS scorer."""

import pytest

from marlowe.analysis.scorer import compute_score, score_to_severity
from marlowe.core.models import AttackResult, AttackStatus, AttackPrompt, TargetResponse, Severity


def _make_result(success: bool) -> AttackResult:
    return AttackResult(
        campaign_id="c1",
        plugin_id="direct_override",
        prompt=AttackPrompt(plugin_id="direct_override", variant_name="v", content="test"),
        response=TargetResponse(content="ok", latency_ms=100),
        status=AttackStatus.SUCCESS if success else AttackStatus.FAILURE,
        vulnerability_detected=success,
        confidence=0.9 if success else 0.0,
    )


def test_zero_exploitability_gives_zero_score():
    results = [_make_result(False)] * 10
    score = compute_score(6.0, "instruction_bypass", results)
    assert score.final == 0.0


def test_full_exploitability():
    results = [_make_result(True)] * 10
    score = compute_score(6.0, "instruction_bypass", results)
    # 6.0 * 1.0 * 2.5 = 15.0 → clamped to 10.0
    assert score.final == 10.0


def test_partial_exploitability():
    results = [_make_result(True)] * 4 + [_make_result(False)] * 6
    score = compute_score(6.0, "instruction_bypass", results)
    # 6.0 * 0.4 * 2.5 = 6.0
    assert score.final == pytest.approx(6.0, abs=0.01)


def test_severity_thresholds():
    from marlowe.core.models import CVSSScore

    assert score_to_severity(CVSSScore.compute(10, 1.0, 1.0)) == Severity.CRITICAL
    assert score_to_severity(CVSSScore.compute(3.5, 1.0, 2.0)) == Severity.HIGH
    assert score_to_severity(CVSSScore.compute(2.0, 1.0, 1.0)) == Severity.LOW
    assert score_to_severity(CVSSScore.compute(0.0, 0.0, 1.0)) == Severity.INFO
