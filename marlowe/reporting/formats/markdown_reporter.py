"""
Markdown reporter — AI-generated security analysis of a scan report.

Sends a structured prompt to the target model via the existing adapter
and asks it to produce a professional security advisory in Markdown.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from marlowe.core.models import Report

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """You are a senior application security engineer specializing in LLM security.
You write clear, professional security advisories for development teams.
Your reports are factual, actionable, and well-structured in Markdown."""

_ANALYSIS_TEMPLATE = """\
You analyzed an LLM system for prompt injection vulnerabilities using an automated \
red-team tool called Marlowe. Here are the results:

**Target model:** {model}
**Campaign:** {campaign}
**Date:** {date}

## Scan statistics
- Total attack variants tested: {total_attacks}
- Successful attacks (model bypassed): {successful_attacks}
- Overall success rate: {success_rate:.1%}
- Overall risk score: {risk_score:.1f} / 10

## Vulnerabilities found
{vulnerabilities_section}

---

Write a professional security advisory in Markdown covering:
1. **Executive Summary** — one paragraph, non-technical, suitable for management
2. **Technical Findings** — detail each vulnerability: what happened, why it is dangerous, CVSS score
3. **Attack Evidence** — show concrete examples of successful injections
4. **Remediation** — specific, prioritised recommendations for each finding
5. **Conclusion** — overall security posture assessment

Be direct and precise. Do not invent findings beyond what is listed above.\
"""


async def generate(report: Report, adapter: object) -> str:
    """
    Call the target model via the provided adapter and return a Markdown security advisory.

    Falls back to a static summary if the AI call fails.

    Args:
        report:  The completed scan report to analyse.
        adapter: A BaseTargetAdapter instance (typed as object to avoid circular import).
    """
    prompt = _build_prompt(report)
    log.info("generating AI analysis", prompt_len=len(prompt))

    try:
        # Import here to avoid a circular dependency at module level
        from marlowe.targets.base import BaseTargetAdapter
        assert isinstance(adapter, BaseTargetAdapter)

        response = await adapter.send(
            prompt=prompt,
            history=[{"role": "system", "content": _SYSTEM_PROMPT}],
        )
        if response.is_error or not response.content:
            log.warning("AI analysis returned empty response, falling back")
            return _fallback_markdown(report)

        log.info("AI analysis generated", chars=len(response.content))
        return response.content

    except Exception as exc:
        log.warning("AI analysis failed, falling back to static report", error=str(exc))
        return _fallback_markdown(report)


def write(markdown: str, path: Path) -> None:
    """Write the markdown string to a file, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_prompt(report: Report) -> str:
    return _ANALYSIS_TEMPLATE.format(
        model=report.campaign.config.target.model,
        campaign=report.campaign.name,
        date=report.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        total_attacks=report.summary.total_attacks,
        successful_attacks=report.summary.successful_attacks,
        success_rate=report.summary.success_rate,
        risk_score=report.summary.overall_risk_score,
        vulnerabilities_section=_build_vulnerabilities_section(report),
    )


def _build_vulnerabilities_section(report: Report) -> str:
    if not report.vulnerabilities:
        return "No vulnerabilities detected."

    lines: list[str] = []
    for v in sorted(report.vulnerabilities, key=lambda x: x.score.final, reverse=True):
        evidence_sample = f"`{v.evidence[0][:80]}`" if v.evidence else "N/A"
        lines.append(
            f"### {v.plugin_id} — {v.severity.upper()} (score {v.score.final}/10)\n"
            f"- **Category:** {v.category}\n"
            f"- **Description:** {v.description}\n"
            f"- **Evidence:** {evidence_sample}\n"
            f"- **Suggested fix:** {v.remediation or 'See OWASP LLM Top 10'}\n"
        )
    return "\n".join(lines)


def _fallback_markdown(report: Report) -> str:
    """Plain Markdown summary used when AI generation is unavailable."""
    lines = [
        f"# Marlowe Security Report — {report.campaign.name}",
        f"\n**Model:** {report.campaign.config.target.model}  ",
        f"**Date:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Risk score:** {report.summary.overall_risk_score:.1f}/10\n",
        "## Summary\n",
        f"- Attacks tested: {report.summary.total_attacks}",
        f"- Successful: {report.summary.successful_attacks} ({report.summary.success_rate:.1%})",
        f"- Vulnerabilities: {len(report.vulnerabilities)}\n",
        "## Findings\n",
    ]
    for v in report.vulnerabilities:
        lines.append(f"### {v.plugin_id} — {v.severity.upper()}")
        lines.append(f"{v.description}\n")
        lines.append(f"**Remediation:** {v.remediation or 'See OWASP LLM Top 10'}\n")
    return "\n".join(lines)
