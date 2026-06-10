"""JSON reporter — full serialisation of a Report to a dict / file."""

from __future__ import annotations

import json
from pathlib import Path

from marlowe.core.models import Report


def to_dict(report: Report) -> dict:
    return report.model_dump(mode="json")


def write(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(to_dict(report), f, indent=2, ensure_ascii=False)
