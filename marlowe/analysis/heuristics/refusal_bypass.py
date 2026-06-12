"""
Refusal detection utility.

contains_refusal() is used by attack plugins to check whether a model response
represents a refusal — helping them distinguish between a successful bypass and
a model that simply declined the injected instruction.
"""

from __future__ import annotations

import re

from marlowe.core.constants import REFUSAL_PATTERNS

_REFUSAL_RE = re.compile("|".join(REFUSAL_PATTERNS), re.IGNORECASE)


def contains_refusal(text: str) -> bool:
    return bool(_REFUSAL_RE.search(text))
