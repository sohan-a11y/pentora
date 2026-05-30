"""Autorize-style response diff engine for IDOR/BOLA detection.

When two different users' tokens fetch "the same" resource and the bodies come
back essentially identical, it usually means one user's authorization leaked
the other's data. We quantify "essentially identical" with
``difflib.SequenceMatcher`` and treat a ratio above :data:`SIMILAR_THRESHOLD`
as similar.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass

SIMILAR_THRESHOLD = 0.85


@dataclass
class DiffResult:
    similar: bool  # bodies "essentially identical"
    ratio: float  # 0.0-1.0
    diff: str  # unified diff for report


def compare_responses(resp_a: str, resp_b: str) -> DiffResult:
    """Compare two response bodies; similar when ratio exceeds the threshold."""
    ratio = difflib.SequenceMatcher(None, resp_a, resp_b).ratio()
    diff = "\n".join(
        difflib.unified_diff(
            resp_a.splitlines(),
            resp_b.splitlines(),
            fromfile="token_a",
            tofile="token_b",
            lineterm="",
        )
    )
    return DiffResult(similar=ratio > SIMILAR_THRESHOLD, ratio=round(ratio, 4), diff=diff)
