"""Optional B text signals. A checks remain the only source of block decisions."""

from __future__ import annotations

import math
from typing import Protocol

from .models import InspectionFinding, RuleAction, Severity


class TextScorer(Protocol):
    model_id: str
    revision: str

    def score(self, text: str) -> float: ...


def inspect_text(text: str, scorer: TextScorer | None, *, stage: str,
                 threshold: float = 0.5) -> tuple[InspectionFinding | None, float | None]:
    """Return a SIGNAL and score; inference failure raises review, never block."""
    if scorer is None or not text:
        return None, None
    if not 0 <= threshold <= 1:
        raise ValueError("B threshold must be between 0 and 1")
    metadata = {"model_id": scorer.model_id, "revision": scorer.revision}
    try:
        score = float(scorer.score(text))
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("classifier score is outside 0..1")
    except Exception as error:
        return InspectionFinding(
            code="B_CLASSIFIER_UNAVAILABLE", severity=Severity.WARNING,
            action=RuleAction.SIGNAL, marker="B", stage=stage,
            message="B classifier could not score the text.",
            metadata={**metadata, "error_type": type(error).__name__},
        ), None
    if score < threshold:
        return None, score
    return InspectionFinding(
        code="B_PROMPT_INJECTION_SIGNAL", severity=Severity.WARNING,
        action=RuleAction.SIGNAL, marker="B", stage=stage,
        message="Optional classifier found a prompt-injection signal.",
        metadata={**metadata, "score": f"{score:.6f}", "threshold": f"{threshold:.6f}"},
    ), score
