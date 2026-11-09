"""Threshold choice under a false-positive cap, estimated by grouped cross-validation.

The bar is set before looking at results: benign texts held for review must
stay at or below ``max_fpr`` (2%, the same bar as D6-44), and among the
thresholds that keep it, the one catching the most attacks is used. Each fold
gets the threshold chosen on the other folds, so no sample is scored with a
threshold tuned on it; folds keep every use of an attack sentence together
(``group``/``fold`` in ko_eval_v2.jsonl). The pooled out-of-fold counts are
the estimate.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def choose_threshold(attack: list[float], benign: list[float], max_fpr: float) -> float:
    """Lowest threshold (most attacks caught) whose benign hold rate is at most max_fpr.

    A sample is flagged when its score is at or above the threshold. With no
    benign sample allowed through, the threshold sits just above the highest
    benign score.
    """
    allowed = math.floor(max_fpr * len(benign) + 1e-9)
    ordered = sorted(benign, reverse=True)
    if allowed >= len(ordered):
        return min(attack + benign, default=0.0)
    # Flag everything strictly above the (allowed+1)-th highest benign score.
    limit = ordered[allowed]
    return math.nextafter(limit, math.inf)


def cross_validate(rows: list[dict[str, Any]], key: str, max_fpr: float = 0.02) -> dict[str, Any]:
    folds = sorted({r["fold"] for r in rows})
    flagged: list[tuple[dict[str, Any], bool]] = []
    thresholds = []
    for fold in folds:
        train = [r for r in rows if r["fold"] != fold]
        threshold = choose_threshold([r[key] for r in train if r["label"] == "attack"],
                                     [r[key] for r in train if r["label"] == "benign"], max_fpr)
        thresholds.append(threshold)
        flagged += [(r, r[key] >= threshold) for r in rows if r["fold"] == fold]
    attacks = [hit for r, hit in flagged if r["label"] == "attack"]
    benign = [hit for r, hit in flagged if r["label"] == "benign"]
    by_kind: dict[str, list[bool]] = defaultdict(list)
    for r, hit in flagged:
        if r["label"] == "attack":
            by_kind[r["kind"]].append(hit)
    return {
        "scorer": key, "max_fpr": max_fpr, "thresholds": thresholds,
        "detection": _rate(sum(attacks), len(attacks)),
        "false_positive": _rate(sum(benign), len(benign)),
        "detection_by_kind": {k: _rate(sum(v), len(v)) for k, v in sorted(by_kind.items())},
        "false_alarms": sorted(r["text"][:80] for r, hit in flagged if r["label"] == "benign" and hit),
        "missed_kinds": sorted(r["kind"] for r, hit in flagged if r["label"] == "attack" and not hit),
    }


def _rate(hits: int, total: int) -> dict[str, Any]:
    low, high = wilson(hits, total)
    return {"hits": hits, "total": total, "rate": round(hits / total, 4) if total else None,
            "ci95": [round(low, 4), round(high, 4)]}


def wilson(hits: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a proportion (95% by default)."""
    if total == 0:
        return 0.0, 1.0
    p = hits / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return max(0.0, centre - spread), min(1.0, centre + spread)
