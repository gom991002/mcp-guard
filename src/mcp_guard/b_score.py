"""Stage 1 B score: one score per package from its B signals (D6-35).

A logistic model trained on labelled npm and PyPI malware and benign packages
(mvp/10-local-entry/b_score) weighs the signals: lookalike name, install scripts, a shipped
.pth file, and the Semgrep code-behaviour rules. The score can only raise a
verdict to review; it never blocks and never relaxes an A decision.

Each result keeps every active signal's contribution in log-odds against the
training average (for a linear model these are the exact SHAP values), so an
audit record shows why a package was held.

The model file says who decides. "rule": any of its review signals raises
review, and the probability only ranks what is held (signals the data showed
no better than chance are recorded but do not raise review). "model": the
probability at or above the threshold raises review. The training script picks
"model" only when it keeps the rule's recall with clearly fewer false alarms.

Without a model file, or when a signal the model was not trained on is
present, any signal raises review.
"""

from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

MODEL_PATH = Path(__file__).resolve().parent / "data" / "b_score_stage1.json"
RULE = "rule-any-signal"


@lru_cache(maxsize=4)
def load_model(path: str = str(MODEL_PATH)) -> dict[str, Any] | None:
    try:
        model = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(model, dict) or not (isinstance(model.get("weights"), dict)
                                           or isinstance(model.get("trees"), list)):
        return None
    return model


def score(features: dict[str, int], model: dict[str, Any] | None = None,
          missing: set[str] | frozenset[str] = frozenset(), ecosystem: str = "") -> dict[str, Any]:
    """{"model", "version", "probability", "threshold", "raise_review", "signals", "contributions"}.

    ``missing``: features that could not be computed (e.g. GuardDog off). The
    model's ``without_guarddog`` variant, trained without them, decides if it
    covers them (D6-37); otherwise a model decision that would rely on them
    falls back to the review signals. ``ecosystem`` ("npm", "pypi") is an input
    of models that weigh signals per ecosystem (D6-40); it is not a signal.
    """
    model = model if model is not None else load_model()
    variant = (model or {}).get("without_guarddog")
    if missing and variant and missing & _used(model) and not missing & _used(variant):
        kept = {k: model[k] for k in ("version", "means", "record_only_signals") if k in model}
        model = {**kept, **variant, "model": model.get("model", "") + "-without-guarddog"}
    signals = sorted(f for f, value in features.items() if value)
    if model is None:
        return {"model": RULE, "version": "", "probability": None, "threshold": None,
                "raise_review": bool(signals), "signals": signals, "contributions": {}}
    trained = set(model.get("features") or model["weights"]) if "columns" in model else set(model["weights"])
    # features left out of the model because they were not computed are not "untrained"
    untrained = [f for f in signals if f not in trained and f not in missing]
    probability = _probability(model, features, ecosystem)
    thresholds = model.get("threshold_by_ecosystem", {})
    threshold = float(thresholds.get(ecosystem, model["threshold"]))
    if model.get("decision") == "model" and not missing & _used(model):
        raised = probability >= threshold
    else:
        review_signals = set(model.get("review_signals", trained))
        raised = any(f in review_signals for f in signals)
    return {"model": model.get("model", ""), "version": model.get("version", ""),
            "decision": model.get("decision", "rule"),
            "probability": round(probability, 4), "threshold": round(threshold, 4),
            # A signal the model never saw cannot be weighed: it raises review.
            "raise_review": raised or bool(untrained),
            "signals": signals, "contributions": _contributions(model, features, ecosystem),
            **({"untrained_signals": untrained} if untrained else {}),
            **({"not_computed": sorted(missing)} if missing else {})}


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def _logit(p: float) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)
    return math.log(p / (1 - p))


def _used(model: dict[str, Any] | None) -> set[str]:
    """Features the model's score depends on."""
    if not model:
        return set()
    if "columns" not in model:
        return {f for f, w in model["weights"].items() if float(w) > 0}
    columns = model["columns"]
    if "trees" in model:
        names = {columns[node[0]] for tree in model["trees"] for node in tree if node[0] != -1}
    else:
        names = {c for c, w in model["weights"].items() if float(w) > 0}
    return {c.split("@")[0] for c in names if not c.startswith("@")}


def _row(model: dict[str, Any], features: dict[str, int], ecosystem: str) -> list[int]:
    row = []
    for column in model["columns"]:
        name, _, eco = column.partition("@")
        if not name:
            row.append(int(ecosystem == eco))
        elif eco:
            row.append(int(bool(features.get(name, 0)) and ecosystem == eco))
        else:
            row.append(int(bool(features.get(name, 0))))
    return row


def _probability(model: dict[str, Any], features: dict[str, int], ecosystem: str) -> float:
    if "columns" not in model:  # D6-35 logistic model
        weights = model["weights"]
        return _sigmoid(float(model["intercept"]) + sum(float(weights[f]) * features.get(f, 0) for f in weights))
    row = _row(model, features, ecosystem)
    if "trees" not in model:
        return _sigmoid(float(model["intercept"])
                        + sum(float(model["weights"][c]) * v for c, v in zip(model["columns"], row)))
    leaves = []
    for nodes in model["trees"]:
        i = 0
        while nodes[i][0] != -1:
            i = nodes[i][2] if row[nodes[i][0]] <= nodes[i][1] else nodes[i][3]
        leaves.append(nodes[i][4])
    if model["kind"] == "gradient_boosting":
        return _sigmoid(float(model["baseline"]) + sum(leaves))
    return sum(leaves) / len(leaves)


MAX_EXACT_SIGNALS = 10


def _contributions(model: dict[str, Any], features: dict[str, int], ecosystem: str) -> dict[str, float]:
    """Each active signal's share of the score, in log-odds.

    D6-35 logistic model: weight x (value - training mean), its exact SHAP
    value. Other models (D6-40): exact Shapley values against the same package
    with no signal, so they add up to the score minus that baseline; with more
    than MAX_EXACT_SIGNALS active signals, each signal's drop when removed.
    """
    if "columns" not in model:
        weights, means = model["weights"], model.get("means", {})
        return {f: round(float(weights[f]) * (features.get(f, 0) - float(means.get(f, 0))), 4)
                for f in weights if features.get(f, 0)}
    active = sorted(f for f in _used(model) if features.get(f, 0))
    value = lambda on: _logit(_probability(model, {f: 1 for f in on}, ecosystem))  # noqa: E731
    if len(active) > MAX_EXACT_SIGNALS:
        full = value(active)
        return {f: round(full - value([g for g in active if g != f]), 4) for f in active}
    n = len(active)
    cache = {mask: value([f for j, f in enumerate(active) if mask >> j & 1]) for mask in range(1 << n)}
    weight = [math.factorial(k) * math.factorial(n - k - 1) / math.factorial(n) for k in range(n)]
    return {f: round(sum(weight[bin(mask).count("1")] * (cache[mask | 1 << j] - cache[mask])
                         for mask in range(1 << n) if not mask >> j & 1), 4)
            for j, f in enumerate(active)}
