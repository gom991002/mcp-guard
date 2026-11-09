"""Train and evaluate the stage 1 B score (D6-35); standard library only.

Method (borrowed from a sports-injury prediction study the user supplied):
stratified 80:20 split, stratified 10-fold cross-validation on the training
part, class weights for the rare class, PR-AUC as the primary metric with
AUC-ROC beside it, the Brier score for calibration, thresholds from F1 and
Youden's J checked against each other, permutation feature importance, and
additive per-signal contributions (exact SHAP values for a linear model).

The model is a logistic regression: the inspection core is standard-library
only, and its contributions add up exactly. Weights are kept non-negative: a B
signal may only raise risk, never lower it.

Two decisions are made on the training part only (the test part is read once,
for the report):

* record-only signals: a signal seen often enough that is more common in
  benign packages and is the only signal of no malicious package is recorded
  but does not raise review;
* the decision itself: the model's threshold replaces the rule "any review
  signal raises review" only if, on the cross-validated predictions, it keeps
  the rule's recall with at least 10% fewer false alarms. Otherwise the rule
  decides and the score ranks what is held. Missing malware costs more than a
  review, since the B score may only raise a verdict to review.

Run: python mvp/10-local-entry/b_score/train.py --data mvp/10-local-entry/b_score/data/features.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry.code_scan import FEATURES, GD_FEATURES  # noqa: E402

# Signals the stage 1 rule used before D6-35 (new rules excluded), for comparison.
# The review signals chosen before D6-37: the recall the new decision must keep.
PREVIOUS_REVIEW_SIGNALS = ("lookalike_name", "install_script", "ships_pth", "B_CODE_DECODE_AND_EXECUTE",
                           "B_CODE_DYNAMIC_EVAL", "B_CODE_DYNAMIC_NETWORK_REQUEST",
                           "B_CODE_PROCESS_EXECUTION", "B_CODE_SECRET_FILE_READ")
OLD_SIGNALS = ("lookalike_name", "install_script", "B_CODE_PROCESS_EXECUTION",
               "B_CODE_DYNAMIC_NETWORK_REQUEST", "B_CODE_SECRET_FILE_READ")
LAMBDAS = (0.001, 0.01, 0.1, 1.0, 10.0)
MIN_SUPPORT = 10  # packages with a signal before the data may demote it


# model -----------------------------------------------------------------------


def sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def solve(a: list[list[float]], b: list[float]) -> list[float]:
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(m[r][col]))
        m[col], m[pivot] = m[pivot], m[col]
        for r in range(n):
            if r != col and m[col][col]:
                f = m[r][col] / m[col][col]
                m[r] = [x - f * y for x, y in zip(m[r], m[col])]
    return [m[i][n] / m[i][i] if m[i][i] else 0.0 for i in range(n)]


def fit(x: list[list[int]], y: list[int], lam: float) -> tuple[list[float], float, float]:
    """Non-negative fit: refit without any feature whose weight comes out negative."""
    active = list(range(len(x[0])))
    while True:
        w, b, shift = _fit([[row[j] for j in active] for row in x], y, lam)
        negative = [j for j, wj in zip(active, w) if wj < 0]
        if not negative:
            full = [0.0] * len(x[0])
            for j, wj in zip(active, w):
                full[j] = wj
            return full, b, shift
        active = [j for j in active if j not in negative]
        if not active:
            return [0.0] * len(x[0]), b, shift


def _fit(x: list[list[int]], y: list[int], lam: float) -> tuple[list[float], float, float]:
    """Class-weighted L2 logistic regression by Newton steps; returns (w, b, log weight ratio)."""
    pos = sum(y)
    w_pos, w_neg = (len(y) - pos) / pos, 1.0  # paper strategy A: weight = class ratio
    k = len(x[0]) if x and x[0] else 0
    beta = [0.0] * (k + 1)  # intercept last
    for _ in range(50):
        grad = [0.0] * (k + 1)
        hess = [[0.0] * (k + 1) for _ in range(k + 1)]
        for row, label in zip(x, y):
            features = row + [1]
            p = sigmoid(sum(b * f for b, f in zip(beta, features)))
            weight = w_pos if label else w_neg
            for i, fi in enumerate(features):
                grad[i] += weight * (p - label) * fi
                for j, fj in enumerate(features):
                    hess[i][j] += weight * p * (1 - p) * fi * fj
        for i in range(k):  # no penalty on the intercept
            grad[i] += lam * beta[i]
            hess[i][i] += lam
        step = solve(hess, grad)
        beta = [b - s for b, s in zip(beta, step)]
        if max(abs(s) for s in step) < 1e-8:
            break
    return beta[:k], beta[k], math.log(w_pos / w_neg)


def predict(model: tuple[list[float], float, float], x: list[list[int]]) -> list[float]:
    w, b, shift = model
    # Undo the class-weight shift of the intercept: calibrated to the data's prevalence.
    return [sigmoid(b - shift + sum(wi * xi for wi, xi in zip(w, row))) for row in x]


# metrics ---------------------------------------------------------------------


def average_precision(y: list[int], s: list[float]) -> float:
    order = sorted(range(len(y)), key=lambda i: -s[i])
    hits, total, ap, i = 0, sum(y), 0.0, 0
    while i < len(order):  # ties share one step
        j = i
        while j < len(order) and s[order[j]] == s[order[i]]:
            j += 1
        group = order[i:j]
        new_hits = sum(y[g] for g in group)
        hits += new_hits
        ap += new_hits / total * (hits / j)
        i = j
    return ap


def roc_auc(y: list[int], s: list[float]) -> float:
    pos = [v for v, label in zip(s, y) if label]
    neg = [v for v, label in zip(s, y) if not label]
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def brier(y: list[int], p: list[float]) -> float:
    return sum((pi - yi) ** 2 for pi, yi in zip(p, y)) / len(y)


def confusion(y: list[int], flagged: list[bool]) -> dict[str, float]:
    tp = sum(1 for f, label in zip(flagged, y) if f and label)
    fp = sum(1 for f, label in zip(flagged, y) if f and not label)
    fn = sum(1 for f, label in zip(flagged, y) if not f and label)
    tn = len(y) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(precision, 4),
            "recall": round(recall, 4), "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0}


def bootstrap_ci(y: list[int], s: list[float], metric, rng: random.Random, reps: int = 1000):
    pos = [i for i, label in enumerate(y) if label]
    neg = [i for i, label in enumerate(y) if not label]
    values = []
    for _ in range(reps):  # stratified by the label, like the paper
        sample = [rng.choice(pos) for _ in pos] + [rng.choice(neg) for _ in neg]
        values.append(metric([y[i] for i in sample], [s[i] for i in sample]))
    values.sort()
    return round(values[int(reps * 0.025)], 4), round(values[int(reps * 0.975)], 4)


# data ------------------------------------------------------------------------


def stratified_split(rows: list[dict], test_share: float, rng: random.Random):
    train, test = [], []
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault((row["label"], row["ecosystem"]), []).append(row)
    for key in sorted(groups):
        members = groups[key][:]
        rng.shuffle(members)
        cut = round(len(members) * test_share)
        test += members[:cut]
        train += members[cut:]
    return train, test


def folds(rows: list[dict], k: int, rng: random.Random) -> list[list[int]]:
    assignment = [[] for _ in range(k)]
    groups: dict[tuple, list[int]] = {}
    for i, row in enumerate(rows):
        groups.setdefault((row["label"], row["ecosystem"]), []).append(i)
    for key in sorted(groups):
        members = groups[key][:]
        rng.shuffle(members)
        for n, i in enumerate(members):
            assignment[n % k].append(i)
    return assignment


def matrix(rows: list[dict]) -> tuple[list[list[int]], list[int]]:
    return [[int(r[f]) for f in FEATURES] for r in rows], [int(r["label"]) for r in rows]


def any_signal(rows: list[dict], signals=FEATURES) -> list[bool]:
    return [any(r[f] == "1" for f in signals) for r in rows]


# thresholds --------------------------------------------------------------------


def thresholds(y: list[int], p: list[float], recall_floor: float) -> dict[str, float]:
    candidates = sorted(set(p))
    best = {"f1": (0.0, 0.5), "youden": (-1.0, 0.5)}
    keep_recall = None
    for t in candidates:
        c = confusion(y, [v >= t for v in p])
        if c["f1"] > best["f1"][0]:
            best["f1"] = (c["f1"], t)
        youden = c["recall"] - c["false_positive_rate"]
        if youden > best["youden"][0]:
            best["youden"] = (youden, t)
        if c["recall"] >= recall_floor:
            keep_recall = t  # the highest threshold that still meets the floor
    return {"f1_max": best["f1"][1], "youden_j": best["youden"][1],
            "keep_rule_recall": keep_recall if keep_recall is not None else min(candidates)}


def without(x: list[list[int]], columns: set[int]) -> list[list[int]]:
    return [[0 if j in columns else v for j, v in enumerate(row)] for row in x]


def decide(y: list[int], oof: list[float], flags_rule: list[bool], previous_recall: float):
    """D6-37 decision: keep the previous review signals' recall, then fewest false alarms."""
    rule_cv = confusion(y, flags_rule)
    cuts = thresholds(y, oof, previous_recall)
    cuts["keep_new_rule_recall"] = thresholds(y, oof, rule_cv["recall"])["keep_rule_recall"]
    candidates = {"rule": rule_cv,
                  "model_keep_previous_recall": confusion(y, [v >= cuts["keep_rule_recall"] for v in oof]),
                  "model_keep_new_rule_recall": confusion(y, [v >= cuts["keep_new_rule_recall"] for v in oof])}
    eligible = {k: c for k, c in candidates.items() if c["recall"] >= previous_recall}
    name = min(eligible, key=lambda k: (eligible[k]["fp"], -eligible[k]["recall"], k != "rule"))
    threshold = {"model_keep_previous_recall": cuts["keep_rule_recall"],
                 "model_keep_new_rule_recall": cuts["keep_new_rule_recall"]}.get(name, cuts["keep_rule_recall"])
    return name, threshold, cuts, candidates


# main --------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--model-out", type=Path, default=ROOT / "src" / "mcp_guard" / "data" / "b_score_stage1.json")
    parser.add_argument("--report-out", type=Path, default=ROOT / "scripts" / "b_score" / "data" / "report.json")
    parser.add_argument("--seed", type=int, default=20261102)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    with args.data.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    # Excluded: packages with no installable files (setup.py-only PyPI malware,
    # held by the wheel-only install and S1_DEPENDENCY_UNVERIFIED instead) and
    # any package an antivirus kept Semgrep from reading. missing_files is not a
    # filter: datasets built before the fix counted setup.py, written elsewhere.
    usable = [r for r in rows if int(r["files"]) > 0 and int(r.get("av_blocked") or 0) == 0
              and r.get("gd_missing", "0") != "1"]  # D6-37: GuardDog could not scan it
    report: dict = {"rows": len(rows), "excluded_no_installable_files": sum(r["files"] == "0" for r in rows),
                    "excluded_av_blocked": sum(int(r.get("av_blocked") or 0) > 0 for r in rows)}
    train, test = stratified_split(usable, 0.2, rng)
    x_train, y_train = matrix(train)
    x_test, y_test = matrix(test)
    report["train"] = {"n": len(train), "malicious": sum(y_train)}
    report["test"] = {"n": len(test), "malicious": sum(y_test)}

    # 10-fold CV: choose the L2 strength by PR-AUC of out-of-fold predictions
    fold_ids = folds(train, 10, rng)
    cv = {}
    for lam in LAMBDAS:
        oof = [0.0] * len(train)
        for k in range(10):
            held = set(fold_ids[k])
            fit_rows = [i for i in range(len(train)) if i not in held]
            model = fit([x_train[i] for i in fit_rows], [y_train[i] for i in fit_rows], lam)
            for i, value in zip(fold_ids[k], predict(model, [x_train[i] for i in fold_ids[k]])):
                oof[i] = value
        cv[lam] = {"pr_auc": average_precision(y_train, oof), "roc_auc": roc_auc(y_train, oof), "oof": oof}
    lam = max(LAMBDAS, key=lambda value: (cv[value]["pr_auc"], -value))
    oof = cv[lam]["oof"]
    report["cv"] = {str(k): {"pr_auc": round(v["pr_auc"], 4), "roc_auc": round(v["roc_auc"], 4)}
                    for k, v in cv.items()}
    report["lambda"] = lam

    # record-only signals, from the training part
    record_only = []
    for f in FEATURES:
        mal = [r for r in train if r["label"] == "1"]
        ben = [r for r in train if r["label"] == "0"]
        hits_mal, hits_ben = sum(r[f] == "1" for r in mal), sum(r[f] == "1" for r in ben)
        sole = sum(1 for r in mal if r[f] == "1" and not any(r[g] == "1" for g in FEATURES if g != f))
        if hits_mal + hits_ben >= MIN_SUPPORT and hits_mal / len(mal) <= hits_ben / len(ben) and sole == 0:
            record_only.append(f)
    review_signals = [f for f in FEATURES if f not in record_only]
    report["record_only_signals"] = record_only

    # D6-37 decision, fixed before the data was seen: keep at least the recall of
    # the previous review signals (cross-validated), then fewest false alarms.
    previous_cv = confusion(y_train, any_signal(train, [f for f in PREVIOUS_REVIEW_SIGNALS if f in FEATURES]))
    rule_cv = confusion(y_train, any_signal(train, review_signals))
    cuts = thresholds(y_train, oof, previous_cv["recall"])
    cuts_rule = thresholds(y_train, oof, rule_cv["recall"])
    cuts["keep_new_rule_recall"] = cuts_rule["keep_rule_recall"]
    candidates = {"rule": rule_cv,
                  "model_keep_previous_recall": confusion(y_train, [v >= cuts["keep_rule_recall"] for v in oof]),
                  "model_keep_new_rule_recall": confusion(y_train, [v >= cuts["keep_new_rule_recall"] for v in oof])}
    eligible = {k: c for k, c in candidates.items() if c["recall"] >= previous_cv["recall"]}
    chosen_name = min(eligible, key=lambda k: (eligible[k]["fp"], -eligible[k]["recall"], k != "rule"))
    decision = "rule" if chosen_name == "rule" else "model"
    chosen = {"model_keep_previous_recall": cuts["keep_rule_recall"],
              "model_keep_new_rule_recall": cuts["keep_new_rule_recall"]}.get(chosen_name, cuts["keep_rule_recall"])
    report["thresholds_from_cv"] = {k: round(v, 4) for k, v in cuts.items()}
    report["previous_rule_cv"] = previous_cv
    report["candidates_cv"] = candidates
    report["rule_cv"] = rule_cv
    report["model_cv_at_rule_recall"] = candidates["model_keep_previous_recall"]
    report["decision"] = decision
    report["chosen"] = chosen_name

    # Without GuardDog (code_scan.guarddog off, the default): the same procedure
    # with the GuardDog columns zeroed, so the fallback is chosen by the data too.
    gd_cols = {j for j, f in enumerate(FEATURES) if f in GD_FEATURES}
    nogd_signals = [f for f in review_signals if f not in GD_FEATURES]
    oof_nogd = [0.0] * len(train)
    for k in range(10):
        held = set(fold_ids[k])
        fit_rows = [i for i in range(len(train)) if i not in held]
        part = fit(without([x_train[i] for i in fit_rows], gd_cols), [y_train[i] for i in fit_rows], lam)
        for i, value in zip(fold_ids[k], predict(part, without([x_train[i] for i in fold_ids[k]], gd_cols))):
            oof_nogd[i] = value
    nogd_name, nogd_threshold, _, nogd_candidates = decide(
        y_train, oof_nogd, any_signal(train, nogd_signals), previous_cv["recall"])
    nogd_decision = "rule" if nogd_name == "rule" else "model"
    nogd_model = fit(without(x_train, gd_cols), y_train, lam)
    p_test_nogd = predict(nogd_model, without(x_test, gd_cols))
    nogd_flags = ([v >= nogd_threshold for v in p_test_nogd] if nogd_decision == "model"
                  else any_signal(test, nogd_signals))
    report["without_guarddog"] = {
        "chosen": nogd_name, "candidates_cv": nogd_candidates,
        "pr_auc": round(average_precision(y_test, p_test_nogd), 4),
        "pr_auc_ci95": bootstrap_ci(y_test, p_test_nogd, average_precision, rng),
        "roc_auc": round(roc_auc(y_test, p_test_nogd), 4),
        "test_decision": confusion(y_test, nogd_flags),
        "test_flag_rate_by_group": {
            "/".join(key): round(sum(nogd_flags[i] for i, r in enumerate(test)
                                     if (r["label"], r["ecosystem"], r["category"]) == key)
                                 / sum(1 for r in test if (r["label"], r["ecosystem"], r["category"]) == key), 4)
            for key in sorted({(r["label"], r["ecosystem"], r["category"]) for r in test})}}

    model = fit(x_train, y_train, lam)
    p_test = predict(model, x_test)
    count_score = [sum(row) for row in x_test]  # the rule, as a score: number of signals
    report["test_metrics"] = {
        "model": {"pr_auc": round(average_precision(y_test, p_test), 4),
                  "pr_auc_ci95": bootstrap_ci(y_test, p_test, average_precision, rng),
                  "roc_auc": round(roc_auc(y_test, p_test), 4),
                  "roc_auc_ci95": bootstrap_ci(y_test, p_test, roc_auc, rng),
                  "brier": round(brier(y_test, p_test), 4),
                  "mean_probability": round(sum(p_test) / len(p_test), 4),
                  "malicious_share": round(sum(y_test) / len(y_test), 4)},
        "signal_count": {"pr_auc": round(average_precision(y_test, count_score), 4),
                         "pr_auc_ci95": bootstrap_ci(y_test, count_score, average_precision, rng),
                         "roc_auc": round(roc_auc(y_test, count_score), 4)},
    }
    report["test_decisions"] = {
        "rule_review_signals": confusion(y_test, any_signal(test, review_signals)),
        "previous_rule": confusion(y_test, any_signal(test, [f for f in PREVIOUS_REVIEW_SIGNALS if f in FEATURES])),
        "chosen": confusion(y_test, ([v >= chosen for v in p_test] if decision == "model"
                                     else any_signal(test, review_signals))),
        "rule_any_signal_new_rules": confusion(y_test, any_signal(test)),
        "rule_any_signal_old_rules": confusion(y_test, any_signal(test, OLD_SIGNALS)),
        **{f"model_{name}": confusion(y_test, [v >= t for v in p_test]) for name, t in cuts.items()},
    }
    flagged = ([v >= chosen for v in p_test] if decision == "model"
               else any_signal(test, review_signals))
    previous = any_signal(test, [f for f in PREVIOUS_REVIEW_SIGNALS if f in FEATURES])
    report["test_recall_by_group"] = {}
    for key in sorted({(r["ecosystem"], r["category"]) for r in test if r["label"] == "1"}):
        idx = [i for i, r in enumerate(test) if (r["ecosystem"], r["category"]) == key]
        report["test_recall_by_group"]["/".join(key)] = {
            "n": len(idx), "model": round(sum(flagged[i] for i in idx) / len(idx), 4),
            "previous_rule": round(sum(previous[i] for i in idx) / len(idx), 4)}
    for key in sorted({(r["ecosystem"], r["category"]) for r in test if r["label"] == "0"}):
        idx = [i for i, r in enumerate(test) if (r["ecosystem"], r["category"]) == key]
        report["test_recall_by_group"]["benign/" + "/".join(key)] = {
            "n": len(idx), "model_flag_rate": round(sum(flagged[i] for i in idx) / len(idx), 4),
            "previous_rule_flag_rate": round(sum(previous[i] for i in idx) / len(idx), 4)}
    # discovery period: recall on the newest fifth of the test part's malware vs the rest
    dated = sorted((r["discovered"], i) for i, r in enumerate(test) if r["label"] == "1" and r.get("discovered"))
    if len(dated) >= 20:
        cut = dated[int(len(dated) * 0.8)][0]
        for name, members in (("older", [i for d, i in dated if d < cut]), ("newest_fifth", [i for d, i in dated if d >= cut])):
            report["test_recall_by_group"][f"discovered/{name}"] = {
                "n": len(members), "from": min(test[i]["discovered"] for i in members),
                "chosen": round(sum(flagged[i] for i in members) / len(members), 4),
                "previous_rule": round(sum(previous[i] for i in members) / len(members), 4)}

    # permutation feature importance on the test set (PR-AUC drop, 10 shuffles)
    base_ap = average_precision(y_test, p_test)
    pfi = {}
    for j, feature in enumerate(FEATURES):
        drops = []
        for _ in range(10):
            column = [row[j] for row in x_test]
            rng.shuffle(column)
            shuffled = [row[:j] + [c] + row[j + 1:] for row, c in zip(x_test, column)]
            drops.append(base_ap - average_precision(y_test, predict(model, shuffled)))
        mean = sum(drops) / len(drops)
        sd = (sum((d - mean) ** 2 for d in drops) / (len(drops) - 1)) ** 0.5
        pfi[feature] = {"mean": round(mean, 4), "sd": round(sd, 4)}
    report["permutation_importance"] = dict(sorted(pfi.items(), key=lambda kv: -kv[1]["mean"]))

    w, b, shift = model
    means = [sum(row[j] for row in x_train) / len(x_train) for j in range(len(FEATURES))]
    contribution = {f: round(sum(abs(w[j] * (row[j] - means[j])) for row in x_test) / len(x_test), 4)
                    for j, f in enumerate(FEATURES)}
    report["mean_abs_contribution_log_odds"] = dict(sorted(contribution.items(), key=lambda kv: -kv[1]))
    report["prevalence"] = {f: {"malicious": round(sum(r[f] == "1" for r in usable if r["label"] == "1")
                                                   / max(1, sum(r["label"] == "1" for r in usable)), 4),
                                "benign": round(sum(r[f] == "1" for r in usable if r["label"] == "0")
                                                / max(1, sum(r["label"] == "0" for r in usable)), 4)}
                            for f in FEATURES}
    pypi_mal = [r for r in usable if r["ecosystem"] == "pypi" and r["label"] == "1"]
    report["pypi_setup_py_only"] = {
        "malicious": len(pypi_mal),
        "no_feature_but_setup_py_hit": sum(1 for r in pypi_mal if not any(r[f] == "1" for f in FEATURES)
                                           and r["setup_py_hits"])}

    weights = {f: round(w[j], 6) for j, f in enumerate(FEATURES)}
    intercept = round(b - shift, 6)
    body = {"weights": weights, "intercept": intercept, "threshold": round(chosen, 6),
            "means": {f: round(m, 6) for f, m in zip(FEATURES, means)},
            "decision": decision, "review_signals": review_signals,
            "without_guarddog": {"weights": {f: round(nogd_model[0][j], 6) for j, f in enumerate(FEATURES)
                                             if f not in GD_FEATURES},
                                 "intercept": round(nogd_model[1] - nogd_model[2], 6),
                                 "threshold": round(nogd_threshold, 6), "decision": nogd_decision,
                                 "review_signals": nogd_signals}}
    model_doc = {
        "model": "stage1-b-logistic", "features": list(FEATURES), **body,
        "version": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16],
        "decision_rule": "'rule': any review signal raises review and the probability ranks what is "
                         "held; 'model': the probability at or above the threshold raises review. Chosen "
                         "on cross-validated predictions: keep at least the recall of the review signals "
                         "before D6-37, then the fewest false alarms (D6-37).",
        "record_only_signals": record_only,
        "calibration": "probability at the training data's malicious share "
                       f"({sum(y_train) / len(y_train):.3f}); real installs have far fewer, so read it "
                       "as a ranking score, not a real-world probability",
        "training": {"date": datetime.now(UTC).date().isoformat(), "seed": args.seed, "lambda": lam,
                     "train": report["train"], "test": report["test"],
                     "sources": ["DataDog/malicious-software-packages-dataset (Apache-2.0)",
                                 "npm-high-impact (MIT) and top-pypi-packages rankings (benign names)"]},
        "test_metrics": report["test_metrics"]["model"],
        "test_decision": report["test_decisions"]["chosen"],
    }
    args.model_out.write_text(json.dumps(model_doc, indent=2) + "\n", encoding="utf-8")
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("train", "test", "lambda", "record_only_signals",
                                             "decision", "chosen", "previous_rule_cv", "candidates_cv",
                                             "test_metrics", "test_decisions",
                                             "test_recall_by_group", "without_guarddog")}, indent=2))


if __name__ == "__main__":
    main()
