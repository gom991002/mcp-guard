"""Grid search over model families for the stage 1 B score (D6-40).

Selection rule, fixed before the run:

* only models whose score cannot fall when a B signal turns on (monotone
  non-decreasing in every signal), since a B signal may only raise risk;
  the package's ecosystem (npm or PyPI) is an input, not a signal, and is
  unconstrained;
* the same split and the same 10 folds as train.py (same seed, same calls);
* the winner is the family and setting with the highest pooled out-of-fold
  PR-AUC on the training part; the test part is read once, for the report;
* the decision threshold is then chosen as train.py does (D6-37): keep the
  cross-validated recall of the review signals before D6-37, then the fewest
  false alarms;
* the same search is run again without the GuardDog features, for scans with
  GuardDog off.

Families: logistic regression with non-negative weights (the D6-35 model),
the same with separate weights per ecosystem, gradient-boosted trees
(scikit-learn HistGradientBoosting), random forest and extra trees, the tree
models with monotonic constraints. Trees are exported to JSON so the engine
evaluates them with the standard library; the export is checked against
scikit-learn's own predictions.

scikit-learn is used here only, not by the engine. Run in a container:
  docker run --rm -v <repo>:/repo python:3.12-slim sh -c \
    "pip install -q scikit-learn==1.5.2 && python /repo/mvp/10-local-entry/b_score/grid_search.py \
     --data /repo/mvp/10-local-entry/b_score/data/features.csv"
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train as T  # noqa: E402  (same helpers, split and folds)

import numpy as np  # noqa: E402
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier  # noqa: E402

FEATURES = list(T.FEATURES)
GD = set(T.GD_FEATURES)
ORDER = ("logistic", "logistic_by_ecosystem", "gradient_boosting", "random_forest", "extra_trees")

GRIDS = {
    "logistic": [{"lambda": lam} for lam in T.LAMBDAS],
    "logistic_by_ecosystem": [{"lambda": lam} for lam in T.LAMBDAS],
    "gradient_boosting": [dict(zip(("learning_rate", "max_leaf_nodes", "max_iter", "l2_regularization",
                                    "min_samples_leaf", "ecosystem"), v))
                          for v in itertools.product((0.03, 0.1, 0.3), (4, 8, 16), (50, 150, 400), (0.0, 1.0),
                                                     (5, 20), (True, False))],
    **{family: [dict(zip(("n_estimators", "max_depth", "min_samples_leaf", "max_features", "ecosystem"), v))
                for v in itertools.product((100, 300), (4, 8, 12), (1, 5, 20), ("sqrt", 0.5, 1.0), (True, False))]
       for family in ("random_forest", "extra_trees")},
}


def columns(features: list[str], family: str, ecosystem: bool) -> list[str]:
    if family == "logistic_by_ecosystem":
        return [f"{f}@{e}" for e in ("npm", "pypi") for f in features] + ["@npm", "@pypi"]
    return features + (["@pypi"] if ecosystem and family not in ("logistic",) else [])


def design(rows: list[dict], cols: list[str]) -> list[list[int]]:
    out = []
    for r in rows:
        eco = r["ecosystem"]
        row = []
        for c in cols:
            if c.startswith("@"):
                row.append(int(eco == c[1:]))
            elif "@" in c:
                f, e = c.split("@")
                row.append(int(r[f] == "1" and eco == e))
            else:
                row.append(int(r[c] == "1"))
        out.append(row)
    return out


class Model:
    def __init__(self, family: str, params: dict, cols: list[str], weight: float):
        self.family, self.params, self.cols, self.weight = family, params, cols, weight

    def fit(self, x, y):
        if self.family.startswith("logistic"):
            self.m = T.fit(x, y, self.params["lambda"])
            return self
        cst = [0 if c.startswith("@") else 1 for c in self.cols]
        cw = {0: 1.0, 1: self.weight}
        if self.family == "gradient_boosting":
            p = {k: v for k, v in self.params.items() if k != "ecosystem"}
            self.m = HistGradientBoostingClassifier(**p, monotonic_cst=cst, class_weight=cw, early_stopping=False,
                                                    random_state=0)
        else:
            p = {k: v for k, v in self.params.items() if k != "ecosystem"}
            cls = RandomForestClassifier if self.family == "random_forest" else ExtraTreesClassifier
            self.m = cls(**p, monotonic_cst=cst, class_weight=cw, n_jobs=2, random_state=0)
        self.m.fit(np.array(x), np.array(y))
        return self

    def predict(self, x) -> list[float]:
        if self.family.startswith("logistic"):
            return T.predict(self.m, x)
        return [float(v) for v in self.m.predict_proba(np.array(x))[:, 1]]


def search(train, y, fold_ids, features, weight, log):
    results = []
    for family in ORDER:
        for params in GRIDS[family]:
            cols = columns(features, family, params.get("ecosystem", False))
            x = design(train, cols)
            oof = [0.0] * len(train)
            fold_ap = []
            started = time.time()
            for k in range(10):
                held = set(fold_ids[k])
                idx = [i for i in range(len(train)) if i not in held]
                m = Model(family, params, cols, weight).fit([x[i] for i in idx], [y[i] for i in idx])
                pred = m.predict([x[i] for i in fold_ids[k]])
                for i, v in zip(fold_ids[k], pred):
                    oof[i] = v
                fold_ap.append(T.average_precision([y[i] for i in fold_ids[k]], pred))
            mean = sum(fold_ap) / 10
            sd = (sum((a - mean) ** 2 for a in fold_ap) / 9) ** 0.5
            results.append({"family": family, "params": params, "pr_auc": round(T.average_precision(y, oof), 4),
                            "roc_auc": round(T.roc_auc(y, oof), 4), "fold_pr_auc_sd": round(sd, 4),
                            "_oof": oof})
            log(f"{family:22} {json.dumps(params):110} PR-AUC {results[-1]['pr_auc']:.4f} "
                f"({time.time() - started:.1f}s)")
    best = max(results, key=lambda r: (r["pr_auc"], -ORDER.index(r["family"])))
    return results, best


def export(model: Model) -> dict:
    """The fitted model as JSON the engine evaluates without scikit-learn."""
    if model.family.startswith("logistic"):
        w, b, shift = model.m
        return {"kind": model.family, "columns": model.cols,
                "weights": {c: round(v, 6) for c, v in zip(model.cols, w)}, "intercept": round(b - shift, 6)}
    trees = []
    if model.family == "gradient_boosting":
        for (predictor,) in model.m._predictors:
            nodes = []
            for n in predictor.nodes:
                nodes.append([-1, 0.0, 0, 0, round(float(n["value"]), 9)] if n["is_leaf"] else
                             [int(n["feature_idx"]), float(n["num_threshold"]), int(n["left"]), int(n["right"]), 0.0])
            trees.append(nodes)
        return {"kind": "gradient_boosting", "columns": model.cols,
                "baseline": float(np.ravel(model.m._baseline_prediction)[0]), "trees": trees}
    for est in model.m.estimators_:
        t = est.tree_
        nodes = []
        for i in range(t.node_count):
            if t.children_left[i] == -1:
                v = t.value[i][0]
                nodes.append([-1, 0.0, 0, 0, round(float(v[1] / v.sum()), 9)])
            else:
                nodes.append([int(t.feature[i]), float(t.threshold[i]), int(t.children_left[i]),
                              int(t.children_right[i]), 0.0])
        trees.append(nodes)
    return {"kind": model.family, "columns": model.cols, "trees": trees}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--current-model", type=Path, default=T.ROOT / "src" / "mcp_guard" / "data" / "b_score_stage1.json")
    parser.add_argument("--out", type=Path, default=T.ROOT / "scripts" / "b_score" / "data" / "grid_report.json")
    parser.add_argument("--export", type=Path, default=T.ROOT / "scripts" / "b_score" / "data" / "grid_models.json")
    parser.add_argument("--seed", type=int, default=20261102)
    parser.add_argument("--quick", action="store_true", help="smoke test: two settings per family")
    args = parser.parse_args()
    if args.quick:
        for family in GRIDS:
            GRIDS[family] = GRIDS[family][:1] + GRIDS[family][-1:]
    log = lambda s: print(s, flush=True)  # noqa: E731
    rng = random.Random(args.seed)
    with args.data.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    usable = [r for r in rows if int(r["files"]) > 0 and int(r.get("av_blocked") or 0) == 0
              and r.get("gd_missing", "0") != "1"]
    train, test = T.stratified_split(usable, 0.2, rng)  # the calls train.py makes, in its order
    fold_ids = T.folds(train, 10, rng)
    y, y_test = [int(r["label"]) for r in train], [int(r["label"]) for r in test]
    weight = (len(y) - sum(y)) / sum(y)
    current = json.loads(args.current_model.read_text(encoding="utf-8"))
    review_signals = current["review_signals"]
    previous = T.confusion(y, T.any_signal(train, [f for f in T.PREVIOUS_REVIEW_SIGNALS if f in FEATURES]))

    report, exported = {"selection": __doc__.split("Families:")[0].strip(), "train": len(train),
                        "test": len(test)}, {}
    for variant, features in (("with_guarddog", FEATURES), ("without_guarddog", [f for f in FEATURES if f not in GD])):
        log(f"== {variant}")
        results, best = search(train, y, fold_ids, features, weight, log)
        signals = [f for f in review_signals if f in features]
        name, threshold, cuts, candidates = T.decide(y, best["_oof"], T.any_signal(train, signals), previous["recall"])
        cols = columns(features, best["family"], best["params"].get("ecosystem", False))
        final = Model(best["family"], best["params"], cols, weight).fit(design(train, cols), y)
        x_test = design(test, cols)
        p_test = final.predict(x_test)
        doc = export(final)
        from_json = [probability(doc, row) for row in x_test]
        gap = max(abs(a - b) for a, b in zip(p_test, from_json))
        assert gap < 1e-6, f"export differs from scikit-learn by {gap}"
        # monotonicity, checked: turning any signal on never lowers the score
        signal_cols = [j for j, c in enumerate(cols) if not c.startswith("@")]
        drops = sum(probability(doc, [1 if j == s else v for j, v in enumerate(row)]) < probability(doc, row) - 1e-12
                    for row in design(train, cols) for s in signal_cols if row[s] == 0)
        assert drops == 0, f"{drops} cases where a signal lowered the score"
        flags = [v >= threshold for v in p_test] if name != "rule" else T.any_signal(test, signals)
        best_by_family = {f: max((r for r in results if r["family"] == f), key=lambda r: r["pr_auc"]) for f in ORDER}
        report[variant] = {
            "winner": {"family": best["family"], "params": best["params"], "pr_auc_cv": best["pr_auc"],
                       "fold_pr_auc_sd": best["fold_pr_auc_sd"]},
            "best_per_family_cv": {f: {"params": r["params"], "pr_auc": r["pr_auc"], "roc_auc": r["roc_auc"],
                                       "fold_pr_auc_sd": r["fold_pr_auc_sd"]} for f, r in best_by_family.items()},
            "decision": name, "threshold": round(threshold, 6), "candidates_cv": candidates,
            "export_max_gap": gap,
            "test": {"pr_auc": round(T.average_precision(y_test, p_test), 4),
                     "pr_auc_ci95": T.bootstrap_ci(y_test, p_test, T.average_precision, rng),
                     "roc_auc": round(T.roc_auc(y_test, p_test), 4), "brier": round(T.brier(y_test, p_test), 4),
                     "decision": T.confusion(y_test, flags),
                     "flag_rate_by_group": {"/".join(k): round(sum(flags[i] for i, r in enumerate(test)
                                                                    if (r["label"], r["ecosystem"], r["category"]) == k)
                                                                / sum((r["label"], r["ecosystem"], r["category"]) == k
                                                                      for r in test), 4)
                                            for k in sorted({(r["label"], r["ecosystem"], r["category"]) for r in test})}},
            "grid": [{k: v for k, v in r.items() if k != "_oof"} for r in results],
        }
        exported[variant] = {**doc, "threshold": round(threshold, 6), "decision": "rule" if name == "rule" else "model",
                             "review_signals": signals, "features": features}
        log(json.dumps({k: v for k, v in report[variant].items() if k != "grid"}, indent=1)[:3000])
    args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    args.export.write_text(json.dumps(exported) + "\n", encoding="utf-8")


def probability(doc: dict, row: list[int]) -> float:
    """What the engine computes (mirrors src/mcp_guard/b_score.py)."""
    import math

    if doc["kind"].startswith("logistic"):
        z = doc["intercept"] + sum(doc["weights"][c] * v for c, v in zip(doc["columns"], row))
        return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))
    leaves = []
    for nodes in doc["trees"]:
        i = 0
        while nodes[i][0] != -1:
            i = nodes[i][2] if row[nodes[i][0]] <= nodes[i][1] else nodes[i][3]
        leaves.append(nodes[i][4])
    if doc["kind"] == "gradient_boosting":
        z = doc["baseline"] + sum(leaves)
        return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))
    return sum(leaves) / len(leaves)


if __name__ == "__main__":
    main()
