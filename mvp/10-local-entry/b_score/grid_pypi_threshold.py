"""Apply the D6-46 PyPI review threshold rule to the grid search winners (D6-40).

D6-46 rule, unchanged: on training-only 10-fold out-of-fold predictions, the
lowest PyPI threshold whose PyPI benign false-positive rate is at most 0.15
(the most recall within that limit); npm keeps the global threshold. The
test part is read once, for the report. The winners' settings come from
grid_report.json; the folds and split are train.py's.

Also reports, on the PyPI test packages, GuardDog's own verdicts (its risk
labels) next to the models, as the comparison with an existing service.

Run in the grid search container (scikit-learn):
  python /repo/mvp/10-local-entry/b_score/grid_pypi_threshold.py --data <features.csv> \
    --report <grid_report.json> --models <grid_models.json>
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grid_search as G  # noqa: E402
import train as T  # noqa: E402

MAX_PYPI_FPR = 0.15


def pypi_threshold(rows: list[dict], y: list[int], scores: list[float]) -> float:
    idx = [i for i, r in enumerate(rows) if r["ecosystem"] == "pypi"]
    benign = [scores[i] for i in idx if y[i] == 0]
    best = None
    for t in sorted({scores[i] for i in idx}, reverse=True):
        if sum(s >= t for s in benign) / len(benign) <= MAX_PYPI_FPR:
            best = t  # keep lowering while the false-alarm limit holds
    return best if best is not None else max(scores) + 1e-9


def confusion_on(rows, y, flags, eco):
    idx = [i for i, r in enumerate(rows) if r["ecosystem"] == eco]
    return T.confusion([y[i] for i in idx], [flags[i] for i in idx])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261102)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    with args.data.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    usable = [r for r in rows if int(r["files"]) > 0 and int(r.get("av_blocked") or 0) == 0
              and r.get("gd_missing", "0") != "1"]
    train, test = T.stratified_split(usable, 0.2, rng)
    fold_ids = T.folds(train, 10, rng)
    y, y_test = [int(r["label"]) for r in train], [int(r["label"]) for r in test]
    weight = (len(y) - sum(y)) / sum(y)
    grid = json.loads(args.report.read_text(encoding="utf-8"))
    models = json.loads(args.models.read_text(encoding="utf-8"))
    out = {"rule": __doc__.split("\n\n")[1].strip()}
    for variant, features in (("with_guarddog", G.FEATURES),
                              ("without_guarddog", [f for f in G.FEATURES if f not in G.GD])):
        win = grid[variant]["winner"]
        cols = G.columns(features, win["family"], win["params"].get("ecosystem", False))
        x = G.design(train, cols)
        oof = [0.0] * len(train)
        for k in range(10):
            held = set(fold_ids[k])
            idx = [i for i in range(len(train)) if i not in held]
            m = G.Model(win["family"], win["params"], cols, weight).fit([x[i] for i in idx], [y[i] for i in idx])
            for i, v in zip(fold_ids[k], m.predict([x[i] for i in fold_ids[k]])):
                oof[i] = v
        assert abs(T.average_precision(y, oof) - win["pr_auc_cv"]) < 1e-3, "folds differ from the grid search"
        global_t = models[variant]["threshold"]
        pypi_t = pypi_threshold(train, y, oof)
        final = G.Model(win["family"], win["params"], cols, weight).fit(x, y)
        p_test = [G.probability(models[variant], row) for row in G.design(test, cols)]
        flags = [p >= (pypi_t if r["ecosystem"] == "pypi" else global_t) for p, r in zip(p_test, test)]
        cv_flags = [p >= (pypi_t if r["ecosystem"] == "pypi" else global_t) for p, r in zip(oof, train)]
        out[variant] = {"family": win["family"], "global_threshold": global_t, "pypi_threshold": round(pypi_t, 6),
                        "cv_pypi": confusion_on(train, y, cv_flags, "pypi"),
                        "test_all": T.confusion(y_test, flags),
                        "test_pypi": confusion_on(test, y_test, flags, "pypi"),
                        "test_npm": confusion_on(test, y_test, flags, "npm"),
                        "test_pypi_global_threshold_only": confusion_on(
                            test, y_test, [p >= global_t for p in p_test], "pypi"),
                        "test_pypi_by_group": {
                            "/".join(k): round(sum(flags[i] for i, r in enumerate(test)
                                                   if (r["label"], r["category"]) == k and r["ecosystem"] == "pypi")
                                               / max(1, sum((r["label"], r["category"]) == k and r["ecosystem"] == "pypi"
                                                            for r in test)), 4)
                            for k in sorted({(r["label"], r["category"]) for r in test if r["ecosystem"] == "pypi"})}}
        models[variant]["threshold_by_ecosystem"] = {"pypi": round(pypi_t, 6)}
        del final
    # GuardDog on its own, the existing service in this data (selection bias: see README)
    gd = {}
    for name, rule in (("guarddog_high_risk", lambda r: r["GD_RISK_HIGH"] == "1"),
                       ("guarddog_suspicious_or_high", lambda r: r["GD_RISK_HIGH"] == "1" or r["GD_RISK_SUSPICIOUS"] == "1"),
                       ("guarddog_any_threat_rule", lambda r: r["GD_THREAT"] == "1"),
                       ("guarddog_any_finding", lambda r: r["GD_THREAT"] == "1" or r["GD_CAPABILITY"] == "1")):
        flags = [rule(r) for r in test]
        gd[name] = {"pypi": confusion_on(test, y_test, flags, "pypi"), "npm": confusion_on(test, y_test, flags, "npm")}
    out["guarddog_alone_test"] = gd
    args.out.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    args.models.write_text(json.dumps(models) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
