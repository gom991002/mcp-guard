"""Write the grid search winner (D6-40) as the engine's B score model; standard library only.

Run: python mvp/10-local-entry/b_score/apply_grid.py --models <grid_models.json> --report <grid_report.json>
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODEL = ROOT / "src" / "mcp_guard" / "data" / "b_score_stage1.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--pypi-report", type=Path, required=True,
                        help="grid_pypi_threshold.py output: D6-46 PyPI thresholds for these models")
    parser.add_argument("--model-out", type=Path, default=MODEL)
    args = parser.parse_args()
    models = json.loads(args.models.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    pypi = json.loads(args.pypi_report.read_text(encoding="utf-8"))
    if not all("threshold_by_ecosystem" in models[v] for v in ("with_guarddog", "without_guarddog")):
        raise SystemExit("run grid_pypi_threshold.py first: the D6-46 PyPI thresholds are missing")
    current = json.loads(MODEL.read_text(encoding="utf-8"))  # train.py's output: split, signals, metadata
    main_model, variant = models["with_guarddog"], models["without_guarddog"]
    win = report["with_guarddog"]["winner"]
    body = {**main_model, "without_guarddog": variant}
    doc = {
        "model": f"stage1-b-{win['family'].replace('_', '-')}", **body,
        "version": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16],
        "selection": f"D6-40 grid search: {win['family']} {json.dumps(win['params'])}, highest cross-validated "
                     f"PR-AUC ({win['pr_auc_cv']}); without GuardDog: "
                     f"{report['without_guarddog']['winner']['family']} "
                     f"{json.dumps(report['without_guarddog']['winner']['params'])}",
        "decision_rule": current["decision_rule"],
        "record_only_signals": current["record_only_signals"],
        "calibration": current["calibration"],
        "training": {**current["training"], "date": datetime.now(UTC).date().isoformat()},
        "test_metrics": {k: v for k, v in report["with_guarddog"]["test"].items()
                         if k not in ("decision", "flag_rate_by_group")},
        "test_decision": pypi["with_guarddog"]["test_all"],  # with the D6-46 PyPI threshold
    }
    args.model_out.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    print(json.dumps({k: doc[k] for k in ("model", "version", "selection", "threshold", "decision")}, indent=1))


if __name__ == "__main__":
    main()
