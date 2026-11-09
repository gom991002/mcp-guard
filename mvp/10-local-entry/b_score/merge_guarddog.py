"""Fill the GuardDog feature columns of features.csv from guarddog_pass.py output (D6-37).

The columns come from local_entry.code_scan.guarddog_features, the function the
scan uses, so training and use encode GuardDog's verdict the same way. Rows
GuardDog could not scan are marked gd_missing=1; train.py leaves them out.

Run: python mvp/10-local-entry/b_score/merge_guarddog.py --features <features.csv> --guarddog <guarddog.jsonl> --out <csv>
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry.code_scan import GD_FEATURES, guarddog_features  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--guarddog", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    results = {}
    for line in args.guarddog.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        results[record["uid"]] = record
    with args.features.open(encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        rows, fields = list(reader), list(reader.fieldnames or [])
    fields += [f for f in ("gd_missing", "gd_rules", "gd_score") if f not in fields]
    missing = 0
    for row in rows:
        result = results.get(row["uid"])
        ok = result is not None and "error" not in result
        missing += not ok
        row.update({k: str(v) for k, v in guarddog_features(result if ok else None).items()})
        row["gd_missing"] = "0" if ok else "1"
        row["gd_rules"] = ";".join(result.get("rules", [])) if ok else ""
        row["gd_score"] = str(result.get("score", "")) if ok else ""
    with args.out.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} rows, GuardDog missing for {missing}; columns {', '.join(GD_FEATURES)}")


if __name__ == "__main__":
    main()
