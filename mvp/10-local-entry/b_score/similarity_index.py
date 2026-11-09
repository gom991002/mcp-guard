"""Evaluate and build the known-malware similarity index (stage 1 B, D6-36).

Index entries are files of "malicious intent" packages only: compromised
versions of real libraries are mostly the library's own code, which would
flag the genuine library. Entries that also match a benign package's file are
removed.

Two variants are compared by 5-fold cross-validation on the training part (the
same split as train.py): index every code file, or only files with a Semgrep
signal. The test part is read once, for the report. The production index is
then built from all malicious-intent packages with --variant (default "hit").

Result (2026-11-02): neither variant added a malicious package the review
signals had not already held on the test part, and the "all" variant matched
real requests, urllib3 and zod files, because lookalike malware copies the
library it imitates. Matches are therefore evidence for reviewers, not a review
signal, and the index keeps only files that carried a Semgrep signal.

Run:
  python mvp/10-local-entry/b_score/similarity_index.py --features mvp/10-local-entry/b_score/data/features.csv \\
      --fingerprints <fingerprints.jsonl>
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry",
               "mvp/10-local-entry/b_score"):
    sys.path.insert(0, str(ROOT / folder))

from mcp_guard import similarity  # noqa: E402
from train import FEATURES, folds, stratified_split  # noqa: E402

MAX_ADDED_BENIGN = 0.01


def key(row: dict) -> tuple[str, str, str]:
    return row["ecosystem"], row["name"], str(row["label"])


def build(packages: list[dict], prints: dict, benign: list[dict], variant: str) -> similarity.Index:
    index = similarity.Index()
    for package in packages:
        if package["label"] != "1" or package["category"] != "malicious_intent":
            continue
        for name, sig, has_hit in prints.get(key(package), []):
            if variant == "all" or has_hit:
                index.add(f"{package['name']}@{package['version']} {name}", similarity.decode(sig))
    # drop entries that a benign package's file also matches
    remove = set()
    for package in benign:
        for _, sig, _ in prints.get(key(package), []):
            decoded = similarity.decode(sig)
            for band in similarity.bands(decoded):
                for i in index.buckets.get(band, ()):
                    if similarity.jaccard(decoded, index.signatures[i]) >= similarity.MATCH_JACCARD:
                        remove.add(i)
    kept = similarity.Index((index.labels[i], index.signatures[i])
                            for i in range(len(index.labels)) if i not in remove)
    kept.removed_as_benign = len(remove)  # type: ignore[attr-defined]
    return kept


def flagged(index: similarity.Index, package: dict, prints: dict) -> bool:
    return any(index.best(similarity.decode(sig)) is not None for _, sig, _ in prints.get(key(package), []))


def held_by_rule(row: dict, review_signals: list[str]) -> bool:
    return any(row[f] == "1" for f in review_signals)


def evaluate(index: similarity.Index, rows: list[dict], prints: dict, review_signals: list[str]) -> dict:
    mal = [r for r in rows if r["label"] == "1"]
    ben = [r for r in rows if r["label"] == "0"]
    sim_mal = [r for r in mal if flagged(index, r, prints)]
    sim_ben = [r for r in ben if flagged(index, r, prints)]
    added_mal = [r for r in sim_mal if not held_by_rule(r, review_signals)]
    added_ben = [r for r in sim_ben if not held_by_rule(r, review_signals)]
    rule_mal = sum(held_by_rule(r, review_signals) for r in mal)
    rule_ben = sum(held_by_rule(r, review_signals) for r in ben)
    groups = {}
    for group in sorted({(r["ecosystem"], r["category"]) for r in mal}):
        members = [r for r in mal if (r["ecosystem"], r["category"]) == group]
        groups["/".join(group)] = {"n": len(members),
                                   "similarity": round(sum(r in sim_mal for r in members) / len(members), 4)}
    return {"malicious": len(mal), "benign": len(ben),
            "similarity_malicious": len(sim_mal), "similarity_benign": len(sim_ben),
            "added_malicious": len(added_mal), "added_benign": len(added_ben),
            "rule_recall": round(rule_mal / len(mal), 4),
            "rule_plus_similarity_recall": round((rule_mal + len(added_mal)) / len(mal), 4),
            "rule_false_positive_rate": round(rule_ben / len(ben), 4),
            "rule_plus_similarity_false_positive_rate": round((rule_ben + len(added_ben)) / len(ben), 4),
            "by_group": groups}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--fingerprints", type=Path, required=True)
    parser.add_argument("--model", type=Path, default=ROOT / "src" / "mcp_guard" / "data" / "b_score_stage1.json")
    parser.add_argument("--index-out", type=Path, default=similarity.INDEX_PATH)
    parser.add_argument("--report-out", type=Path, default=ROOT / "scripts" / "b_score" / "data" / "similarity_report.json")
    parser.add_argument("--seed", type=int, default=20261102)
    parser.add_argument("--variant", choices=("all", "hit"), default="hit")
    args = parser.parse_args()
    with args.features.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    usable = [r for r in rows if int(r["files"]) > 0 and int(r.get("av_blocked") or 0) == 0]
    prints = {}
    with args.fingerprints.open(encoding="utf-8") as stream:
        for line in stream:
            record = json.loads(line)
            prints[(record["ecosystem"], record["name"], str(record["label"]))] = record["files"]
    review_signals = json.loads(args.model.read_text(encoding="utf-8")).get("review_signals", list(FEATURES))

    rng = random.Random(args.seed)
    train, test = stratified_split(usable, 0.2, rng)  # the same split as train.py
    fold_ids = folds(train, 5, random.Random(args.seed + 1))
    report: dict = {"cv": {}}
    for variant in ("all", "hit"):
        added_mal = added_ben = benign_total = 0
        for k in range(5):
            held = set(fold_ids[k])
            fit_rows = [train[i] for i in range(len(train)) if i not in held]
            eval_rows = [train[i] for i in fold_ids[k]]
            index = build(fit_rows, prints, [r for r in fit_rows if r["label"] == "0"], variant)
            result = evaluate(index, eval_rows, prints, review_signals)
            added_mal += result["added_malicious"]
            added_ben += result["added_benign"]
            benign_total += result["benign"]
        report["cv"][variant] = {"added_malicious": added_mal, "added_benign": added_ben,
                                 "added_benign_rate": round(added_ben / benign_total, 4)}
    variant = args.variant
    report["variant"] = variant
    report["use"] = "evidence for reviewers and the review aid; does not raise review"

    train_index = build(train, prints, [r for r in train if r["label"] == "0"], variant)
    report["test"] = evaluate(train_index, test, prints, review_signals)
    report["train_index_entries"] = len(train_index.labels)

    benign_all = [r for r in usable if r["label"] == "0"]
    index = build(usable, prints, benign_all, variant)
    meta = {"model": "known-malware-similarity", "variant": variant, "use": report["use"],
            "date": datetime.now(UTC).date().isoformat(),
            "source": "DataDog/malicious-software-packages-dataset (Apache-2.0), malicious-intent packages",
            "removed_as_benign": index.removed_as_benign,  # type: ignore[attr-defined]
            "packages": sum(1 for r in usable if r["label"] == "1" and r["category"] == "malicious_intent")}
    args.index_out.write_text(json.dumps(index.to_json(meta)) + "\n", encoding="utf-8")
    report["production_index"] = {**meta, "entries": len(index.labels),
                                  "bytes": args.index_out.stat().st_size}
    args.report_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
