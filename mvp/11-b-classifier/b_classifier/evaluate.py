"""Measure a B classifier per language: detection rate, false positives, CPU time.

python mvp/11-b-classifier/b_classifier/evaluate.py \
    --dataset mvp/11-b-classifier/datasets/eval_ko_en.jsonl --threshold 0.5

Cross-validated choice of a threshold at most 2% benign held (b_classifier/cv.py),
for the classifier, the engine's text rules and both together:

python mvp/11-b-classifier/b_classifier/evaluate.py \
    --dataset mvp/11-b-classifier/datasets/ko_eval_v2.jsonl --cv --resources --report r.json

``--rules-only`` needs no model. ``--resources`` reports load time, memory and
per-text time. Each dataset line: {"text", "label": "attack"|"benign", "lang",
"kind"}, plus "fold" and "field" (description|response) for --cv.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


def load_samples(path: str | Path) -> list[dict[str, Any]]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def evaluate(score: Callable[[str], float], samples: list[dict[str, Any]],
             threshold: float = 0.5) -> dict[str, Any]:
    rows = []
    for sample in samples:
        started = time.perf_counter()
        value = score(sample["text"])
        rows.append({**sample, "score": round(value, 4), "flagged": value >= threshold,
                     "ms": round((time.perf_counter() - started) * 1000, 1)})
    report = {"threshold": threshold, "samples": rows, "by_language": {}}
    for lang in sorted({row["lang"] for row in rows}) + ["all"]:
        group = [r for r in rows if lang == "all" or r["lang"] == lang]
        attacks = [r for r in group if r["label"] == "attack"]
        benign = [r for r in group if r["label"] == "benign"]
        report["by_language"][lang] = {
            "attacks": len(attacks), "benign": len(benign),
            "detection_rate": _rate(sum(r["flagged"] for r in attacks), len(attacks)),
            "false_positive_rate": _rate(sum(r["flagged"] for r in benign), len(benign)),
            "missed": [r["kind"] for r in attacks if not r["flagged"]],
            "false_alarms": [r["kind"] for r in benign if r["flagged"]],
            "ms_median": statistics.median([r["ms"] for r in group]) if group else None,
            "ms_max": max((r["ms"] for r in group), default=None),
        }
    return report


def _rate(hits: int, total: int) -> float | None:
    return round(hits / total, 3) if total else None


def rule_score(sample: dict[str, Any]) -> float:
    """1.0 when the engine's text rules for that field match (D6-39), else 0.0."""
    from mcp_guard.text_rules import DESCRIPTION_RULES, RESPONSE_RULES, scan

    rules = RESPONSE_RULES if sample.get("field") == "response" else DESCRIPTION_RULES
    return 1.0 if scan(sample["text"], rules) else 0.0


def resident_mb() -> float | None:
    """This process's resident memory in MB, where the platform tells it."""
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                    "PagefileUsage", "PeakPagefileUsage")]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return round(counters.WorkingSetSize / 2**20, 1)
    return None


def cv_report(samples: list[dict[str, Any]], score: Callable[[str], float] | None,
              max_fpr: float = 0.02) -> dict[str, Any]:
    from b_classifier.cv import cross_validate

    rows = [dict(sample, rules=rule_score(sample)) for sample in samples]
    keys = ["rules"]
    if score is not None:
        for row in rows:
            row["classifier"] = score(row["text"])
            row["either"] = max(row["classifier"], row["rules"])  # a rule hit counts as 1.0
        keys += ["classifier", "either"]
    return {"results": {key: cross_validate(rows, key, max_fpr) for key in keys},
            "scores": [{k: r[k] for k in ("group", "fold", "label", "kind", "field", *keys)} for r in rows]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a B classifier per language")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--model", default=None, help="Hugging Face model id (default Horizon Labs small)")
    parser.add_argument("--report", help="write the full JSON report here")
    parser.add_argument("--cv", action="store_true",
                        help="choose thresholds at most --max-fpr benign held, by grouped cross-validation")
    parser.add_argument("--max-fpr", type=float, default=0.02)
    parser.add_argument("--rules-only", action="store_true", help="with --cv: the text rules only, no model")
    parser.add_argument("--resources", action="store_true", help="report load time, memory and per-text time")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    samples = load_samples(args.dataset)
    if args.cv and args.rules_only:
        report = cv_report(samples, None, args.max_fpr)
        _print_cv(report)
        if args.report:
            Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0
    from b_classifier.prompt_guard import MODEL_ID, PromptGuardClassifier

    before, cpu_before, started = resident_mb(), time.process_time(), time.perf_counter()
    classifier = PromptGuardClassifier(args.model or MODEL_ID)
    load = {"load_seconds": round(time.perf_counter() - started, 2), "rss_before_mb": before,
            "rss_after_load_mb": resident_mb()}
    if args.cv:
        report = cv_report(samples, classifier.score, args.max_fpr)
        _print_cv(report)
    else:
        report = evaluate(classifier.score, samples, args.threshold)
    if args.resources:
        times = []
        for sample in samples:
            begun = time.perf_counter()
            classifier.score(sample["text"])
            times.append((time.perf_counter() - begun) * 1000)
        times.sort()
        report["resources"] = {**load, "rss_after_scoring_mb": resident_mb(),
                               "cpu_seconds_total": round(time.process_time() - cpu_before, 2),
                               "texts": len(times), "ms_median": round(statistics.median(times), 1),
                               "ms_p95": round(times[int(len(times) * 0.95) - 1], 1),
                               "ms_max": round(times[-1], 1),
                               "text_chars_median": statistics.median(len(s["text"]) for s in samples)}
        print("resources:", json.dumps(report["resources"]))
    report["model"] = {"id": classifier.model_id, "revision": classifier.revision}
    for lang, summary in report.get("by_language", {}).items():
        print(f"{lang}: detection {summary['detection_rate']} | false positives "
              f"{summary['false_positive_rate']} | median {summary['ms_median']} ms | "
              f"missed {summary['missed']} | false alarms {summary['false_alarms']}")
    if args.report:
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def _print_cv(report: dict[str, Any]) -> None:
    for key, result in report["results"].items():
        d, f = result["detection"], result["false_positive"]
        print(f"{key}: detection {d['rate']} {d['ci95']} | benign held {f['rate']} {f['ci95']} "
              f"({f['hits']}/{f['total']}) | thresholds {[round(t, 4) for t in result['thresholds']]}")


if __name__ == "__main__":
    raise SystemExit(main())
