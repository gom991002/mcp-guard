"""Evaluate the LLM review aid on held test packages (D6-36).

The aid only ever sees packages the review signals held. This script takes the
held packages of the test part (the same split as train.py, never used for
training), samples malicious and benign ones, rebuilds each package's evidence
exactly as the scan does (Semgrep findings, known-malware similarity, code
excerpts), asks the model, and compares its assessment with the label.

The two numbers that matter:
* malicious packages called "likely_benign": a reviewer who trusted the aid
  would let them through;
* benign packages called "likely_benign": review work the aid could save.

Run inside Docker on the network of the model server (samples are malware):
  docker run --rm --network mcp-guard-eval -v "<repo>:/repo:ro" -v "<out>:/out" \\
    --entrypoint python3 semgrep/semgrep:1.183.0 /repo/mvp/10-local-entry/b_score/eval_review_assist.py \\
    --features /repo/mvp/10-local-entry/b_score/data/features.csv --out /out/review_eval.json \\
    --base-url http://mcp-guard-ollama:11434/v1 --model qwen2.5-coder:7b --work /work
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry",
               "mvp/10-local-entry/b_score"):
    sys.path.insert(0, str(ROOT / folder))

import build_dataset as data  # noqa: E402
from local_entry import code_scan, review_assist  # noqa: E402
from mcp_guard.b_score import score  # noqa: E402
from mcp_guard.dependencies import _normalize, _popular  # noqa: E402
from train import stratified_split  # noqa: E402


def wilson(k: int, n: int) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p, z = k / n, 1.96
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def ask(base_url: str, model: str, messages: list[dict], timeout: float) -> str:
    # The same request review_assist.chat sends; the model server is a container on
    # a private Docker network, which review_assist's http-only-on-localhost rule
    # does not know about.
    body = json.dumps({"model": model, "messages": messages, "temperature": 0,
                       "response_format": {"type": "json_object"}}).encode()
    request = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())["choices"][0]["message"]["content"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--model-file", type=Path, default=ROOT / "src" / "mcp_guard" / "data" / "b_score_stage1.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--per-class", type=int, default=30)
    parser.add_argument("--seed", type=int, default=20261102)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--items", type=Path, help="re-evaluate the packages of an earlier report (same sample)")
    args = parser.parse_args()

    with args.features.open(encoding="utf-8") as stream:
        rows = [r for r in csv.DictReader(stream) if int(r["files"]) > 0 and int(r.get("av_blocked") or 0) == 0]
    _, test = stratified_split(rows, 0.2, random.Random(args.seed))  # the split train.py used
    review_signals = json.loads(args.model_file.read_text(encoding="utf-8"))["review_signals"]
    held = [r for r in test if any(r[f] == "1" for f in review_signals)]
    rng = random.Random(args.seed + 7)
    sample = []
    if args.items:  # the same packages as an earlier run, for a direct comparison
        wanted = {(r["ecosystem"], r["name"], str(r["label"]))
                  for r in json.loads(args.items.read_text(encoding="utf-8"))["results"]}
        sample = [r for r in rows if (r["ecosystem"], r["name"], r["label"]) in wanted]
    for label in ("1", "0") if not args.items else ():
        pool = sorted((r for r in held if r["label"] == label), key=lambda r: (r["ecosystem"], r["name"]))
        sample += rng.sample(pool, min(args.per_class, len(pool)))
    print(f"held test packages: {sum(r['label'] == '1' for r in held)} malicious, "
          f"{sum(r['label'] == '0' for r in held)} benign; sampled {len(sample)}", flush=True)

    popular = {eco: {_normalize(n) for n in _popular(eco)} for eco in ("npm", "pypi")}
    args.work.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="review-eval-", dir=args.work) as temp:
        work = Path(temp)
        items = []
        for n, row in enumerate(sample):
            item = {**row, "label": int(row["label"]), "key": f"p{n:03d}",
                    "cap": data.SAMPLE_CAPS.get((row["ecosystem"], row["category"]), (0, 20_000_000))[1]}
            folder = work / "pkg" / item["key"]
            try:
                if item["label"]:
                    data.write_malicious(item, folder, work / "setup" / item["key"])
                else:
                    data.write_benign(item, folder)
            except Exception as error:  # noqa: BLE001 - a fetch failure skips one package
                print(f"  skip {row['name']}: {error}", flush=True)
                continue
            items.append(item)
        body = code_scan.run_semgrep([work / "pkg"], "/usr/bin/semgrep", timeout=7200)
        skip = [work / "pkg" / i["key"] for i in items if _normalize(i["name"]) in popular[i["ecosystem"]]]
        targets = [work / "pkg" / i["key"] for i in items if work / "pkg" / i["key"] not in skip]
        body = code_scan.similar_to_known_malware(body, targets)
        for item in items:
            folder = (work / "pkg" / item["key"]).resolve()
            mine = [f for f in body["findings"] if f.get("path") and Path(f["path"]).resolve().is_relative_to(folder)]
            hits = {f["code"] for f in mine if f["code"] in code_scan.SCORED_RULE_CODES}
            files = [p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()]
            meta = None
            if item["ecosystem"] == "npm" and (folder / "package.json").is_file():
                try:
                    meta = json.loads((folder / "package.json").read_text("utf-8", "replace"))
                except ValueError:
                    meta = None
            features = code_scan.package_features(item["name"], item["ecosystem"], files, hits,
                                                  meta if isinstance(meta, dict) else None)
            evidence = [{k: f[k] for k in ("code", "path", "line", "message") if k in f}
                        for f in mine if f["code"] in {*code_scan.SCORED_RULE_CODES, code_scan.SIMILAR}][:20]
            description = (meta or {}).get("description", "") if isinstance(meta, dict) else ""
            if item["ecosystem"] == "pypi":
                from email.parser import HeaderParser

                text = item.get("metadata_text")
                for path in ([] if text else folder.glob("*.dist-info/METADATA")):
                    if path.is_file():
                        text = path.read_text(encoding="utf-8", errors="replace")
                description = str(HeaderParser().parsestr(text).get("Summary") or "") if text else ""
            package = {"name": item["name"], "version": item["version"], "score": score(features),
                       "evidence": evidence, "description": description}
            messages, ai_directed = review_assist.build_messages(
                package, review_assist.evidence_for({}, package))
            started = time.time()
            try:
                reply = review_assist.parse(ask(args.base_url, args.model, messages, args.timeout))
            except Exception as error:  # noqa: BLE001 - recorded as unclear, like the aid does
                reply = {"assessment": "unclear", "reasons": [f"no model answer: {error}"], "lines": [],
                         "suspicion": None, "checks": {}}
            results.append({"ecosystem": item["ecosystem"], "category": item["category"],
                            "label": item["label"], "name": item["name"], "version": item["version"],
                            "assessment": reply["assessment"], "reasons": reply["reasons"],
                            "suspicion": reply.get("suspicion"), "checks": reply.get("checks", {}),
                            "evidence_items": len(evidence),
                            "similar_to_known_malware": any(e["code"] == code_scan.SIMILAR for e in evidence),
                            "code_aimed_at_ai_reviewer": ai_directed,
                            "seconds": round(time.time() - started, 1)})
            print(f"  {len(results):3d} label={item['label']} {item['ecosystem']} {item['name'][:30]:30} "
                  f"-> {reply['assessment']} s={reply.get('suspicion')} ({results[-1]['seconds']}s) "
                  f"{(reply['reasons'] or [''])[0][:90]}", flush=True)

    summary = {}
    for label, name in ((1, "malicious"), (0, "benign")):
        group = [r for r in results if r["label"] == label]
        counts = {a: sum(r["assessment"] == a for r in group) for a in review_assist.ASSESSMENTS}
        summary[name] = {"n": len(group), **counts,
                         **{f"{a}_rate": round(counts[a] / len(group), 4) if group else 0.0
                            for a in review_assist.ASSESSMENTS},
                         **{f"{a}_ci95": wilson(counts[a], len(group)) for a in review_assist.ASSESSMENTS}}
    scored = [r for r in results if isinstance(r.get("suspicion"), int)]
    pos = [r["suspicion"] for r in scored if r["label"] == 1]
    neg = [r["suspicion"] for r in scored if r["label"] == 0]
    summary["suspicion_roc_auc"] = (round(sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
                                          / (len(pos) * len(neg)), 4) if pos and neg else None)
    summary["suspicion_scored"] = {"malicious": len(pos), "benign": len(neg)}
    summary["checks"] = {check: {name: {a: sum(r.get("checks", {}).get(check) == a for r in results
                                               if r["label"] == label) for a in review_assist.ANSWERS}
                                 for label, name in ((1, "malicious"), (0, "benign"))}
                         for check in review_assist.CHECKS}
    report = {"model": args.model, "base_url": args.base_url, "per_class": args.per_class, "seed": args.seed,
              "held_test": {"malicious": sum(r["label"] == "1" for r in held),
                            "benign": sum(r["label"] == "0" for r in held)},
              "summary": summary,
              "mean_seconds": round(sum(r["seconds"] for r in results) / max(1, len(results)), 1),
              "results": results}
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("model", "held_test", "summary", "mean_seconds")}, indent=2))


if __name__ == "__main__":
    main()
