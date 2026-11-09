"""Measure the description LLM check (D6-44) beside the phrase rules (D6-39).

Same data as eval_text_rules.py (MCPTox poisoned descriptions, read from a
local copy and not stored; MCPTox clean descriptions and Docker's MCP catalog
as benign). A local model on CPU is slow, so a stratified sample is drawn
with a fixed seed: 33 malicious per attack template (99) and 50 benign from
each benign source (100), about 3 hours on a CPU-only 7B model.

Fixed before running: the check is worth enabling if, together with the
rules, it holds at most 2% of benign descriptions (the D6-39 total limit) and
catches more poisoned descriptions than the rules alone. Also reported: how
often the model cited words that are not in the description (dropped by the
guard), and how often its reply was unusable.

Run: python mvp/11-b-classifier/b_text/eval_description_llm.py --mcptox <response_all.json> \
       --docker <mcp-registry>/servers --base-url http://127.0.0.1:11434/v1 --model qwen2.5-coder:7b
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for folder in ("src", "mvp/11-b-classifier", "mvp/11-b-classifier/b_text"):
    sys.path.insert(0, str(ROOT / folder))

from b_classifier.description_llm_client import OpenAICompatibleReviewer  # noqa: E402
from eval_text_rules import _BLOCK, description, hits  # noqa: E402
from mcp_guard.description_llm import build_messages, verify  # noqa: E402


def wilson(k: int, n: int) -> list[float]:
    if not n:
        return [0.0, 0.0]
    z, p = 1.96, k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mcptox", type=Path, required=True)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--http-host", action="append", default=[])
    parser.add_argument("--malicious", type=int, default=99)
    parser.add_argument("--benign-per-source", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--out", type=Path, default=ROOT / "scripts" / "b_text" / "report_llm.json")
    args = parser.parse_args()
    rng = random.Random(args.seed)
    data = json.loads(args.mcptox.read_text(encoding="utf-8"))
    malicious, clean = {}, {}
    for server in data["servers"].values():
        for name, text in _BLOCK.findall(server["clean_system_promot"]):
            clean[(server["server_name"], name)] = text.strip()
        for case in server["malicious_instance"]:
            malicious.setdefault(case["metadata"].get("paradigm", "?"), []).append(description(case["poisoned_tool"]))
    docker = []
    for path in sorted(args.docker.glob("*/tools.json")):
        tools = json.loads(path.read_text(encoding="utf-8"))
        tools = tools if isinstance(tools, list) else tools.get("tools", [])
        docker += [t["description"] for t in tools if isinstance(t, dict) and isinstance(t.get("description"), str)]
    share = args.malicious // len(malicious)
    sample = [(1, template, t) for template in sorted(malicious)
              for t in rng.sample(malicious[template], min(share, len(malicious[template])))]
    sample += [(0, "mcptox_clean", t) for t in rng.sample(sorted(clean.values()), args.benign_per_source)]
    sample += [(0, "docker_catalog", t) for t in rng.sample(sorted(docker), args.benign_per_source)]

    reviewer = OpenAICompatibleReviewer(args.base_url, args.model, timeout=600, http_hosts=tuple(args.http_host))
    rows = []
    for n, (label, group, text) in enumerate(sample, 1):
        started = time.time()
        try:
            result = verify(text, reviewer.complete(build_messages(text)))
            error = ""
        except Exception as exc:  # noqa: BLE001 - counted as unusable
            result, error = {"raised": [], "benign": [], "unverified": 0}, type(exc).__name__
        rows.append({"label": label, "group": group, "llm": bool(result["raised"]), "rules": bool(hits(text)),
                     "unusable": bool(error), "error": error, "unverified": result["unverified"],
                     "categories": sorted({f["category"] for f in result["raised"]}),
                     "seconds": round(time.time() - started, 1)})
        print(f"{n:4d}/{len(sample)} label={label} {group:14} llm={rows[-1]['llm']!s:5} "
              f"rules={rows[-1]['rules']!s:5} unverified={result['unverified']} {error} ({rows[-1]['seconds']}s)",
              flush=True)

    def rate(selected, key):
        k = sum(1 for r in selected if key(r))
        return {"n": len(selected), "k": k, "rate": round(k / len(selected), 4) if selected else 0.0,
                "ci95": wilson(k, len(selected))}

    mal = [r for r in rows if r["label"] == 1]
    ben = [r for r in rows if r["label"] == 0]
    report = {"model": args.model, "seed": args.seed, "sample": {"malicious": len(mal), "benign": len(ben)},
              "recall": {"rules": rate(mal, lambda r: r["rules"]), "llm": rate(mal, lambda r: r["llm"]),
                         "rules_or_llm": rate(mal, lambda r: r["rules"] or r["llm"])},
              "benign_hold": {"rules": rate(ben, lambda r: r["rules"]), "llm": rate(ben, lambda r: r["llm"]),
                              "rules_or_llm": rate(ben, lambda r: r["rules"] or r["llm"])},
              "recall_by_template": {t: rate([r for r in mal if r["group"] == t], lambda r: r["rules"] or r["llm"])
                                     for t in sorted(malicious)},
              "benign_hold_by_source": {s: rate([r for r in ben if r["group"] == s], lambda r: r["llm"])
                                        for s in ("mcptox_clean", "docker_catalog")},
              "unusable_replies": rate(rows, lambda r: r["unusable"]),
              "replies_with_unverified_quotes": rate(rows, lambda r: r["unverified"] > 0),
              "mean_seconds": round(sum(r["seconds"] for r in rows) / len(rows), 1)}
    report["worth_enabling"] = (report["benign_hold"]["rules_or_llm"]["rate"] <= 0.02
                                and report["recall"]["rules_or_llm"]["k"] > report["recall"]["rules"]["k"])
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
