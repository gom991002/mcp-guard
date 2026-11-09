"""Measure the stage 2 structural signals (src/mcp_guard/structure_signals.py) with the word rules.

Same data as eval_text_rules.py (MCPTox read from a local copy, never stored
here; Docker's MCP catalog, MIT), split by server: a server whose SHA-256 of
its name is even is development, odd is test. The signals were written by
looking at development servers only. Bars fixed before the test run, the same
as D6-39: each signal holds at most 1% of benign descriptions, and all
description signals together (word rules + structural) at most 2%.

Run: python -I mvp/11-b-classifier/b_text/eval_structure.py --mcptox <response_all.json> --docker <mcp-registry>/servers

Staged check (rules -> classifier -> LLM for what is left), when the models run:
add --classifier, and --llm-url/--llm-model. The classifier threshold and the
LLM floor are chosen on the development half so that everything together holds
at most 2% of its benign descriptions, then reported on the test half. Scores
are cached in --cache (keyed by text) so a slow model is asked once per text;
--llm-sample N asks the LLM about at most N texts per half (fixed seed).
--llm-band LOW,HIGH asks it only about texts whose classifier score is in
[LOW, HIGH): the staged check's grey zone, so a CPU model finishes in time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from mcp_guard.structure_signals import description_signals  # noqa: E402
from mcp_guard.text_rules import DESCRIPTION_RULES, scan  # noqa: E402

MAX_RULE_HOLD = 0.01
MAX_TOTAL_HOLD = 0.02
_TOOL = re.compile(r"Tool:\s*(.+?)\s*\nDescription:\s*(.*?)(?=\nArguments:|\n\s*\n\s*Tool:|\Z)", re.S)
STRUCTURE = ("B_DESCRIPTION_CROSS_TOOL_DIRECTIVE", "B_DESCRIPTION_ARGUMENT_TAMPERING", "B_DESCRIPTION_PRIORITY_CLAIM")


def split(name: str) -> str:
    return "dev" if int(hashlib.sha256(name.encode("utf-8")).hexdigest(), 16) % 2 == 0 else "test"


def load(mcptox: Path, docker: Path) -> tuple[list[dict], list[dict]]:
    data = json.loads(mcptox.read_text(encoding="utf-8"))
    attacks, benign = [], []
    for server in data["servers"].values():
        siblings = list(server["tool_names"])
        part = split(server["server_name"])
        for name, text in _TOOL.findall(server["clean_system_promot"]):
            benign.append({"part": part, "source": "mcptox_clean", "name": name.strip(),
                           "text": text.strip(), "siblings": siblings})
        for case in server["malicious_instance"]:
            block = case["poisoned_tool"].replace("\\n", "\n")
            found = _TOOL.search(block)
            name, text = (found.group(1).strip(), found.group(2).strip()) if found else ("", block)
            attacks.append({"part": part, "name": name, "text": text, "siblings": siblings,
                            "template": case["metadata"].get("paradigm", "?"),
                            "risk": case["metadata"].get("security risk", "?")})
    for path in sorted(docker.glob("*/tools.json")):
        tools = json.loads(path.read_text(encoding="utf-8"))
        tools = tools if isinstance(tools, list) else tools.get("tools", [])
        tools = [t for t in tools if isinstance(t, dict) and isinstance(t.get("description"), str)]
        names = [str(t.get("name", "")) for t in tools]
        for tool in tools:
            benign.append({"part": split(path.parent.name), "source": "docker_catalog", "name": str(tool.get("name", "")),
                           "text": tool["description"], "siblings": names})
    return attacks, benign


def signals(item: dict) -> set[str]:
    found = {h.rule_id for h in scan(item["text"], DESCRIPTION_RULES)}
    return found | {h.rule_id for h in description_signals(item["text"], item["name"], item["siblings"])}


def summary(attacks: list[dict], benign: list[dict], rules: set[str]) -> dict:
    held = [b for b in benign if b["hits"] & rules]
    caught = [a for a in attacks if a["hits"] & rules]
    by: dict[str, dict[str, list[int]]] = {"template": defaultdict(lambda: [0, 0]), "risk": defaultdict(lambda: [0, 0])}
    for a in attacks:
        for key in ("template", "risk"):
            by[key][a[key]][0] += 1
            by[key][a[key]][1] += bool(a["hits"] & rules)
    return {"benign": len(benign), "benign_held": len(held), "benign_hold_rate": round(len(held) / len(benign), 4),
            "attacks": len(attacks), "recall": round(len(caught) / len(attacks), 4),
            "by_template": {k: round(c / n, 4) for k, (n, c) in sorted(by["template"].items())},
            "by_risk": {k: round(c / n, 4) for k, (n, c) in sorted(by["risk"].items())},
            # Only Docker catalog text (MIT) is kept; MCPTox has no licence notice.
            "benign_held_by_source": {src: sum(b["source"] == src for b in held)
                                      for src in ("mcptox_clean", "docker_catalog")},
            "benign_examples": [b["text"][:160] for b in held if b["source"] == "docker_catalog"][:8]}


def _cached(cache: dict, kind: str, text: str, compute) -> object:
    key = f"{kind}:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"
    if key not in cache:
        cache[key] = compute(text)
    return cache[key]


def staged(attacks: list[dict], benign: list[dict], args: argparse.Namespace) -> dict:
    """Rules, then the classifier, then the LLM on what is left; thresholds from the dev half."""
    sys.path.insert(0, str(ROOT / "mvp" / "11-b-classifier"))
    cache = json.loads(args.cache.read_text(encoding="utf-8")) if args.cache and args.cache.exists() else {}
    items = attacks + benign
    if args.classifier:
        from b_classifier.prompt_guard import PromptGuardClassifier
        classifier = PromptGuardClassifier()
        for item in items:
            item["score"] = _cached(cache, "classifier", item["text"], classifier.score)
    band = tuple(float(x) for x in args.llm_band.split(",")) if args.llm_band else None
    reviewer = None
    if args.llm_url:
        from b_classifier.description_llm_client import OpenAICompatibleReviewer
        from mcp_guard.description_llm import build_messages, verify
        reviewer = OpenAICompatibleReviewer(args.llm_url, args.llm_model, timeout=600,
                                            http_hosts=tuple(args.llm_http_host))
        rng = random.Random(7)
        for part in ("dev", "test"):
            open_items = [i for i in items if i["part"] == part and not i["hits"]
                          and (band is None or band[0] <= i.get("score", 0.0) < band[1])]
            asked = open_items if not args.llm_sample else rng.sample(open_items, min(args.llm_sample, len(open_items)))
            for item in asked:
                item["llm"] = _cached(cache, f"llm:{args.llm_model}", item["text"],
                                      lambda t: bool(verify(t, reviewer.complete(build_messages(t)))["raised"]))
    if args.cache:
        args.cache.write_text(json.dumps(cache), encoding="utf-8")

    def flagged(item: dict, threshold: float | None, floor: float | None) -> bool:
        if item["hits"]:
            return True
        score = item.get("score")
        if threshold is not None and score is not None and score >= threshold:
            return True
        if "llm" not in item or (floor is not None and score is not None and score < floor):
            return False
        return item["llm"]

    def rates(part: str, threshold: float | None, floor: float | None) -> dict:
        a = [i for i in attacks if i["part"] == part]
        b = [i for i in benign if i["part"] == part]
        return {"recall": round(sum(flagged(i, threshold, floor) for i in a) / len(a), 4),
                "benign_hold_rate": round(sum(flagged(i, threshold, floor) for i in b) / len(b), 4),
                "attacks": len(a), "benign": len(b)}

    grid = sorted({round(i["score"], 4) for i in items if "score" in i} | {1.01}) if args.classifier else [None]
    floors = [None, 0.01, 0.05, 0.1, 0.2, 0.3, 0.5] if args.classifier and reviewer else [None]
    best = None
    for threshold in grid:
        for floor in floors:
            dev = rates("dev", threshold, floor)
            if dev["benign_hold_rate"] <= MAX_TOTAL_HOLD and (best is None or dev["recall"] > best[2]["recall"]):
                best = (threshold, floor, dev)
    threshold, floor, dev = best if best else (None, None, rates("dev", None, None))
    note = "LLM asked on a sample: rates count only the sampled texts as LLM-checked" if args.llm_sample else ""
    return {"classifier_threshold": threshold, "llm_floor": floor, "dev": dev, "test": rates("test", threshold, floor),
            "note": note}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mcptox", type=Path, required=True)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--part", choices=("dev", "test", "all"), default="dev")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--classifier", action="store_true", help="add the Horizon B classifier (needs onnxruntime)")
    parser.add_argument("--llm-url", help="OpenAI-compatible endpoint for the description LLM check")
    parser.add_argument("--llm-model")
    parser.add_argument("--llm-sample", type=int, default=0)
    parser.add_argument("--llm-band", help="LOW,HIGH: ask the LLM only in this classifier score range")
    parser.add_argument("--llm-http-host", action="append", default=[],
                        help="host the LLM may be reached on over plain http (e.g. host.docker.internal)")
    parser.add_argument("--cache", type=Path, help="JSON cache of classifier scores and LLM answers")
    args = parser.parse_args()
    attacks, benign = load(args.mcptox, args.docker)
    for item in attacks + benign:
        item["hits"] = signals(item)
    if args.classifier or args.llm_url:
        report = staged(attacks, benign, args)
        print(json.dumps(report, indent=1))
        if args.out:
            args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return
    if args.part != "all":
        attacks = [a for a in attacks if a["part"] == args.part]
        benign = [b for b in benign if b["part"] == args.part]
    words = {r.rule_id for r in DESCRIPTION_RULES}
    report = {"part": args.part, "per_signal": {r: summary(attacks, benign, {r}) for r in (*sorted(words), *STRUCTURE)},
              "word_rules": summary(attacks, benign, words),
              "structure_only": summary(attacks, benign, set(STRUCTURE)),
              "word_and_structure": summary(attacks, benign, words | set(STRUCTURE))}
    report["bars"] = {"each_signal_at_most_1pct": all(v["benign_hold_rate"] <= MAX_RULE_HOLD
                                                       for v in report["per_signal"].values()),
                      "together_at_most_2pct": report["word_and_structure"]["benign_hold_rate"] <= MAX_TOTAL_HOLD}
    for key in ("per_signal",):
        for rule, r in report[key].items():
            print(f"{rule:40} hold {r['benign_hold_rate']:.2%} ({r['benign_held']}/{r['benign']})  recall {r['recall']:.2%}")
    for key in ("word_rules", "structure_only", "word_and_structure"):
        r = report[key]
        print(f"{key:20} hold {r['benign_hold_rate']:.2%} ({r['benign_held']}/{r['benign']})  recall {r['recall']:.2%} "
              f"({r['attacks']})  {r['by_template']}")
    print("bars:", report["bars"])
    if args.out:
        args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
