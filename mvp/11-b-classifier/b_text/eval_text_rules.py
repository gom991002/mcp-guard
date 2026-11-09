"""Measure the stage 2 B description rules (D6-39).

Malicious: MCPTox (AAAI 2026) poisoned tool descriptions, 1,348 cases on 45 real
MCP servers, labelled with the attack template and risk class. The dataset has
no declared licence: it is read from a local copy and not stored here.
Benign: the same servers' authentic tool descriptions from MCPTox, and real
tool descriptions from Docker's MCP catalog (docker/mcp-registry, MIT).

Rules are those in src/mcp_guard/text_rules.py plus the operator phrase list of
the default policy. Fixed before running: a rule is kept only if it holds at
most 1% of benign descriptions (both benign sets together), and the kept rules
together at most 2%. Recall is reported per attack template: Template-2 cases
contain the literal "ignore the previous instructions".

Run: python mvp/11-b-classifier/b_text/eval_text_rules.py --mcptox <response_all.json> --docker <mcp-registry>/servers
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from mcp_guard.policy import _phrase_pattern  # noqa: E402
from mcp_guard.registry import DEFAULT_REGISTRY  # noqa: E402
from mcp_guard.text_rules import DESCRIPTION_RULES, scan  # noqa: E402

MAX_RULE_HOLD = 0.01
MAX_TOTAL_HOLD = 0.02
_BLOCK = re.compile(r"Tool:\s*(.+?)\s*\nDescription:\s*(.*?)(?=\n\s*\n\s*Tool:|\Z)", re.S)


def description(block: str) -> str:
    match = _BLOCK.search(block)
    return match.group(2).strip() if match else block


def hits(text: str) -> set[str]:
    found = {h.rule_id for h in scan(text, DESCRIPTION_RULES)}
    if any(_phrase_pattern(p).search(text) for p in DEFAULT_REGISTRY.suspicious_phrases):
        found.add("B_SUSPICIOUS_DESCRIPTION (operator phrases)")
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mcptox", type=Path, required=True)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "scripts" / "b_text" / "report.json")
    args = parser.parse_args()
    data = json.loads(args.mcptox.read_text(encoding="utf-8"))
    malicious, benign_mcptox = [], {}
    for server in data["servers"].values():
        for name, text in _BLOCK.findall(server["clean_system_promot"]):
            benign_mcptox[(server["server_name"], name)] = text.strip()
        for case in server["malicious_instance"]:
            malicious.append((case["metadata"].get("paradigm", "?"), case["metadata"].get("security risk", "?"),
                              description(case["poisoned_tool"])))
    benign_docker = []
    for path in sorted(args.docker.glob("*/tools.json")):
        tools = json.loads(path.read_text(encoding="utf-8"))
        tools = tools if isinstance(tools, list) else tools.get("tools", [])
        benign_docker += [t["description"] for t in tools if isinstance(t, dict) and isinstance(t.get("description"), str)]
    benign = [("mcptox_clean", t) for t in benign_mcptox.values()] + [("docker_catalog", t) for t in benign_docker]
    benign_hits = [(src, hits(t), t) for src, t in benign]
    mal_hits = [(paradigm, risk, hits(t)) for paradigm, risk, t in malicious]
    rules = [r.rule_id for r in DESCRIPTION_RULES] + ["B_SUSPICIOUS_DESCRIPTION (operator phrases)"]
    report: dict = {"benign": {"mcptox_clean": len(benign_mcptox), "docker_catalog": len(benign_docker)},
                    "malicious": len(malicious), "rules": {}}
    for rule in rules:
        held = [(src, t) for src, h, t in benign_hits if rule in h]
        caught = sum(rule in h for _, _, h in mal_hits)
        report["rules"][rule] = {
            "benign_hold_rate": round(len(held) / len(benign), 4),
            "benign_held_by_source": {s: sum(1 for src, _ in held if src == s) for s in report["benign"]},
            "benign_examples": [t[:160] for _, t in held[:5]],
            "recall": round(caught / len(malicious), 4)}
    kept = [r for r in rules if report["rules"][r]["benign_hold_rate"] <= MAX_RULE_HOLD]
    previous = ["B_DESCRIPTION_PROMPT_OVERRIDE", "B_DESCRIPTION_SECRET_HARVESTING",
                "B_SUSPICIOUS_DESCRIPTION (operator phrases)"]

    def combined(selection: list[str]) -> dict:
        held = sum(1 for _, h, _ in benign_hits if h & set(selection))
        by_paradigm: dict[str, list[int]] = {}
        by_risk: dict[str, list[int]] = {}
        for paradigm, risk, h in mal_hits:
            hit = bool(h & set(selection))
            for table, key in ((by_paradigm, paradigm), (by_risk, risk)):
                table.setdefault(key, [0, 0])
                table[key][0] += 1
                table[key][1] += hit
        return {"rules": selection, "benign_hold_rate": round(held / len(benign), 4),
                "recall": round(sum(bool(h & set(selection)) for _, _, h in mal_hits) / len(malicious), 4),
                "recall_by_template": {k: round(c / n, 4) for k, (n, c) in sorted(by_paradigm.items())},
                "recall_by_risk": {k: round(c / n, 4) for k, (n, c) in sorted(by_risk.items())}}

    report["before_d6_39"] = combined(previous)
    report["kept"] = combined(kept)
    report["kept_within_total_limit"] = report["kept"]["benign_hold_rate"] <= MAX_TOTAL_HOLD
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("benign", "malicious")}, ensure_ascii=False))
    for rule, r in report["rules"].items():
        print(f"{rule:46} benign hold {r['benign_hold_rate']:.2%} {r['benign_held_by_source']}  recall {r['recall']:.2%}")
    for key in ("before_d6_39", "kept"):
        r = report[key]
        print(f"{key}: benign hold {r['benign_hold_rate']:.2%}, recall {r['recall']:.2%}, by template {r['recall_by_template']}")


if __name__ == "__main__":
    main()
