"""Choose the M2 tool-name lookalike method on real tool names (D6-38).

Benign data: the tools.json files of Docker's MCP catalog (docker/mcp-registry,
MIT): real tool names from many servers. Each server's tools are compared with
the tools of all other servers, as an approved catalog would be; a flagged
tool is a false alarm (a review). Identical names are not compared: the MCP
specification expects them across servers.

Attacks: impersonation variants of the real names, one per class (ASCII and
Unicode homoglyphs, separators, case, omission, repetition, transposition,
substitution, word order, added prefix or suffix). They are generated here, so
recall is optimistic for the classes the methods were built for.

Rule fixed before running: among methods that hold at most 2% of benign tools,
the one with the highest recall (ties: the simpler method).

Run: python mvp/04-tools-list-relay/m2_names/eval_lookalike.py --servers <mcp-registry>/servers
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from mcp_guard.confusables import (  # noqa: E402
    confusable_match,
    lookalike_name,
    name_tokens,
    tool_name_violations,
)

MAX_BENIGN_HOLD = 0.02
METHODS = {  # simplest first
    "uts39 (standard)": None,
    "uts39+separators": dict(separators=True, reorder=False, edit="off"),
    "uts39+separators+reorder": dict(separators=True, reorder=True, edit="off"),
    "uts39+separators+reorder+edit(guarded)": dict(separators=True, reorder=True, edit="guarded"),
    "uts39+separators+reorder+edit(any)": dict(separators=True, reorder=True, edit="any"),
}
ADJACENT = {c: n for row in ("qwertyuiop", "asdfghjkl", "zxcvbnm") for c, n in zip(row, row[1:] + row[-2])}


def flagged(method: str, name: str, candidates: set[str]) -> bool:
    options = METHODS[method]
    if options is None:
        return confusable_match(name, candidates) is not None
    return lookalike_name(name, candidates, **options) is not None


def variants(name: str, rng: random.Random) -> dict[str, str]:
    out: dict[str, str] = {}
    for old, new in (("l", "1"), ("o", "0"), ("m", "rn"), ("w", "vv"), ("i", "l")):
        if old in name:
            out["ascii_homoglyph"] = name.replace(old, new, 1)
            break
    for old, new in (("a", "а"), ("e", "е"), ("o", "о")):
        if old in name:
            out["unicode_homoglyph"] = name.replace(old, new, 1)
            break
    words = name_tokens(name)
    if len(words) > 1:
        out["separators"] = ("-".join(words) if "_" in name else "_".join(words))
        out["word_order"] = "_".join(reversed(words))
    out["case"] = name.upper() if name != name.upper() else name.lower()
    letters = [i for i, c in enumerate(name) if c.isalpha()]
    if len(letters) > 2:
        i = rng.choice(letters[1:])
        out["omission"] = name[:i] + name[i + 1:]
        out["repetition"] = name[:i] + name[i] + name[i:]
        j = rng.choice(letters[:-1])
        if j + 1 < len(name) and name[j] != name[j + 1]:
            out["transposition"] = name[:j] + name[j + 1] + name[j] + name[j + 2:]
        k = rng.choice(letters)
        if name[k].lower() in ADJACENT:
            out["substitution"] = name[:k] + ADJACENT[name[k].lower()] + name[k + 1:]
    out["affix"] = name + "_v2" if rng.random() < 0.5 else "my_" + name
    return {k: v for k, v in out.items() if v != name}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--servers", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "scripts" / "m2_names" / "report.json")
    parser.add_argument("--seed", type=int, default=20261103)
    args = parser.parse_args()
    servers: dict[str, list[str]] = {}
    for path in sorted(args.servers.glob("*/tools.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        tools = data if isinstance(data, list) else data.get("tools", [])
        names = sorted({t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)})
        if names:
            servers[path.parent.name] = names
    all_names = {n for names in servers.values() for n in names}
    total = sum(len(v) for v in servers.values())
    report: dict = {"servers": len(servers), "tools": total, "methods": {}}
    rng = random.Random(args.seed)
    attack_cases = []  # (class, variant, approved catalogue = everything else)
    for server, names in servers.items():
        for name in names:
            for kind, variant in variants(name, rng).items():
                if variant not in all_names:  # an existing real name is not an attack
                    attack_cases.append((kind, variant, server))
    for method in METHODS:
        held, examples = 0, []
        for server, names in servers.items():
            others = {n for s, v in servers.items() if s != server for n in v}
            for name in names:
                if flagged(method, name, others - {name}):
                    held += 1
                    if len(examples) < 12:
                        options = METHODS[method]
                        match = (lookalike_name(name, others - {name}, **options) if options
                                 else (confusable_match(name, others), "skeleton"))
                        examples.append(f"{name} ~ {match[0]} ({match[1]})")
        caught, by_class = 0, {}
        for kind, variant, server in attack_cases:
            # the attacker's server is new: every real tool is in the approved catalogue
            hit = flagged(method, variant, all_names)
            format_hit = bool(tool_name_violations(variant))
            caught += hit or format_hit
            stats = by_class.setdefault(kind, [0, 0, 0])
            stats[0] += 1
            stats[1] += hit
            stats[2] += hit or format_hit
        report["methods"][method] = {
            "benign_hold_rate": round(held / total, 4), "benign_held": held, "benign_examples": examples,
            "recall_with_format_check": round(caught / len(attack_cases), 4),
            "recall_by_class": {k: {"n": n, "name_check": round(h / n, 4), "with_format": round(f / n, 4)}
                                for k, (n, h, f) in sorted(by_class.items())}}
    eligible = [m for m in METHODS if report["methods"][m]["benign_hold_rate"] <= MAX_BENIGN_HOLD]
    report["attacks"] = len(attack_cases)
    report["chosen"] = max(eligible, key=lambda m: (report["methods"][m]["recall_with_format_check"],
                                                     -list(METHODS).index(m))) if eligible else None
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for method, result in report["methods"].items():
        print(f"{method:42} benign hold {result['benign_hold_rate']:.2%}  recall {result['recall_with_format_check']:.2%}")
    print("chosen:", report["chosen"])


if __name__ == "__main__":
    main()
