"""Measure prefix/suffix (combosquatting) rules for M2 tool names (D6-38 follow-up).

Benign: real tool names from Docker's MCP catalog (docker/mcp-registry, MIT);
each server's tools are compared with all other servers' tools.
Attacks: a real name with one extra word before or after it. Words are split
into those in the rule's affix list and words the rules have never seen, and
recall is reported for both, so the list cannot simply grade itself.

Rules:
  A  the name contains another tool's whole word sequence plus extra words
  B  A, and every extra word is in the common-affix list
  C  B, and the imitated name has two or more words

Run: python mvp/04-tools-list-relay/m2_names/eval_affix.py --servers <mcp-registry>/servers
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from mcp_guard.confusables import name_tokens  # noqa: E402

AFFIXES = frozenset({"my", "new", "official", "real", "secure", "safe", "pro", "plus", "v2", "v3", "2",
                     "latest", "beta", "fixed", "enhanced", "advanced", "better", "fast", "mcp", "tool"})
UNSEEN = ("super", "ultra", "true", "verified", "x", "premium", "lite", "next", "turbo", "prime")


def contains(words: tuple[str, ...], base: tuple[str, ...]) -> tuple[str, ...] | None:
    """Extra words if ``base`` appears as a contiguous run inside ``words``."""
    n, m = len(words), len(base)
    if m == 0 or n <= m:
        return None
    for i in range(n - m + 1):
        if words[i:i + m] == base:
            return words[:i] + words[i + m:]
    return None


def rule_hit(rule: str, name: str, catalogue: dict[tuple[str, ...], str]) -> str | None:
    words = name_tokens(name)
    for base, original in catalogue.items():
        extra = contains(words, base)
        if extra is None:
            continue
        if rule == "A":
            return original
        if all(w in AFFIXES for w in extra) and (rule == "B" or len(base) >= 2):
            return original
    return None


def load(servers_dir: Path) -> dict[str, list[str]]:
    servers = {}
    for path in sorted(servers_dir.glob("*/tools.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        tools = data if isinstance(data, list) else data.get("tools", [])
        names = sorted({t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)})
        if names:
            servers[path.parent.name] = names
    return servers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--servers", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "scripts" / "m2_names" / "affix_report.json")
    parser.add_argument("--seed", type=int, default=20261103)
    args = parser.parse_args()
    servers = load(args.servers)
    all_names = {n for v in servers.values() for n in v}
    total = sum(len(v) for v in servers.values())
    rng = random.Random(args.seed)
    attacks = []  # (seen?, variant)
    for names in servers.values():
        for name in names:
            for seen, pool in ((True, sorted(AFFIXES)), (False, UNSEEN)):
                word = rng.choice(pool)
                variant = f"{word}_{name}" if rng.random() < 0.5 else f"{name}_{word}"
                if variant not in all_names:
                    attacks.append((seen, variant, name))
    report: dict = {"servers": len(servers), "tools": total, "attacks": len(attacks), "rules": {}}
    full = {name_tokens(n): n for n in all_names}
    for rule in ("A", "B", "C"):
        held, examples = 0, []
        for server, names in servers.items():
            catalogue = {name_tokens(n): n for s, v in servers.items() if s != server for n in v}
            for name in names:
                hit = rule_hit(rule, name, {k: v for k, v in catalogue.items() if v != name})
                if hit:
                    held += 1
                    if len(examples) < 15:
                        examples.append(f"{name} contains {hit}")
        caught = {True: [0, 0], False: [0, 0]}
        for seen, variant, base in attacks:
            caught[seen][0] += 1
            caught[seen][1] += rule_hit(rule, variant, full) is not None
        report["rules"][rule] = {
            "benign_hold_rate": round(held / total, 4), "benign_held": held, "benign_examples": examples,
            "recall_listed_affixes": round(caught[True][1] / caught[True][0], 4),
            "recall_unseen_affixes": round(caught[False][1] / caught[False][0], 4)}
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for rule, r in report["rules"].items():
        print(f"rule {rule}: benign hold {r['benign_hold_rate']:.2%} ({r['benign_held']}), "
              f"recall listed {r['recall_listed_affixes']:.2%}, unseen {r['recall_unseen_affixes']:.2%}")
        print("   e.g.", r["benign_examples"][:8])


if __name__ == "__main__":
    main()
