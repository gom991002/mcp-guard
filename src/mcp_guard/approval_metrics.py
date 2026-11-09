"""Approval fatigue metrics over the M1 audit log (stage 4, 3-A4).

People stop reading prompts they see often. Repeated security warnings draw
steadily less brain response (repetition suppression, Kirwan et al., Frontiers
in Psychology 2020, fMRI), and attention to warnings reported falling within a
work week and partly recovering between days (Vance et al., MIS Quarterly
2018). Practitioner guides on agent oversight watch the same behaviour through
three numbers: approval rate, time to decide, and how rarely anything is
refused. This module computes those per approver and per tool from the audit
log, plus the habituation pattern the studies describe: decisions getting
faster as the same person sees more prompts in one day.

Flags are heuristics to start a review, not a verdict on a person; their
thresholds are not validated for agent approvals (design discussion):

* ``near_always_approved``: approval rate at or above 0.95 over 20 or more prompts;
* ``fast_decisions``: median time to decide under 2 seconds;
* ``speeding_up``: within a day, later prompts are decided faster (negative
  Spearman correlation of decision time with the prompt's order that day, at
  or below -0.5, over 10 or more decisions).

Local limits: Claude Code tells no hook what the user answered, so an
approval is inferred when the tool then runs and a prompt with no recorded
outcome counts as "no record" (refused or abandoned), not as refused. The
remote approval page (D6-49) records approvals, refusals and expiries; an
expiry is counted apart from a refusal.

Run: python -m mcp_guard.approval_metrics --audit-log <audit.jsonl> [--json]
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .audit import AuditEvent, read_audit_log

MIN_PROMPTS_FOR_RATE = 20
NEAR_ALWAYS = 0.95
FAST_SECONDS = 2.0
MIN_DECISIONS_FOR_TREND = 10
SPEEDING_UP_RHO = -0.5


def prompts(events: Iterable[AuditEvent]) -> list[dict[str, Any]]:
    """One record per approval prompt: who, which tool, when, outcome, seconds to decide."""
    asked: dict[tuple[str, str], dict[str, Any]] = {}
    for event in sorted(events, key=lambda e: e.timestamp):
        key = (event.session_id, event.request_id)
        if event.event_type == "approval_requested" and event.request_id:
            asked[key] = {"approver": event.user or "(unknown)", "tool": _tool(event),
                          "session": event.session_id, "requested_at": event.timestamp,
                          "outcome": "no_record", "seconds": None}
        elif event.event_type == "approval_decided" and key in asked:
            record = asked[key]
            record["outcome"] = "approved" if event.verdict == "allow" else \
                "expired" if event.details.get("decision") == "expired" else "refused"
            seconds = event.details.get("seconds")
            record["seconds"] = float(seconds) if isinstance(seconds, (int, float)) else None
    return sorted(asked.values(), key=lambda r: r["requested_at"])


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    decided = [r for r in records if r["outcome"] != "no_record"]
    approved = sum(r["outcome"] == "approved" for r in records)
    times = [r["seconds"] for r in records if r["seconds"] is not None]
    out: dict[str, Any] = {
        "prompts": len(records), "approved": approved,
        "refused": sum(r["outcome"] == "refused" for r in records),
        "expired": sum(r["outcome"] == "expired" for r in records),
        "no_record": len(records) - len(decided),
        "approval_rate": round(approved / len(records), 4) if records else None,
        "median_seconds": round(statistics.median(times), 3) if times else None,
        "share_under_2s": round(sum(t < FAST_SECONDS for t in times) / len(times), 4) if times else None,
        "max_prompts_in_a_day": max(_per_day(records).values(), default=0),
        "speed_trend_rho": _speed_trend(records),
    }
    flags = []
    if len(records) >= MIN_PROMPTS_FOR_RATE and out["approval_rate"] >= NEAR_ALWAYS:
        flags.append("near_always_approved")
    if out["median_seconds"] is not None and out["median_seconds"] < FAST_SECONDS:
        flags.append("fast_decisions")
    if out["speed_trend_rho"] is not None and out["speed_trend_rho"] <= SPEEDING_UP_RHO:
        flags.append("speeding_up")
    out["flags"] = flags
    return out


def report(events: Iterable[AuditEvent]) -> dict[str, Any]:
    records = prompts(events)
    by: dict[str, dict[str, list]] = {"approver": defaultdict(list), "tool": defaultdict(list)}
    for record in records:
        by["approver"][record["approver"]].append(record)
        by["tool"][record["tool"]].append(record)
    return {"overall": summarise(records),
            "by_approver": {k: summarise(v) for k, v in sorted(by["approver"].items())},
            "by_tool": {k: summarise(v) for k, v in sorted(by["tool"].items())},
            "limits": ["local approvals are inferred from the tool running; a prompt with no "
                       "recorded outcome is 'no_record', not 'refused'",
                       "flag thresholds are heuristics, not validated for agent approvals"]}


def _tool(event: AuditEvent) -> str:
    return f"{event.server_name}:{event.tool_name}" if event.server_name else event.tool_name


def _per_day(records: list[dict[str, Any]]) -> dict[tuple[str, str], int]:
    days: dict[tuple[str, str], int] = defaultdict(int)
    for r in records:
        days[(r["approver"], r["requested_at"].date().isoformat())] += 1
    return days


def _speed_trend(records: list[dict[str, Any]]) -> float | None:
    """Spearman rho of decision time against the prompt's order within its approver's day."""
    order: dict[tuple[str, str], int] = defaultdict(int)
    pairs = []
    for r in records:
        day = (r["approver"], r["requested_at"].date().isoformat())
        order[day] += 1
        if r["seconds"] is not None:
            pairs.append((order[day], r["seconds"]))
    if len(pairs) < MIN_DECISIONS_FOR_TREND:
        return None
    x, y = _ranks([p[0] for p in pairs]), _ranks([p[1] for p in pairs])
    mx, my = statistics.fmean(x), statistics.fmean(y)
    sx = sum((a - mx) ** 2 for a in x) ** 0.5
    sy = sum((b - my) ** 2 for b in y) ** 0.5
    if not sx or not sy:
        return None
    return round(sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy), 4)


def _ranks(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mcp-guard approval fatigue metrics (M1 audit log)")
    parser.add_argument("--audit-log", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = report(read_audit_log(args.audit_log, include_rotated=True))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    for scope in ("by_approver", "by_tool"):
        for name, s in result[scope].items():
            print(f"{scope[3:]:8} {name:30} prompts={s['prompts']:4} approved={s['approval_rate']} "
                  f"median_s={s['median_seconds']} under_2s={s['share_under_2s']} "
                  f"trend={s['speed_trend_rho']} flags={','.join(s['flags']) or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
