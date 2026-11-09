from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# Verdict vocabulary is shared with the engine of record (src/mcp_guard) so the
# two cannot drift. Run with PYTHONPATH=src.
from mcp_guard.models import RuleAction, Severity, Verdict


class RuleFamily(str, Enum):
    YARA_TEXT = "yara_text"
    OPA_DECISION = "opa_decision"
    SIGMA_CORRELATION = "sigma_correlation"
    SEMGREP_STATIC = "semgrep_static"
    WAF_GATEWAY = "waf_gateway"


@dataclass(frozen=True)
class Rule:
    """One rule, labelled the way Docs/Core_mds/architecture.md defines.

    marker: a drawing ID (M1-M5, L1-L4, C1-C3, 2-A5, 3-A4), "A" for a decision
    check that has no drawing ID, or "B" for a signal.
    rule_id prefix: the marker, or S<stage>_ when the marker is "A".
    """

    rule_id: str
    family: RuleFamily
    title: str
    stage: str
    marker: str
    severity: Severity
    default_action: RuleAction
    description: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Match:
    rule: Rule
    message: str
    evidence: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


def verdict_from_matches(matches: list[Match]) -> Verdict:
    # Same rule as mcp_guard.policy: only A rules may block; a B signal can
    # raise the verdict to review but never decides block or allow.
    if any(match.rule.default_action == RuleAction.BLOCK for match in matches):
        return Verdict.BLOCK
    if any(
        match.rule.default_action in {RuleAction.REVIEW, RuleAction.SIGNAL}
        for match in matches
    ):
        return Verdict.REVIEW
    return Verdict.ALLOW
