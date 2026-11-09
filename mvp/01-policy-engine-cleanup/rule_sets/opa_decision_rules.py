from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from mcp_guard.confusables import confusable_match, tool_name_violations

from .common import Match, Rule, RuleAction, RuleFamily, Severity, Verdict, verdict_from_matches


@dataclass(frozen=True)
class DecisionInput:
    server_name: str
    namespace: str
    tool_name: str
    source: str
    schema_hash: str | None
    approved_schema_hash: str | None
    trusted_namespaces: frozenset[str]
    protected_tool_names: frozenset[str]
    registered_servers: frozenset[str]
    trusted_sources: frozenset[str]
    live_mode: bool = False
    approved_tool: bool = False
    description: str = ""
    approved_description: str = ""
    live_approved_schema_hash: str | None = None


@dataclass(frozen=True)
class DecisionRule:
    rule: Rule
    predicate: Callable[[DecisionInput], bool]
    message: str

    def evaluate(self, data: DecisionInput) -> Match | None:
        if not self.predicate(data):
            return None
        return Match(
            rule=self.rule,
            message=self.message,
            metadata={
                "server_name": data.server_name,
                "namespace": data.namespace,
                "tool_name": data.tool_name,
            },
        )


def _rule(
    rule_id: str,
    title: str,
    stage: str,
    marker: str,
    severity: Severity,
    action: RuleAction,
    description: str,
    tags: tuple[str, ...],
) -> Rule:
    return Rule(
        rule_id=rule_id,
        family=RuleFamily.OPA_DECISION,
        title=title,
        stage=stage,
        marker=marker,
        severity=severity,
        default_action=action,
        description=description,
        tags=tags,
    )


# A decisions for tool registration. IDs, markers, stages, and actions match
# the findings of mcp_guard.policy.evaluate_registration (checked by tests).
# Stage 4 (M4 value policy, 3-A4 approval) has no rules yet.
OPA_DECISION_RULES: tuple[DecisionRule, ...] = (
    DecisionRule(
        rule=_rule(
            "M2_EMPTY_SERVER_NAME",
            "Empty server name",
            "2-registration",
            "M2",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "A tool without a server name cannot be bound to a server.",
            ("identity-binding", "input-validation"),
        ),
        predicate=lambda data: not data.server_name.strip(),
        message="MCP server name is empty; the tool cannot be bound to a server.",
    ),
    DecisionRule(
        rule=_rule(
            "M2_EMPTY_TOOL_NAME",
            "Empty tool name",
            "2-registration",
            "M2",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "A tool without a name cannot be bound.",
            ("identity-binding", "input-validation"),
        ),
        predicate=lambda data: not data.tool_name.strip(),
        message="Tool name is empty.",
    ),
    DecisionRule(
        rule=_rule(
            "M2_EMPTY_NAMESPACE",
            "Empty namespace",
            "2-registration",
            "M2",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "A tool without a namespace cannot be bound.",
            ("identity-binding", "input-validation"),
        ),
        predicate=lambda data: not data.namespace.strip(),
        message="Tool namespace is empty.",
    ),
    DecisionRule(
        rule=_rule(
            "S0_UNREGISTERED_SERVER",
            "Unregistered MCP server",
            "0-entry",
            "A",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "Fail-closed: the core connects only to servers on the managed list.",
            ("fail-closed", "allow-list"),
        ),
        predicate=lambda data: data.server_name not in data.registered_servers,
        message="MCP server is not registered in mcp-guard policy.",
    ),
    DecisionRule(
        rule=_rule(
            "S0_UNTRUSTED_SOURCE",
            "Untrusted registration source",
            "0-entry",
            "A",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "Fail-closed: registrations must arrive through a trusted channel.",
            ("fail-closed", "allow-list"),
        ),
        predicate=lambda data: data.source not in data.trusted_sources,
        message="Tool registration source is not trusted.",
    ),
    DecisionRule(
        rule=_rule(
            "M2_PROTECTED_NAME_UNTRUSTED_NAMESPACE",
            "Protected tool from untrusted namespace",
            "2-registration",
            "M2",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "Blocks protected tool names outside trusted namespaces.",
            ("identity-binding", "impersonation"),
        ),
        predicate=lambda data: (
            data.tool_name in data.protected_tool_names
            and data.namespace not in data.trusted_namespaces
        ),
        message="Protected tool name is registered from an untrusted namespace.",
    ),
    DecisionRule(
        rule=_rule(
            "M2_CONFUSABLE_PROTECTED_NAME",
            "Lookalike of a protected tool name",
            "2-registration",
            "M2",
            Severity.CRITICAL,
            RuleAction.BLOCK,
            "Blocks names whose UTS #39 skeleton matches a protected tool name.",
            ("identity-binding", "impersonation", "confusables"),
        ),
        predicate=lambda data: (
            data.tool_name not in data.protected_tool_names
            and confusable_match(data.tool_name, data.protected_tool_names) is not None
        ),
        message="Tool name looks like a protected tool name but is not identical.",
    ),
    DecisionRule(
        rule=_rule(
            "M2_NONSTANDARD_TOOL_NAME",
            "Tool name outside MCP recommendation",
            "2-registration",
            "M2",
            Severity.WARNING,
            RuleAction.REVIEW,
            "Reviews tool names outside MCP's ASCII character and length recommendation.",
            ("confusables", "naming"),
        ),
        predicate=lambda data: (
            bool(data.tool_name.strip()) and bool(tool_name_violations(data.tool_name))
        ),
        message="Tool name is outside the MCP tool name recommendation.",
    ),
    DecisionRule(
        rule=_rule(
            "M3_SCHEMA_HASH_CHANGED",
            "Approved schema hash changed",
            "2-registration",
            "M3",
            Severity.WARNING,
            RuleAction.REVIEW,
            "Requires re-approval when an approved tool definition changes.",
            ("schema-hash", "reapproval"),
        ),
        predicate=lambda data: (
            (data.approved_schema_hash is not None
             and data.schema_hash != data.approved_schema_hash)
            or (data.live_mode and data.approved_tool
                and data.live_approved_schema_hash is not None
                and data.schema_hash != data.live_approved_schema_hash)
        ),
        message="Tool schema hash changed after approval.",
    ),
    DecisionRule(
        rule=_rule(
            "M3_MISSING_SCHEMA_HASH",
            "Missing schema hash",
            "2-registration",
            "M3",
            Severity.WARNING,
            RuleAction.REVIEW,
            "A definition without a hash cannot be pinned.",
            ("schema-hash",),
        ),
        predicate=lambda data: not data.schema_hash,
        message="Tool registration has no schema hash for change detection.",
    ),
    DecisionRule(
        rule=_rule(
            "S2_UNAPPROVED_TOOL", "Unapproved live tool", "2-registration", "A",
            Severity.CRITICAL, RuleAction.BLOCK,
            "A live tool must occur in reviewed server configuration.",
            ("allow-list", "live-list"),
        ),
        predicate=lambda data: data.live_mode and not data.approved_tool,
        message="Tool is absent from the reviewed server configuration.",
    ),
    DecisionRule(
        rule=_rule(
            "M3_MISSING_APPROVED_HASH", "Missing approved live hash", "2-registration", "M3",
            Severity.WARNING, RuleAction.REVIEW,
            "Live tools require a reviewed schema hash.",
            ("schema-hash", "live-list"),
        ),
        predicate=lambda data: (
            data.live_mode and data.approved_tool
            and not data.live_approved_schema_hash
        ),
        message="Live tool has no approved schema hash.",
    ),
    DecisionRule(
        rule=_rule(
            "M3_DESCRIPTION_CHANGED", "Live description changed", "2-registration", "M3",
            Severity.WARNING, RuleAction.REVIEW,
            "A changed live tool description requires review.",
            ("definition", "reapproval"),
        ),
        predicate=lambda data: (
            data.live_mode and data.approved_tool
            and data.description != data.approved_description
        ),
        message="Live tool description differs from the reviewed definition.",
    ),
)


def evaluate_decision(
    data: DecisionInput,
    signals: list[Match] | None = None,
) -> tuple[Verdict, list[Match]]:
    """Run A decision rules; B signals (e.g. from scan_text) can only raise the verdict."""
    matches = [
        match
        for rule in OPA_DECISION_RULES
        if (match := rule.evaluate(data)) is not None
    ]
    signal_matches = list(signals or [])
    if any(match.rule.default_action != RuleAction.SIGNAL for match in signal_matches):
        raise ValueError("signals must contain only B signal matches")
    return verdict_from_matches(matches + signal_matches), matches
