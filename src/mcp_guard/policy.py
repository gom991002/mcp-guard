from __future__ import annotations

import re
from collections.abc import Iterable
from re import Pattern

from .confusables import confusable_match, lookalike_name, tool_name_violations
from . import structure_signals, text_rules
from .b_signals import TextScorer, inspect_text
from .description_llm import DescriptionReviewer, inspect_description
from .m5 import names_other_server_tool
from .models import (
    GuardDecision,
    InspectionFinding,
    RuleAction,
    Severity,
    ToolRegistration,
    Verdict,
)
from .registry import DEFAULT_REGISTRY, GuardRegistry


# D6-38: chosen on 755 real tool names (mvp/04-tools-list-relay/m2_names): 0.53% of benign
# tools held, 88% of generated impersonations caught (UTS #39 alone: 27%).
LOOKALIKE_OPTIONS = {"separators": True, "reorder": True, "edit": "any"}


def evaluate_registration(
    registration: ToolRegistration,
    registry: GuardRegistry = DEFAULT_REGISTRY,
    *, classifier: TextScorer | None = None, b_threshold: float = 0.5,
    catalog: Iterable[tuple[str, str]] | None = None,
    description_reviewer: DescriptionReviewer | None = None,
) -> GuardDecision:
    """``catalog``: approved (server, tool) pairs across servers; by default the
    registry's approved schema hashes. ``description_reviewer``: optional LLM
    check of the description (D6-44), a B signal."""
    findings: list[InspectionFinding] = []
    catalog = list(catalog) if catalog is not None else None  # read more than once

    if not registration.server_name.strip():
        findings.append(
            InspectionFinding(
                code="M2_EMPTY_SERVER_NAME",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="M2",
                stage="2-registration",
                message="MCP server name is empty; the tool cannot be bound to a server.",
            )
        )

    if not registration.tool_name.strip():
        findings.append(
            InspectionFinding(
                code="M2_EMPTY_TOOL_NAME",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="M2",
                stage="2-registration",
                message="Tool name is empty.",
            )
        )

    if not registration.namespace.strip():
        findings.append(
            InspectionFinding(
                code="M2_EMPTY_NAMESPACE",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="M2",
                stage="2-registration",
                message="Tool namespace is empty.",
            )
        )

    if _uses_unregistered_server(registration, registry):
        findings.append(
            InspectionFinding(
                code="S0_UNREGISTERED_SERVER",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="A",
                stage="0-entry",
                message="MCP server is not registered in mcp-guard policy.",
                metadata={"server_name": registration.server_name},
            )
        )

    if _uses_untrusted_source(registration, registry):
        findings.append(
            InspectionFinding(
                code="S0_UNTRUSTED_SOURCE",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="A",
                stage="0-entry",
                message="Tool registration source is not trusted.",
                evidence=registration.source,
            )
        )

    if _uses_protected_name_from_untrusted_namespace(registration, registry):
        findings.append(
            InspectionFinding(
                code="M2_PROTECTED_NAME_UNTRUSTED_NAMESPACE",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="M2",
                stage="2-registration",
                message="Protected tool name is registered from an untrusted namespace.",
                metadata={
                    "namespace": registration.namespace,
                    "tool_name": registration.tool_name,
                },
            )
        )

    lookalike_of = _confusable_protected_name(registration, registry)
    if lookalike_of:
        findings.append(
            InspectionFinding(
                code="M2_CONFUSABLE_PROTECTED_NAME",
                severity=Severity.CRITICAL,
                action=RuleAction.BLOCK,
                marker="M2",
                stage="2-registration",
                message="Tool name looks like a protected tool name but is not identical.",
                evidence=lookalike_of,
                metadata={
                    "namespace": registration.namespace,
                    "tool_name": registration.tool_name,
                },
            )
        )

    lookalike = _lookalike_of_other_tool(registration, registry, catalog) if not lookalike_of else None
    if lookalike:
        candidate, how, owner = lookalike
        findings.append(
            InspectionFinding(
                code="M2_LOOKALIKE_TOOL_NAME",
                severity=Severity.WARNING,
                action=RuleAction.REVIEW,
                marker="M2",
                stage="2-registration",
                message="Tool name looks like an approved tool of another server or a protected name.",
                evidence=candidate,
                metadata={"tool_name": registration.tool_name, "how": how, "owner": owner},
            )
        )

    named = _names_other_server_tool(registration, registry, catalog)
    if named:
        findings.append(
            InspectionFinding(
                code="M5_DESCRIPTION_NAMES_OTHER_SERVER_TOOL",
                severity=Severity.WARNING,
                action=RuleAction.REVIEW,
                marker="M5",
                stage="2-registration",
                message="Tool description names a tool of another server (D6-43: isolation per server).",
                evidence=named[1],
                metadata={"tool_name": registration.tool_name, "owner": named[0]},
            )
        )

    name_violations = (
        tool_name_violations(registration.tool_name)
        if registration.tool_name.strip()
        else ()
    )
    if name_violations:
        findings.append(
            InspectionFinding(
                code="M2_NONSTANDARD_TOOL_NAME",
                severity=Severity.WARNING,
                action=RuleAction.REVIEW,
                marker="M2",
                stage="2-registration",
                message="Tool name is outside the MCP tool name recommendation.",
                evidence=",".join(name_violations),
            )
        )

    # D6-39: built-in description rules (src/mcp_guard/text_rules.py) and the
    # operator's phrase list. Text a built-in rule already matched is not
    # reported again as an operator phrase: one signal per piece of text.
    builtin = text_rules.scan(registration.description, text_rules.DESCRIPTION_RULES)
    for hit in builtin:
        rule = next(r for r in text_rules.DESCRIPTION_RULES if r.rule_id == hit.rule_id)
        findings.append(
            InspectionFinding(
                code=hit.rule_id,
                severity=Severity.WARNING,
                action=RuleAction.SIGNAL,
                marker="B",
                stage="2-registration",
                message=f"Tool description: {rule.title.lower()}.",
                evidence=hit.evidence[:200],
                metadata={"field": "description"},
            )
        )
    # Structural signals: what the description tells the model to do with the
    # server's other tools (src/mcp_guard/structure_signals.py, mvp/11-b-classifier/b_text).
    for hit in structure_signals.description_signals(
            registration.description, registration.tool_name,
            _server_tools(registration.server_name, registry, catalog)):
        findings.append(
            InspectionFinding(
                code=hit.rule_id,
                severity=Severity.WARNING,
                action=RuleAction.SIGNAL,
                marker="B",
                stage="2-registration",
                message="Tool description directs how other tools are called.",
                evidence=hit.evidence[:200],
                metadata={"field": "description"},
            )
        )
    matched_phrase = _find_suspicious_phrase(registration.description, registry,
                                             skip=[(h.start, h.end) for h in builtin])
    if matched_phrase:
        findings.append(
            InspectionFinding(
                code="B_SUSPICIOUS_DESCRIPTION",
                severity=Severity.WARNING,
                action=RuleAction.SIGNAL,
                marker="B",
                stage="2-registration",
                message="Tool description contains suspicious text.",
                evidence=matched_phrase,
                metadata={"field": "description"},
            )
        )

    signal, b_score = inspect_text(registration.description, classifier,
                             stage="2-registration", threshold=b_threshold)
    if signal is not None:
        findings.append(signal)
    # Staged check (design discussion, 2026-11-04): the LLM, slow and with the
    # most false holds, sees only what the cheaper checks left open. A
    # description another B signal already raised goes to review anyway; with
    # a classifier and the reviewer's ``classifier_floor``, a score below the
    # floor is taken as clean. Without a floor every remaining description is asked.
    raised = any(f.marker == "B" and f.action == RuleAction.SIGNAL for f in findings)
    floor = getattr(description_reviewer, "classifier_floor", None)
    below_floor = floor is not None and b_score is not None and b_score < floor
    if description_reviewer is not None and not raised and not below_floor:
        llm_signal = inspect_description(registration.description, description_reviewer)
        if llm_signal is not None:
            findings.append(llm_signal)

    approved_hash = registry.approved_hash_for(
        registration.server_name,
        registration.tool_name,
    )
    if approved_hash is not None and registration.schema_hash != approved_hash:
        findings.append(
            InspectionFinding(
                code="M3_SCHEMA_HASH_CHANGED",
                severity=Severity.WARNING,
                action=RuleAction.REVIEW,
                marker="M3",
                stage="2-registration",
                message="Tool schema hash changed after approval.",
                metadata={
                    "approved_schema_hash": approved_hash,
                    "observed_schema_hash": registration.schema_hash or "",
                },
            )
        )

    if not registration.schema_hash:
        findings.append(
            InspectionFinding(
                code="M3_MISSING_SCHEMA_HASH",
                severity=Severity.WARNING,
                action=RuleAction.REVIEW,
                marker="M3",
                stage="2-registration",
                message="Tool registration has no schema hash for change detection.",
            )
        )

    verdict = _verdict_for(findings)
    b_scores = ({"field": "description", "score": b_score,
                 "threshold": b_threshold, "model_id": classifier.model_id,
                 "revision": classifier.revision},) if classifier is not None and registration.description else ()
    return GuardDecision(verdict=verdict, findings=tuple(findings), b_scores=b_scores)


def evaluate_live_registration(
    observed: ToolRegistration,
    approved: ToolRegistration | None,
    registry: GuardRegistry = DEFAULT_REGISTRY,
    *, classifier: TextScorer | None = None, b_threshold: float = 0.5,
    catalog: Iterable[tuple[str, str]] | None = None,
    description_reviewer: DescriptionReviewer | None = None,
) -> GuardDecision:
    """Check a fetched definition against the reviewed config and core rules."""
    base = evaluate_registration(observed, registry,
                                 classifier=classifier, b_threshold=b_threshold, catalog=catalog,
                                 description_reviewer=description_reviewer)
    findings = list(base.findings)
    if approved is None:
        findings.append(InspectionFinding(
            code="S2_UNAPPROVED_TOOL", severity=Severity.CRITICAL,
            action=RuleAction.BLOCK, marker="A", stage="2-registration",
            message="Tool is absent from the reviewed server configuration.",
        ))
    else:
        if not approved.schema_hash:
            findings.append(InspectionFinding(
                code="M3_MISSING_APPROVED_HASH", severity=Severity.WARNING,
                action=RuleAction.REVIEW, marker="M3", stage="2-registration",
                message="Live tool has no approved schema hash.",
            ))
        elif observed.schema_hash != approved.schema_hash and not any(
            finding.code == "M3_SCHEMA_HASH_CHANGED" for finding in findings
        ):
            findings.append(InspectionFinding(
                code="M3_SCHEMA_HASH_CHANGED", severity=Severity.WARNING,
                action=RuleAction.REVIEW, marker="M3", stage="2-registration",
                message="Live tool schema differs from the reviewed definition.",
            ))
        if observed.description != approved.description:
            findings.append(InspectionFinding(
                code="M3_DESCRIPTION_CHANGED", severity=Severity.WARNING,
                action=RuleAction.REVIEW, marker="M3", stage="2-registration",
                message="Live tool description differs from the reviewed definition.",
            ))
    return GuardDecision(verdict=_verdict_for(findings), findings=tuple(findings),
                         b_scores=base.b_scores)


def _uses_unregistered_server(
    registration: ToolRegistration,
    registry: GuardRegistry,
) -> bool:
    return registration.server_name not in registry.registered_servers


def _uses_untrusted_source(
    registration: ToolRegistration,
    registry: GuardRegistry,
) -> bool:
    return registration.source not in registry.trusted_sources


def _uses_protected_name_from_untrusted_namespace(
    registration: ToolRegistration,
    registry: GuardRegistry,
) -> bool:
    return (
        registration.tool_name in registry.protected_tool_names
        and registration.namespace not in registry.trusted_namespaces
    )


def _confusable_protected_name(
    registration: ToolRegistration,
    registry: GuardRegistry,
) -> str | None:
    # A lookalike of a protected name has no legitimate use, so the namespace
    # does not matter here (UTS #39 skeleton comparison).
    if registration.tool_name in registry.protected_tool_names:
        return None
    return confusable_match(registration.tool_name, registry.protected_tool_names)


def _server_tools(server_name: str, registry: GuardRegistry,
                  catalog: Iterable[tuple[str, str]] | None) -> list[str]:
    """The approved tools of this server: the names a description could direct."""
    pairs = set(catalog) if catalog is not None else {
        tuple(key.split(":", 1)) for key in registry.approved_schema_hashes if ":" in key}
    return sorted(tool for server, tool in pairs if server == server_name)


def _names_other_server_tool(registration: ToolRegistration, registry: GuardRegistry,
                             catalog: Iterable[tuple[str, str]] | None) -> tuple[str, str] | None:
    """A tool approved for its own server was reviewed; a later description change is M3's."""
    pairs = set(catalog) if catalog is not None else {
        tuple(key.split(":", 1)) for key in registry.approved_schema_hashes if ":" in key}
    if (registration.server_name, registration.tool_name) in pairs:
        return None
    return names_other_server_tool(registration.server_name, registration.description, pairs)


def _lookalike_of_other_tool(
    registration: ToolRegistration,
    registry: GuardRegistry,
    catalog: Iterable[tuple[str, str]] | None,
) -> tuple[str, str, str] | None:
    """(name, how, owner) of an approved tool of another server, or a protected
    name, that this tool name imitates (D6-38).

    A tool already approved for its own server was accepted by a person and is
    not compared again. Identical names are not lookalikes: servers may share
    a name and clients tell them apart by server (MCP 2026-07-28).
    """
    pairs = set(catalog) if catalog is not None else {
        tuple(key.split(":", 1)) for key in registry.approved_schema_hashes if ":" in key}
    if (registration.server_name, registration.tool_name) in pairs:
        return None
    owners: dict[str, str] = {name: "protected" for name in registry.protected_tool_names}
    for server, tool in sorted(pairs):
        if server != registration.server_name:
            owners.setdefault(tool, server)
    match = lookalike_name(registration.tool_name, owners, **LOOKALIKE_OPTIONS)
    if match is None:
        return None
    return match[0], match[1], owners[match[0]]


def _find_suspicious_phrase(
    description: str,
    registry: GuardRegistry,
    skip: list[tuple[int, int]] | None = None,
) -> str | None:
    """The first operator phrase found outside the ``skip`` spans."""
    for phrase in registry.suspicious_phrases:
        for match in _phrase_pattern(phrase).finditer(description):
            if not any(match.start() < end and start < match.end() for start, end in skip or ()):
                return phrase
    return None


def _phrase_pattern(phrase: str) -> Pattern[str]:
    tokens = re.findall(r"[A-Za-z0-9_.-]+", phrase.casefold())
    if not tokens:
        return re.compile(re.escape(phrase), re.IGNORECASE)
    separator = r"[\s_\-]+"
    pattern = separator.join(re.escape(token) for token in tokens)
    return re.compile(pattern, re.IGNORECASE)


def _verdict_for(findings: list[InspectionFinding]) -> Verdict:
    if any(finding.action == RuleAction.BLOCK for finding in findings):
        return Verdict.BLOCK
    if any(
        finding.action in {RuleAction.REVIEW, RuleAction.SIGNAL}
        for finding in findings
    ):
        return Verdict.REVIEW
    return Verdict.ALLOW

