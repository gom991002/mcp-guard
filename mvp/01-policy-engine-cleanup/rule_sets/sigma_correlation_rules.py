from __future__ import annotations

from datetime import timedelta

# One audit event model for the engine and the correlation rules.
from mcp_guard.audit import AuditEvent

from .common import Match, Rule, RuleAction, RuleFamily, Severity

# M1 extension (not in the drawings): correlation over the audit stream.
# These rules alert after the fact; they do not replace stage 2-4 decisions.
# Event types are the ones mcp_guard.audit.EVENT_TYPES defines and the
# gateway, L2 wrapper, and L4 hook emit.

REPEATED_BLOCKS_RULE = Rule(
    rule_id="M1_REPEATED_BLOCKED_SERVER",
    family=RuleFamily.SIGMA_CORRELATION,
    title="Repeated blocked server",
    stage="audit",
    marker="M1",
    severity=Severity.WARNING,
    default_action=RuleAction.REVIEW,
    description="Flags a server blocked several times in a short time window.",
    tags=("audit", "correlation"),
)

DEFINITION_CHANGED_SOON_AFTER_APPROVAL_RULE = Rule(
    rule_id="M1_DEFINITION_CHANGED_SOON_AFTER_APPROVAL",
    family=RuleFamily.SIGMA_CORRELATION,
    title="Definition changed soon after approval",
    stage="audit",
    marker="M1",
    severity=Severity.CRITICAL,
    default_action=RuleAction.REVIEW,
    description=(
        "Flags definition changes within 24 hours of approval. M3 itself requires "
        "re-approval for any change; this only marks a quick change as suspicious."
    ),
    tags=("audit", "related:M3", "reapproval"),
)

TAINTED_SESSION_EXTERNAL_CALL_RULE = Rule(
    rule_id="M1_TAINTED_SESSION_EXTERNAL_CALL",
    family=RuleFamily.SIGMA_CORRELATION,
    title="External call in a tainted session",
    stage="audit",
    marker="M1",
    severity=Severity.CRITICAL,
    default_action=RuleAction.REVIEW,
    description=(
        "Flags an external tool call after a contaminated response in the same "
        "mcp-guard session, on any server. M4 taint is per session, and attack "
        "③ usually crosses servers (e.g. a GitHub response leads to a mail send)."
    ),
    tags=("audit", "related:M4", "response-contamination", "exfiltration"),
)


def correlate_events(events: list[AuditEvent]) -> list[Match]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    matches: list[Match] = []
    matches.extend(_repeated_blocks(ordered))
    matches.extend(_definition_changed_soon_after_approval(ordered))
    matches.extend(_tainted_session_external_call(ordered))
    return matches


def _repeated_blocks(events: list[AuditEvent]) -> list[Match]:
    matches: list[Match] = []
    window = timedelta(minutes=5)
    reported: set[str] = set()
    for event in events:
        if event.verdict != "block" or event.server_name in reported:
            continue
        related = [
            other
            for other in events
            if other.server_name == event.server_name
            and other.verdict == "block"
            and timedelta(0) <= other.timestamp - event.timestamp <= window
        ]
        if len(related) >= 3:
            reported.add(event.server_name)
            matches.append(
                Match(
                    rule=REPEATED_BLOCKS_RULE,
                    message="Server was blocked at least 3 times within 5 minutes.",
                    metadata={"server_name": event.server_name},
                )
            )
    return matches


def _definition_changed_soon_after_approval(events: list[AuditEvent]) -> list[Match]:
    matches: list[Match] = []
    window = timedelta(hours=24)
    approvals = [event for event in events if event.event_type == "definition_approved"]
    changes = [event for event in events if event.event_type == "definition_changed"]
    for approval in approvals:
        for change in changes:
            if approval.server_name != change.server_name:
                continue
            if approval.tool_name != change.tool_name:
                continue
            if timedelta(0) <= change.timestamp - approval.timestamp <= window:
                matches.append(
                    Match(
                        rule=DEFINITION_CHANGED_SOON_AFTER_APPROVAL_RULE,
                        message="Tool definition changed within 24 hours of approval.",
                        metadata={
                            "server_name": change.server_name,
                            "tool_name": change.tool_name,
                        },
                    )
                )
    return matches


def _tainted_session_external_call(events: list[AuditEvent]) -> list[Match]:
    # No time window: taint lasts for the whole session (A-01 ③).
    matches: list[Match] = []
    tainted_at: dict[str, AuditEvent] = {}
    for event in events:
        if not event.session_id:
            continue
        if event.event_type == "response_contaminated":
            tainted_at.setdefault(event.session_id, event)
        elif event.event_type == "external_tool_call" and event.session_id in tainted_at:
            source = tainted_at[event.session_id]
            matches.append(
                Match(
                    rule=TAINTED_SESSION_EXTERNAL_CALL_RULE,
                    message="External call occurred in a session tainted by an earlier response.",
                    metadata={
                        "session_id": event.session_id,
                        "tainted_by": source.server_name,
                        "call_server": event.server_name,
                        "call_tool": event.tool_name,
                    },
                )
            )
    return matches
