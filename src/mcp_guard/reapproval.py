"""M3 re-approval: what kind of change a held definition is (D6-45).

A tool whose approved definition changed is hidden until someone approves the
new one. By default that is the administrator. Where the administrator lets
users accept changes for themselves, only low-risk changes qualify; this
module decides which, with reasons, and summarises the change in the guard's
own words for the person deciding. It changes no verdict: an accepted change
lifts only the M3 change findings, never any other A or B finding.

Shared by the remote gateway and the local wrapper. Design: REAPPROVAL.md.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .m5 import is_external_send
from .models import GuardDecision, ToolRegistration
from .registry import GuardRegistry

CHANGE_CODES = frozenset({"M3_SCHEMA_HASH_CHANGED", "M3_DESCRIPTION_CHANGED"})


def description_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def classify(observed: ToolRegistration, approved: ToolRegistration | None, decision: GuardDecision,
             registry: GuardRegistry, *, observed_schema: Any = None, approved_schema: Any = None,
             approval: dict[str, Any] | None = None) -> dict[str, Any]:
    """{"held_for_change": bool, "user_acceptable": bool, "reasons": [...]}.

    ``held_for_change``: the definition differs from an approved one (M3).
    ``user_acceptable``: nothing but that change holds it, and the change does
    not add a way to send data out. A new tool is always the administrator's.
    """
    codes = {f.code for f in decision.findings}
    reasons = []
    if approved is None:
        reasons.append("new tool, not in the approved configuration")
    other = sorted(codes - CHANGE_CODES)
    if other:
        reasons.append("other findings: " + ", ".join(other))
    sends_now, why_now = is_external_send(observed.server_name, observed.tool_name, observed_schema,
                                          registry, approval)
    sent_before = False
    if approved is not None:
        sent_before, _ = is_external_send(approved.server_name, approved.tool_name, approved_schema,
                                          registry, approval)
    if sends_now and not sent_before:
        reasons.append(f"can now send data out ({why_now})")
    held = approved is not None and bool(codes & CHANGE_CODES)
    return {"held_for_change": held, "user_acceptable": held and not reasons, "reasons": reasons}


def summary(observed: ToolRegistration, approved: ToolRegistration | None, *,
            observed_schema: Any = None, approved_schema: Any = None) -> dict[str, Any]:
    """What changed, in the guard's words; the new description is quoted, never interpreted."""
    out: dict[str, Any] = {
        "schema_changed": approved is None or observed.schema_hash != approved.schema_hash,
        "description_changed": approved is None or observed.description != approved.description,
        "description_length": [len(approved.description) if approved else None, len(observed.description)],
    }
    new, old = _properties(observed_schema), _properties(approved_schema)
    if observed_schema is not None and approved_schema is not None:
        out["inputs_added"] = sorted(set(new) - set(old))
        out["inputs_removed"] = sorted(set(old) - set(new))
        out["inputs_retyped"] = sorted(k for k in set(new) & set(old) if _type(new[k]) != _type(old[k]))
    else:
        out["inputs"] = sorted(new) if observed_schema is not None else None
        out["inputs_compared"] = False  # the approved schema was not recorded
    return out


def _properties(schema: Any) -> dict[str, Any]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def _type(spec: Any) -> Any:
    return spec.get("type") if isinstance(spec, dict) else None
