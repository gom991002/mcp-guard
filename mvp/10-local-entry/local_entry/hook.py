"""L4: Claude Code hook that re-judges MCP calls and guards built-in tools in tainted sessions.

PreToolUse
  * ``mcp__<server>__<tool>`` of a guarded server: deny tools that are not
    approved (second line behind the L2 wrapper).
  * Built-in tools that can send data out (default Bash, PowerShell, WebFetch)
    in a tainted session: deny (D6-07). Tools the user listed in advance under
    ``taint_exceptions`` get Claude Code's approval prompt instead, with the
    raw input in the reason (3-A4 for exceptions only).
  * Approved tools of guarded MCP servers that can send data out (D6-42: the
    administrator's mark, else the name or recorded inputs) are treated the
    same way in a tainted session: deny, or the approval prompt for a tool
    listed as ``mcp__<server>__<tool>`` under ``taint_exceptions``. A wrapper
    cannot tell which client session asks for its tool list, so the tool is
    removed at call time, not from the list.
PostToolUse
  * A result from a taint source (default every MCP tool, WebFetch, WebSearch)
    marks the session tainted (M4). Taint is never cleared in a session.

Servers the user connects directly are left to Claude Code's normal flow. If
the hook cannot load its configuration it denies MCP calls and guarded
built-in tools (fail closed).

M1 audit (manifest ``audit_log``): denials, tainted-session send attempts,
approval prompts, and taint marks are recorded. Claude Code tells no hook
what the user answered at a prompt, so an approval is recorded only when the
tool then runs (PostToolUse, inferred); a refusal leaves no trace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from mcp_guard.audit import AuditRecorder, audit_event, digest
from mcp_guard.m5 import is_external_send
from mcp_guard.m4_values import inspect_values
from mcp_guard.registry import GuardRegistry
from mcp_guard.taint import SessionTaintStore

from .approvals import LocalApprovals, approval_entry, load_approvals
from .manifest import GATEWAY_SERVER_NAME, GuardManifest

_MAX_RAW_INPUT = 4000


def decide(event: dict[str, Any], manifest: GuardManifest, approvals: LocalApprovals,
           taint: SessionTaintStore | None = None,
           registry: GuardRegistry | None = None) -> tuple[str, str] | None:
    """Return (decision, reason) for PreToolUse, or None for the normal flow."""
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str):
        return None
    if tool_name in manifest.guarded_builtins:
        taint_decision = _tainted_send(event, manifest, taint, tool_name)
        if taint_decision:
            return taint_decision
        value = _value_decision(event, registry, "claude-code", tool_name)
        if value:
            return value
        return None
    if not tool_name.startswith("mcp__"):
        return None
    server, separator, tool = tool_name[len("mcp__"):].partition("__")
    if not separator or not server or not tool:
        return "deny", f"mcp-guard: cannot parse MCP tool name {tool_name!r}"
    entry = manifest.servers.get(server)
    if server == GATEWAY_SERVER_NAME:
        # The gateway inspects its own tools, but it cannot see what this session read
        # locally: a session tainted here must not send out through the gateway either.
        if gateway_sends_data_out(tool, event.get("tool_input"), registry)[0]:
            taint_decision = _tainted_send(event, manifest, taint, tool_name)
            if taint_decision:
                return taint_decision
        return None  # the remote gateway applies M4 value policy and obtains approval
    if entry is None or not entry["guard"]:
        return None  # direct servers are the user's choice
    if "url" in entry:
        return "deny", f"mcp-guard: {server!r} must be reached through the mcp-guard gateway"
    if tool not in approvals.tool_names(server):
        return "deny", f"mcp-guard: {tool!r} is not an approved tool of guarded server {server!r}"
    if sends_data_out(server, tool, approvals, registry)[0]:
        taint_decision = _tainted_send(event, manifest, taint, tool_name)
        if taint_decision:
            return taint_decision
    return None  # the L2 wrapper applies M4 value policy and obtains approval


def _value_decision(event: dict[str, Any], registry: GuardRegistry | None,
                    server: str, tool: str) -> tuple[str, str] | None:
    arguments = event.get("tool_input")
    if not isinstance(arguments, dict):
        arguments = {}
    findings = inspect_values(registry.m4_value_policy if registry else None, server, tool, arguments)
    if not findings:
        return None
    raw = json.dumps(arguments, ensure_ascii=False)
    if len(raw) > _MAX_RAW_INPUT:
        return "deny", "mcp-guard: M4 value policy needs approval, but the input is too long to show whole"
    codes = ", ".join(sorted({f.code for f in findings}))
    return "ask", f"mcp-guard: M4 value policy ({codes}); check the destination and approve this exact input: {raw}"


def sends_data_out(server: str, tool: str, approvals: LocalApprovals,
                   registry: GuardRegistry | None = None) -> tuple[bool, str]:
    """D6-42 for an approved local MCP tool, from what its approval recorded."""
    entry = approval_entry(approvals, server, tool) or {}
    return is_external_send(server, tool, entry.get("input_schema"), registry or _NO_POLICY, approval=entry)


def gateway_sends_data_out(tool: str, tool_input: Any, registry: GuardRegistry | None = None) -> tuple[bool, str]:
    """D6-42 for a tool reached through the mcp-guard gateway, seen only by name and call input.

    The administrator marks it in the local policy as ``mcp-guard:<tool>``; an
    unmarked tool follows the gateway's hint rule on its name and input names.
    """
    keys = tool_input if isinstance(tool_input, dict) else {}
    schema = {"type": "object", "properties": {str(k): {} for k in keys}}
    return is_external_send(GATEWAY_SERVER_NAME, tool, schema, registry or _NO_POLICY)


def _tainted_send(event: dict[str, Any], manifest: GuardManifest, taint: SessionTaintStore | None,
                  tool_name: str) -> tuple[str, str] | None:
    """M4 in a tainted session: deny a tool that can send data out, or ask for a listed exception."""
    record = taint.get(str(event.get("session_id", ""))) if taint else None
    if record is None:
        return None
    raw = json.dumps(event.get("tool_input", {}), ensure_ascii=False)
    if len(raw) > _MAX_RAW_INPUT:
        raw = raw[:_MAX_RAW_INPUT] + f" … (+{len(raw) - _MAX_RAW_INPUT} chars)"
    source = f"session tainted by {record.first_source}"
    if tool_name in manifest.taint_exceptions:
        return "ask", f"mcp-guard: {source}; {tool_name} is an exception you allowed. Input: {raw}"
    return "deny", f"mcp-guard: {source}; {tool_name} is blocked in tainted sessions (start a new session)"


_NO_POLICY = GuardRegistry.from_dict({})


def record_result(event: dict[str, Any], manifest: GuardManifest, taint: SessionTaintStore,
                  audit: AuditRecorder | None = None, registry: GuardRegistry | None = None) -> None:
    """PostToolUse: mark the session tainted when a taint source returned content.

    A server the administrator gave the ``trusted_output`` trust tier does not taint.
    """
    audit = audit or AuditRecorder()
    tool_name = str(event.get("tool_name", ""))
    session_id = str(event.get("session_id", ""))
    context = _context(event)
    server = tool_name[len("mcp__"):].partition("__")[0] if tool_name.startswith("mcp__") else ""
    trusted_output = bool(server) and registry is not None and registry.trust_tier(server) == "trusted_output"
    if session_id and not trusted_output and any(re.fullmatch(p, tool_name) for p in manifest.taint_sources):
        if taint.get(session_id) is None:
            taint.mark(session_id, tool_name)
            audit.record(audit_event("response_contaminated", details={"source": tool_name},
                                     **context))
    ask = _ask_path(manifest, event)
    if ask is not None and ask.exists():  # the tool ran after an approval prompt
        requested = json.loads(ask.read_text(encoding="utf-8"))
        ask.unlink()
        audit.record(audit_event(
            "approval_decided", verdict="allow",
            details={"decision": "approved", "inferred_from": "tool ran (PostToolUse)",
                     "seconds": round(time.time() - float(requested["requested_at"]), 3)},
            **context))


def record_decision(event: dict[str, Any], manifest: GuardManifest, verdict: tuple[str, str],
                    taint: SessionTaintStore, audit: AuditRecorder, external: bool | None = None) -> None:
    """PreToolUse: record a denial, a tainted-session send attempt, or an approval prompt.

    ``external``: the verdict came from the tainted-session send rule (an MCP
    tool that sends data out); built-in guarded tools always do.
    """
    decision, reason = verdict
    tool_name = str(event.get("tool_name", ""))
    context = _context(event)
    arguments = digest(event.get("tool_input", {}))
    if tool_name not in manifest.guarded_builtins and not external and not reason.startswith("mcp-guard: M4 value policy"):
        audit.record(audit_event("tool_call_checked", verdict="block",
                                 details={"reason": reason, "arguments": arguments}, **context))
        return
    record = taint.get(str(event.get("session_id", "")))
    details = {"outcome": decision, "tainted_by": record.first_source if record else "",
               "arguments": arguments}
    audit.record(audit_event("external_tool_call",
                             verdict="block" if decision == "deny" else "review",
                             details=details, **context))
    if decision != "ask":
        return
    audit.record(audit_event("approval_requested", verdict="review", details=details, **context))
    ask = _ask_path(manifest, event)
    if ask is not None:
        ask.parent.mkdir(parents=True, exist_ok=True)
        ask.write_text(json.dumps({"requested_at": time.time(), "tool": tool_name}),
                       encoding="utf-8")


def _is_tainted_mcp_send(event: dict[str, Any], approvals: LocalApprovals, registry: GuardRegistry,
                         taint: SessionTaintStore) -> bool:
    tool_name = str(event.get("tool_name", ""))
    server, separator, tool = tool_name[len("mcp__"):].partition("__")
    if not (tool_name.startswith("mcp__") and separator and taint.get(str(event.get("session_id", "")))):
        return False
    if server == GATEWAY_SERVER_NAME:
        return gateway_sends_data_out(tool, event.get("tool_input"), registry)[0]
    return tool in approvals.tool_names(server) and sends_data_out(server, tool, approvals, registry)[0]


def _context(event: dict[str, Any]) -> dict[str, str]:
    tool_name = str(event.get("tool_name", ""))
    server, separator, tool = tool_name[len("mcp__"):].partition("__")
    names = ({"server_name": server, "tool_name": tool}
             if tool_name.startswith("mcp__") and separator else {"tool_name": tool_name})
    return {"session_id": str(event.get("session_id", "")),
            "request_id": str(event.get("tool_use_id", "")), **names}


def _ask_path(manifest: GuardManifest, event: dict[str, Any]) -> Path | None:
    """Where a pending approval prompt waits for its PostToolUse, keyed by tool_use_id."""
    tool_use_id = str(event.get("tool_use_id", ""))
    if not tool_use_id:
        return None
    key = f"{event.get('session_id', '')}|{tool_use_id}"
    return Path(manifest.state_dir) / "asks" / f"{hashlib.sha256(key.encode()).hexdigest()[:32]}.json"


def main(argv: list[str] | None = None, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
    parser = argparse.ArgumentParser(description="mcp-guard L4 Claude Code hook")
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    try:
        event = json.load(stdin)
    except json.JSONDecodeError:
        event = {}
    if not isinstance(event, dict):
        event = {}
    post = event.get("hook_event_name") == "PostToolUse"
    try:
        manifest = GuardManifest.from_path(args.manifest)
        taint = SessionTaintStore(manifest.state_dir)
        audit = manifest.audit_recorder(client="claude-code")
        if post:
            try:
                registry = GuardRegistry.from_path(manifest.policy)
            except (OSError, ValueError):
                registry = None  # taint as usual: a trust tier can only relax, so none applies
            record_result(event, manifest, taint, audit, registry)
            return 0
        approvals = load_approvals(manifest.approvals,
                                   manifest.user_approvals if manifest.allow_user_approval else None)
        registry = GuardRegistry.from_path(manifest.policy)
        verdict = decide(event, manifest, approvals, taint, registry)
    except (OSError, ValueError, KeyError) as error:
        tool = str(event.get("tool_name", ""))
        guarded = tool.startswith("mcp__") or tool in ("Bash", "PowerShell", "WebFetch")
        verdict = ("deny", f"mcp-guard hook could not load its configuration: {error}") \
            if guarded and not post else None
    else:
        if verdict and audit.enabled:
            try:  # recording never changes the decision
                record_decision(event, manifest, verdict, taint, audit,
                                external=_is_tainted_mcp_send(event, approvals, registry, taint))
            except (OSError, ValueError) as error:
                print(f"mcp-guard: audit record failed ({error})", file=sys.stderr, flush=True)
    if verdict:
        decision, reason = verdict
        json.dump({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }}, stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
