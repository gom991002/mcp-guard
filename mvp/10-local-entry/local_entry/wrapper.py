"""L2: fail-closed stdio wrapper that puts the inspection core in front of a local server.

The client launches this wrapper instead of the server. The wrapper loads the
core first and refuses to start the server if it cannot (fail closed). It then
relays newline-delimited JSON-RPC (MCP stdio binding) and intervenes in two
places only, so it works with both modern and initialize-era servers:

* responses to ``tools/list``: only tools the core allows reach the client;
* ``tools/call`` requests: calls to any tool not in the last allowed list are
  answered with an error and never reach the server.

``notifications/tools/list_changed`` clears the allowed list until the client
lists again, so a changed definition is re-inspected before use.

M5 (D6-43): the session is every server in the manifest. If any approved tool
of any of them, or any tool now listed, can send data out, the session is
sensitive for the rest of this run: tool, prompt and resource descriptions and
the server's instructions are replaced before they reach the client.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from mcp_guard.audit import (
    AuditFinding,
    DEFINITION_CHANGE_CODES,
    AuditRecorder,
    audit_event,
    audit_event_for_decision,
    definition_change_details,
    digest,
)
from mcp_guard.stage1 import Stage1Error, verify_stage1
from mcp_guard.models import Verdict
from mcp_guard.registry import GuardRegistry

from mcp_guard.reapproval import classify
from mcp_guard.text_rules import RESPONSE_RULES, response_text, scan as scan_text
from mcp_guard.m5 import (WITHHELD_INSTRUCTIONS, is_external_send, likely_external_send, sanitize_prompt,
                          sanitize_resource, sanitize_tool)
from mcp_guard.m4_values import inspect_values

from .approvals import LocalApprovals, approval_entry, inspect_tool, load_approvals, write_pending
from .manifest import local_decision_model, local_recorder
from .value_approvals import LocalValueApprovals

BLOCKED_CODE = -32602  # MCP "Unknown tool" protocol error


class StdioGuard:
    def __init__(
        self,
        server_name: str,
        namespace: str,
        registry: GuardRegistry,
        approvals: LocalApprovals,
        client_out: BinaryIO,
        log: Any = sys.stderr,
        pending_path: Path | None = None,
        audit: AuditRecorder | None = None,
        description_reviewer: Any | None = None,
        allow_user_approval: bool = False,
        value_approvals: LocalValueApprovals | None = None,
    ) -> None:
        self._server = server_name
        self._allow_user_approval = allow_user_approval
        self._held: dict[str, dict[str, Any]] = {}  # tool -> D6-45 classification of a held definition
        self._description_reviewer = description_reviewer  # D6-44, a B signal
        self._namespace = namespace
        self._registry = registry
        self._value_approvals = value_approvals
        self._approvals = approvals
        self._out = client_out
        self._log = log
        self._pending_path = pending_path
        self._audit = audit or AuditRecorder()
        self._lock = threading.Lock()
        self._list_requests: dict[str, tuple[bool, float]] = {}  # id -> (first page?, start)
        self._allowed: set[str] = set()
        self._calls: dict[str, tuple[str, float]] = {}  # request id -> (tool, start)
        self._reported_changes: dict[str, tuple[str | None, str]] = {}
        self._listed_allowed: dict[str, tuple[str | None, str]] = {}
        self._described: dict[str, str] = {}  # request id -> method whose text M5 may replace
        self._sensitive = any(
            is_external_send(server, tool["name"], None, registry, approval=tool)[0]
            for server, entry in approvals.servers.items() if isinstance(entry, dict)
            for tool in entry.get("tools", []) if isinstance(tool, dict) and isinstance(tool.get("name"), str))
        # Trust tier: a restricted server's text is always replaced, sensitive session or not.
        self._sensitive = self._sensitive or registry.trust_tier(self._server) == "restricted"

    # client -> server ----------------------------------------------------

    def from_client(self, line: bytes) -> bytes | None:
        """Return the line to forward to the server, or None if answered here."""
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._reply(None, -32700, "mcp-guard: message is not valid JSON")
            return None
        if not isinstance(message, dict):
            self._reply(None, -32600, "mcp-guard: JSON-RPC batches are not supported")
            return None
        method = message.get("method")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        if method in _DESCRIBED and "id" in message:
            with self._lock:
                self._described[_key(message["id"])] = method
        if method == "tools/list" and "id" in message:
            with self._lock:
                self._list_requests[_key(message["id"])] = (
                    "cursor" not in params, time.monotonic())
        elif method == "tools/call" and "id" in message:
            name = params.get("name")
            request_id = _key(message["id"])
            if "arguments" in params and not isinstance(params["arguments"], dict):
                self._reply(message["id"], BLOCKED_CODE,
                            "mcp-guard: tool arguments must be an object")
                return None
            with self._lock:
                allowed = isinstance(name, str) and name in self._allowed
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            value_findings = inspect_values(self._registry.m4_value_policy, self._server, name, arguments) if allowed else ()
            if value_findings:
                codes = [f.code for f in value_findings]
                self._audit.record(audit_event(
                    "value_policy_checked", server_name=self._server, namespace=self._namespace,
                    tool_name=name, request_id=request_id, verdict=Verdict.REVIEW.value,
                    finding_codes=tuple(codes),
                    findings=tuple(AuditFinding(f.code, f.marker, f.stage) for f in value_findings),
                    details={"paths": [f.path for f in value_findings], "arguments": digest(arguments)}))
                if self._value_approvals is None:
                    self._reply(message["id"], BLOCKED_CODE, "mcp-guard: M4 value approval is unavailable")
                    return None
                if not self._value_approvals.consume(self._server, name, arguments):
                    ident = self._value_approvals.request(self._server, name, arguments, codes)
                    self._audit.record(audit_event(
                        "approval_requested", server_name=self._server, namespace=self._namespace,
                        tool_name=name, request_id=ident, verdict=Verdict.REVIEW.value,
                        details={"reason": "M4 value policy", "arguments": digest(arguments)}))
                    self._reply(message["id"], BLOCKED_CODE,
                                f"mcp-guard: M4 destination approval required for {name}; request {ident}. "
                                "Run python -m local_entry.value_approve --manifest <manifest> list, "
                                "then approve <request_id> and retry the same input.")
                    return None
            if allowed:
                with self._lock:
                    self._calls[request_id] = (name, time.monotonic())
            details: dict[str, Any] = {"arguments": digest(arguments)}
            if not allowed:
                details["reason"] = "not in the inspected tool list"
            self._audit.record(audit_event(
                "tool_call_checked", server_name=self._server, namespace=self._namespace,
                tool_name=name if isinstance(name, str) else "", request_id=request_id,
                verdict=Verdict.ALLOW.value if allowed else Verdict.BLOCK.value, details=details))
            if not allowed:
                self._note(f"blocked tools/call {name!r}: not in the inspected tool list")
                with self._lock:
                    held = self._held.get(name) if isinstance(name, str) else None
                self._reply(message["id"], BLOCKED_CODE, _held_message(name, held, self._allow_user_approval)
                            if held else f"mcp-guard blocked the call: {name!r} is not an allowed tool")
                return None
        return line

    # server -> client ----------------------------------------------------

    def from_server(self, line: bytes) -> bytes | None:
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._note("dropped a non-JSON line from the server's stdout")
            return None
        if not isinstance(message, dict):
            self._note("dropped a non-object message from the server")
            return None
        if message.get("method") == "notifications/tools/list_changed":
            with self._lock:
                self._allowed.clear()
            self._audit.record(audit_event("tools_list_changed", server_name=self._server,
                                           namespace=self._namespace))
            return line
        # Only responses (an id and no method) can answer a tools/list request;
        # otherwise a server-sent request could consume the pending id.
        if "id" in message and "method" not in message:
            request_id = _key(message["id"])
            with self._lock:
                listing = self._list_requests.pop(request_id, None)
                call = self._calls.pop(request_id, None)
                described = self._described.pop(request_id, None)
            result = message.get("result")
            if described and isinstance(result, dict) and self._sensitive:
                message["result"] = _replace_text(described, result)
                return _encode(message)
            if call is not None:
                self._record_call_result(request_id, call, message)
            if listing is not None:
                body = result if "error" not in message else message["error"]
                outcome = ("error" if "error" in message else
                           "ok" if isinstance(result, dict) else "invalid_result")
                self._audit.record(audit_event(
                    "upstream_call", server_name=self._server, namespace=self._namespace,
                    request_id=request_id, details={
                        "operation": "tools/list",
                        "outcome": outcome,
                        "ms": round((time.monotonic() - listing[1]) * 1000),
                        "result": digest(body)}))
            if listing is not None and isinstance(result, dict):
                message["result"] = self._filter(result, listing[0], request_id)
                return _encode(message)
            if isinstance(result, dict) and "tools" in result:
                # A tool list nobody asked for (e.g. a duplicate response) is
                # never passed through unfiltered.
                self._note("dropped an unsolicited tool list")
                return None
        return line

    def _filter(self, result: dict[str, Any], first_page: bool, request_id: str = "") -> dict[str, Any]:
        tools = result.get("tools")
        kept: list[dict[str, Any]] = []
        pending = []
        notes: dict[str, dict[str, Any]] = {}
        try:
            for tool in tools if isinstance(tools, list) else []:
                observed, decision = inspect_tool(
                    self._server, self._namespace, tool, self._approvals, self._registry,
                    description_reviewer=self._description_reviewer,
                )
                self._record_decision(observed, decision, request_id)
                if decision.verdict == Verdict.ALLOW:
                    kept.append(tool)
                else:
                    pending.append(observed)
                    notes[observed.tool_name] = self._reapproval_note(observed, decision, tool)
                    codes = ",".join(f.code for f in decision.findings)
                    self._note(f"hid tool {observed.tool_name!r} ({decision.verdict.value}: {codes})")
        except Exception as error:  # fail closed: the core must answer
            self._note(f"core check failed, hiding all tools: {error}")
            self._audit.record(audit_event(
                "registration_evaluated", server_name=self._server, namespace=self._namespace,
                request_id=request_id, verdict=Verdict.BLOCK.value,
                details={"core_error": str(error), "hidden": "all tools"}))
            kept = []
        with self._lock:
            if first_page:
                self._allowed = {tool["name"] for tool in kept}
                self._held = {}
            else:
                self._allowed.update(tool["name"] for tool in kept)
            self._held.update({name: note["reapproval"] for name, note in notes.items()})
        if pending and self._pending_path:
            raw = {t.get("name"): t for t in tools if isinstance(t, dict)} if isinstance(tools, list) else {}
            hints = {p.tool_name: hint for p in pending
                     if (hint := likely_external_send(p.tool_name, raw.get(p.tool_name, {}).get("inputSchema")))}
            write_pending(self._pending_path, self._server, self._namespace, pending, self._approvals, hints,
                          notes)
        if not self._sensitive and any(
                is_external_send(self._server, str(t.get("name")), t.get("inputSchema"), self._registry,
                                 approval_entry(self._approvals, self._server, str(t.get("name"))))[0]
                for t in kept):
            self._sensitive = True
            self._note("session can send data out: replacing descriptions (M5)")
        if self._sensitive:
            kept = [sanitize_tool(t, self._replacement(str(t.get("name")))) for t in kept]
        return {**result, "tools": kept}

    def _reapproval_note(self, observed: Any, decision: Any, tool: dict[str, Any]) -> dict[str, Any]:
        """D6-45: who may approve this held definition, and its input schema for next time."""
        entry = approval_entry(self._approvals, self._server, observed.tool_name)
        approved = self._approvals.approved(self._server, self._namespace, observed.tool_name)
        schema = tool.get("inputSchema")
        return {"input_schema": schema,
                "reapproval": classify(observed, approved, decision, self._registry, observed_schema=schema,
                                       approved_schema=(entry or {}).get("input_schema"), approval=entry)}

    def _replacement(self, tool_name: str) -> str | None:
        entry = approval_entry(self._approvals, self._server, tool_name) or {}
        reviewed = entry.get("replacement")
        return reviewed if isinstance(reviewed, str) and reviewed else             self._registry.replacement_descriptions.get(f"{self._server}:{tool_name}")

    # audit -----------------------------------------------------------------

    def _record_decision(self, observed: Any, decision: Any, request_id: str) -> None:
        event = audit_event_for_decision(observed, decision, request_id=request_id)
        definition = (observed.schema_hash, observed.description)
        with self._lock:  # D6-20: an unchanged allowed entry is recorded once
            repeat = (decision.verdict == Verdict.ALLOW
                      and self._listed_allowed.get(observed.tool_name) == definition)
            if decision.verdict == Verdict.ALLOW:
                self._listed_allowed[observed.tool_name] = definition
            else:
                self._listed_allowed.pop(observed.tool_name, None)
        if not repeat:
            self._audit.record(event)
        if not DEFINITION_CHANGE_CODES & set(event.finding_codes):
            return
        with self._lock:
            if self._reported_changes.get(observed.tool_name) == definition:
                return  # a pending change is recorded once, not on every list
            self._reported_changes[observed.tool_name] = definition
        approved = self._approvals.approved(self._server, self._namespace, observed.tool_name)
        self._audit.record(audit_event_for_decision(
            observed, decision, event_type="definition_changed", request_id=request_id,
            details=definition_change_details(observed, approved)))

    def _record_call_result(self, request_id: str, call: tuple[str, float],
                            message: dict[str, Any]) -> None:
        tool, started = call
        result = message.get("result")
        if "error" in message:
            outcome, body = "error", message.get("error")
        else:
            outcome = "error_result" if isinstance(result, dict) and result.get("isError") else "ok"
            body = result
        self._audit.record(audit_event(
            "upstream_call", server_name=self._server, namespace=self._namespace, tool_name=tool,
            request_id=request_id,
            details={"operation": "tools/call", "outcome": outcome,
                     "ms": round((time.monotonic() - started) * 1000), "result": digest(body)}))
        hits = scan_text(response_text(result), RESPONSE_RULES)
        if hits:  # B (stage 3): recorded only; Claude Code's hook taints the session either way
            self._audit.record(audit_event(
                "response_classified", server_name=self._server, namespace=self._namespace, tool_name=tool,
                request_id=request_id, finding_codes=tuple(h.rule_id for h in hits),
                findings=tuple(AuditFinding(h.rule_id, "B", "3-response") for h in hits),
                details={"flagged": True, "rule": "text_rules", "evidence": digest(hits[0].evidence)}))

    # helpers ---------------------------------------------------------------

    def write_client(self, line: bytes) -> None:
        with self._lock:
            self._out.write(line.rstrip(b"\r\n") + b"\n")
            self._out.flush()

    def _reply(self, request_id: object, code: int, message: str) -> None:
        self.write_client(_encode({"jsonrpc": "2.0", "id": request_id,
                                   "error": {"code": code, "message": message}}))

    def _note(self, text: str) -> None:
        print(f"mcp-guard[{self._server}]: {text}", file=self._log, flush=True)


def _code_scan_hold(manifest: Any, server: str, entry: dict[str, Any]) -> tuple | None:
    """None if the server may start; else (verdict, codes, findings, details).

    A missing or stale report is an A decision (the required scan was not made
    over this code): block. Unaccepted findings are B signals: review, which
    holds the server until someone accepts them.
    """
    try:
        from . import code_scan
    except ImportError as error:  # fail closed: the scan was required
        code = "S1_CODE_SCAN_MISSING"
        return (Verdict.BLOCK.value, (code,), (AuditFinding(code, "A", "1-integration"),),
                {"reason": f"code scan rules unavailable: {error}"})
    report = code_scan.load_report(code_scan.report_path(manifest.code_scan["reports"], server))
    status, reason = code_scan.report_status(report, entry, manifest.code_scan.get("similarity_feed"))
    if status == "ok":
        return None
    if status in {"missing", "stale"}:
        code = "S1_CODE_SCAN_MISSING" if status == "missing" else "S1_CODE_SCAN_STALE"
        return (Verdict.BLOCK.value, (code,), (AuditFinding(code, "A", "1-integration"),),
                {"reason": reason})
    codes = code_scan.review_codes(report)
    return (Verdict.REVIEW.value, codes,
            tuple(AuditFinding(c, "B", "1-integration") for c in codes),
            {"reason": reason, "code_scan": code_scan.summary(report)})


def _description_reviewer(manifest: Any) -> Any | None:
    """The manifest's B description LLM check (D6-44), or None when it is off."""
    check = manifest.description_check
    if not check.get("enabled"):
        return None
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "11-b-classifier"))
    from b_classifier.description_llm_client import OpenAICompatibleReviewer

    return OpenAICompatibleReviewer(check["base_url"], check["model"], timeout=float(check["timeout"]),
                                    api_key_env=check["api_key_env"])


def child_environment() -> dict[str, str]:
    """The server's environment: ours, with Python bytecode writes turned off.

    A Python server would otherwise write ``__pycache__`` into its pinned
    install tree on the first run, and stage 1 would refuse the next start.
    Redirecting the cache elsewhere (PYTHONPYCACHEPREFIX) would keep the speed
    but load bytecode from outside the pinned tree, which nothing checks.
    """
    return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}


def wrapper_session(server_name: str) -> str:
    """Session of one wrapper process (D6-26).

    The client starts a stdio server process per session, and the wrapper is
    told nothing about the conversation, so one process is one session. The
    L4 hook records Claude Code's own session id for the same conversation.
    """
    return f"l2:{server_name}:{uuid.uuid4().hex[:16]}"


def _held_message(name: object, held: dict[str, Any], allow_user: bool) -> str:
    """No server text: the model reads this too (D6-45)."""
    what = "changed since it was approved" if held.get("held_for_change") else "is not approved yet"
    if held.get("user_acceptable") and allow_user:
        how = "you may review it with `pending` and accept it with `approve --as-user`"
    else:
        how = "an administrator must review it with `pending` and `approve`"
    return f"mcp-guard is holding {name!r}: its definition {what}; {how}"


_DESCRIBED = frozenset({"initialize", "prompts/list", "resources/list", "resources/templates/list"})


def _replace_text(method: str, result: dict[str, Any]) -> dict[str, Any]:
    """M5: the same result without text the server wrote (sensitive sessions)."""
    if method == "initialize":
        return {**result, "instructions": WITHHELD_INSTRUCTIONS} if "instructions" in result else result
    field = {"prompts/list": "prompts", "resources/list": "resources",
             "resources/templates/list": "resourceTemplates"}[method]
    clean = sanitize_prompt if method == "prompts/list" else sanitize_resource
    items = result.get(field)
    return {**result, field: [clean(i) for i in items if isinstance(i, dict)]} if isinstance(items, list) else result


def _key(request_id: object) -> str:
    return json.dumps(request_id)


def _encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _pump(source: BinaryIO, handle, sink) -> None:
    for raw in iter(source.readline, b""):
        if not raw.strip():
            continue
        forwarded = handle(raw.rstrip(b"\r\n"))
        if forwarded is not None:
            sink(forwarded)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mcp-guard L2 stdio wrapper")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--approvals", required=True, help="service (admin) approvals")
    parser.add_argument("--user-approvals", help="the user's own approvals, if the manifest allows")
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--record-pending", help="write unapproved definitions here for review")
    parser.add_argument("--manifest", required=True,
                        help="L1 manifest; require stage 1 before guarded local launch")
    parser.add_argument("--audit-log", help="append M1 audit events here (JSON Lines)")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the server command after --")
    audit = local_recorder(args.audit_log or "", model=local_decision_model({
        "policy": args.policy, "approvals": args.approvals, "user_approvals": args.user_approvals,
    }) if args.audit_log else None, session_id=wrapper_session(args.server_name))
    try:  # L2 fail-closed: no core, no server.
        registry = GuardRegistry.from_path(args.policy)
        approvals = load_approvals(args.approvals, args.user_approvals)
    except (OSError, ValueError) as error:
        print(f"mcp-guard: core unavailable ({error}); refusing to start {args.server_name}",
              file=sys.stderr, flush=True)
        audit.record(audit_event("server_admission", server_name=args.server_name,
                                 namespace=args.namespace, verdict=Verdict.BLOCK.value,
                                 details={"reason": f"L2 core unavailable: {error}"}))
        return 78
    try:
        from .manifest import GuardManifest

        manifest = GuardManifest.from_path(args.manifest)
        entry = manifest.servers.get(args.server_name)
        if (not isinstance(entry, dict) or entry.get("guard") is not True or
                entry.get("namespace") != args.namespace or
                entry.get("command") != command[0] or
                entry.get("args", []) != command[1:]):
            raise Stage1Error("S1_MANIFEST_MISMATCH", "Wrapper command differs from guarded manifest")
        evidence = verify_stage1(entry, b_scored_elsewhere=manifest.b_scored_elsewhere(),
                                 trusted_publishers=registry.trusted_registry_publishers)
    except (OSError, ValueError) as error:
        code = error.code if isinstance(error, Stage1Error) else "S1_MANIFEST_INVALID"
        marker = error.marker if isinstance(error, Stage1Error) else "A"
        # review (e.g. unaccepted dependency findings) also keeps the server stopped.
        verdict = getattr(error, "verdict", Verdict.BLOCK.value)
        print(f"mcp-guard: stage 1 {'holds' if verdict == 'review' else 'rejected'} "
              f"{args.server_name}: {error}", file=sys.stderr, flush=True)
        audit.record(audit_event(
            "integration_checked", server_name=args.server_name,
            namespace=args.namespace, verdict=verdict,
            finding_codes=(code,),
            findings=(AuditFinding(code, marker, "1-integration"),),
            details={"reason": str(error)}))
        return 78
    if manifest.code_scan.get("enabled") and (entry.get("stage1") or {}).get("provider") == "docker":
        # D6-34: image code is not scanned; Docker verifies the image signature.
        evidence = {**evidence, "code_scan": "not applicable (Docker image)"}
    elif manifest.code_scan.get("enabled"):
        held = _code_scan_hold(manifest, args.server_name, entry)
        if held is not None:
            verdict, codes, findings, details = held
            print(f"mcp-guard: stage 1 code scan holds {args.server_name}: {details['reason']}",
                  file=sys.stderr, flush=True)
            audit.record(audit_event(
                "integration_checked", server_name=args.server_name, namespace=args.namespace,
                verdict=verdict, finding_codes=codes, findings=findings,
                details={**evidence, **details}))
            return 78
        evidence = {**evidence, "code_scan": "accepted or clean"}
    if entry.get("sandbox"):  # OS isolation: run the verified files inside a locked-down container
        from .sandbox import describe, docker_command

        evidence = {**evidence, "sandbox": describe(entry["sandbox"])}
        launch = docker_command(entry["sandbox"])
    else:
        launch = [shutil.which(command[0]) or command[0], *command[1:]]
    audit.record(audit_event(
        "integration_checked", server_name=args.server_name,
        namespace=args.namespace, verdict=Verdict.ALLOW.value, details=evidence))
    try:
        child = subprocess.Popen(launch, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, env=child_environment())
    except OSError as error:
        print(f"mcp-guard: cannot start {args.server_name}: {error}", file=sys.stderr, flush=True)
        return 1
    guard = StdioGuard(args.server_name, args.namespace, registry, approvals, sys.stdout.buffer,
                       pending_path=Path(args.record_pending) if args.record_pending else None,
                       audit=audit, description_reviewer=_description_reviewer(manifest),
                       allow_user_approval=manifest.allow_user_approval,
                       value_approvals=LocalValueApprovals(manifest.state_dir))

    def to_child(line: bytes) -> None:
        child.stdin.write(line + b"\n")
        child.stdin.flush()

    def client_loop() -> None:
        try:
            _pump(sys.stdin.buffer, guard.from_client, to_child)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                child.stdin.close()  # stdio shutdown: close the server's input
            except OSError:
                pass

    threading.Thread(target=client_loop, daemon=True).start()
    try:
        _pump(child.stdout, guard.from_server, guard.write_client)
    except (BrokenPipeError, OSError):
        pass
    try:
        return child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.terminate()
        return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
