from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import replace
from typing import Any

from mcp_guard.admission import ServerIdentity, Stage0Admission
from mcp_guard.b_signals import TextScorer, inspect_text
from mcp_guard.audit import (
    DEFINITION_CHANGE_CODES,
    AuditEvent,
    AuditFinding,
    audit_event,
    audit_event_for_decision,
    definition_change_details,
    digest,
)
from mcp_guard.m5 import is_external_send, sanitize_tool
from mcp_guard.m4_values import inspect_values
from mcp_guard.models import GuardDecision, Verdict
from mcp_guard.policy import evaluate_live_registration, evaluate_registration
from mcp_guard.reapproval import CHANGE_CODES, classify, description_digest, summary
from mcp_guard.registry import GuardRegistry
from mcp_guard.taint import SessionTaintStore
from mcp_guard.text_rules import RESPONSE_RULES, response_text, scan as scan_text
from rule_sets.waf_gateway_rules import GatewayRequest, inspect_gateway_request

from .jsonrpc import (
    GUARD_BLOCKED,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    error_response,
    load_single_request,
    success_response,
)
from .models import GatewayConfig, GatewayResponse, ToolCallClient, ToolDefinition, UpstreamServer
from .live_catalog import LiveToolCatalog
from .taint_exceptions import MAX_SHOWN_ARGUMENTS, ApprovalRequest, TaintExceptionStore, arguments_digest


class RemoteMcpGateway:
    def __init__(
        self,
        config: GatewayConfig,
        tool_call_client: ToolCallClient | None = None,
        admission: Stage0Admission | None = None,
        live_catalog: LiveToolCatalog | None = None,
        classifier: TextScorer | None = None,
        b_threshold: float = 0.5,
        description_reviewer: Any | None = None,
        reapproval: Any | None = None,
        review_url: str = "",
        taint: SessionTaintStore | None = None,
        exceptions: TaintExceptionStore | None = None,
        approval_url: str = "",
        new_session_url: str = "",
    ) -> None:
        self._config = config
        # M4 (stage 3-4): every upstream tool result taints its session, as on the
        # local path; a tainted session loses the tools that can send data out.
        self._taint = taint
        # 3-A4 (D6-49): a user's own exceptions to that block, each call approved
        # by the user on the gateway's approval page.
        self._exceptions = exceptions
        self._approval_url = approval_url
        # Where a signed-in user starts a new session (http_gateway/session_epochs.py).
        self._new_session_url = new_session_url
        # D6-45: re-approval records (gateway_mvp.reapproval_store) and the page
        # users review changes on, when the administrator allows it.
        self._reapproval = reapproval
        self._review_url = review_url
        self._description_reviewer = description_reviewer  # D6-44, a B signal
        self._tool_call_client = tool_call_client
        self._admission = admission
        self._live_catalog = live_catalog
        self._classifier = classifier
        self._b_threshold = b_threshold
        # (server, tool) -> last changed definition reported, so a pending change
        # is recorded once rather than on every tools/list.
        self._reported_changes: dict[tuple[str, str], tuple[str | None, str]] = {}
        # (server, tool) -> definition last recorded as allowed in a tool list.
        self._listed_allowed: dict[tuple[str, str], tuple[str | None, str]] = {}
        self._reported_lock = threading.Lock()

    def tools_list_changed(self, server_name: str) -> None:
        """Invalidate a live snapshot when an upstream change event arrives."""
        if self._live_catalog is not None:
            self._live_catalog.invalidate(server_name)

    def handle(self, request: GatewayRequest, session_id: str = "", user: str = "") -> GatewayResponse:
        edge_findings = inspect_gateway_request(
            request,
            allowed_origins=self._config.allowed_origins,
        )
        if edge_findings:
            return GatewayResponse(
                status_code=_status_for_edge_findings({m.rule.rule_id for m in edge_findings}),
                body=error_response(
                    None,
                    GUARD_BLOCKED,
                    "mcp-guard rejected the gateway request",
                    {"findings": [match.rule.rule_id for match in edge_findings]},
                ),
                edge_findings=tuple(match.rule.rule_id for match in edge_findings),
            )

        message, parse_error = load_single_request(request.body)
        if parse_error is not None:
            return GatewayResponse(status_code=400, body=parse_error)
        assert message is not None

        method = message["method"]
        if method == "tools/list":
            return self._tools_list(message, session_id, user)
        if method == "tools/call":
            return self._tools_call(message, session_id, user)
        return GatewayResponse(
            status_code=200,
            body=error_response(message.get("id"), METHOD_NOT_FOUND, "Method not found"),
        )

    def _tools_list(self, message: dict[str, Any], session_id: str, user: str = "") -> GatewayResponse:
        visible_tools: list[dict[str, Any]] = []
        held: list[str] = []
        visible: list[ToolDefinition] = []
        audit_events: list[AuditEvent] = []
        unavailable: list[str] = []
        context = {"session_id": session_id, "request_id": _request_id(message)}
        for upstream in self._config.upstreams:
            admission = self._admit(upstream)
            if admission.verdict != Verdict.ALLOW:
                audit_events.append(_admission_event(upstream, admission, context))
                continue
            started = time.monotonic()
            try:
                tools, cached = self._tools_for(upstream)
            except (OSError, ValueError, ConnectionError, TimeoutError) as error:
                unavailable.append(upstream.name)
                audit_events.append(_upstream_event(upstream, "tools/list", "error", context,
                                                    error=type(error).__name__,
                                                    ms=_elapsed_ms(started)))
                continue
            if self._live_catalog is not None and not cached:
                audit_events.append(_upstream_event(
                    upstream, "tools/list", "ok", context, ms=_elapsed_ms(started),
                    result=digest([tool.to_mcp_tool() for tool in tools])))
            for tool in tools:
                decision = self._decide_tool(upstream, tool, user)
                audit_events.extend(self._decision_events(
                    "registration_evaluated", upstream, tool, decision, context))
                if decision.verdict == Verdict.ALLOW:
                    visible.append(tool)
                elif self._note_held(upstream, tool, decision, user) is not None:
                    held.append(f"{upstream.name}:{tool.name}")

        # M5 (D6-43): if anything listed can send data out, the session is
        # sensitive and the model sees no text the servers wrote.
        registry = self._registry()
        senders = [t for t in visible
                   if is_external_send(t.server_name, t.name, t.input_schema, registry)[0]]
        tainted = self._tainted(session_id)
        withheld: list[ToolDefinition] = []
        if tainted is not None:  # M4: removed from the list, and blocked again at call time
            mine = self._exceptions.exceptions_for(user) if self._exceptions is not None else set()
            withheld = [t for t in senders if f"{t.server_name}:{t.name}" not in mine]
            visible = [t for t in visible if t not in withheld]
        restricted = [t for t in visible if registry.trust_tier(t.server_name) == "restricted"]
        for tool in visible:
            item = tool.to_mcp_tool()
            replace_text = senders or tool in restricted  # restricted servers: always (trust tier)
            visible_tools.append(sanitize_tool(item, registry.replacement_descriptions.get(
                f"{tool.server_name}:{tool.name}")) if replace_text else item)

        result: dict[str, Any] = {
            "resultType": "complete", "tools": visible_tools,
            "ttlMs": 0, "cacheScope": "private",
        }
        if unavailable:
            result["_meta"] = {"mcp_guard/unavailableUpstreams": unavailable}
        if withheld:
            result.setdefault("_meta", {})["mcp_guard/withheldInTaintedSession"] = sorted(
                f"{t.server_name}:{t.name}" for t in withheld)
        if held:  # D6-45: names only, never the server's text
            result.setdefault("_meta", {})["mcp_guard/pendingReview"] = sorted(held)
        if senders or restricted:  # the tools that made text be replaced: senders, restricted servers
            result.setdefault("_meta", {})["mcp_guard/descriptionsReplaced"] = sorted(
                {f"{t.server_name}:{t.name}" for t in [*senders, *restricted]})
        return GatewayResponse(
            status_code=200,
            body=success_response(message.get("id"), result),
            audit_events=tuple(audit_events),
        )

    def _tools_call(self, message: dict[str, Any], session_id: str, user: str = "") -> GatewayResponse:
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return GatewayResponse(
                status_code=200,
                body=error_response(message.get("id"), INVALID_PARAMS, "Tool name is required"),
            )
        if "arguments" in params and not isinstance(params["arguments"], dict):
            return GatewayResponse(status_code=200,
                body=error_response(message.get("id"), INVALID_PARAMS, "Tool arguments must be an object"))

        found = self._config.find_tool_owner(params["name"]) or self._approved_new_tool_owner(params["name"])
        if found is None:
            return GatewayResponse(
                status_code=200,
                body=error_response(message.get("id"), METHOD_NOT_FOUND, "Tool not found"),
            )
        upstream, _ = found
        context = {"session_id": session_id, "request_id": _request_id(message)}
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}

        admission = self._admit(upstream)
        if admission.verdict != Verdict.ALLOW:
            return GatewayResponse(
                status_code=200,
                body=error_response(
                    message.get("id"), GUARD_BLOCKED,
                    "mcp-guard did not approve this upstream",
                    {"decision": admission.to_dict()},
                ),
                audit_events=(_admission_event(upstream, admission, context),),
            )

        list_started = time.monotonic()
        try:
            tools, cached = self._tools_for(
                upstream,
                force=(params["name"] in self._config.registry.refresh_before_call_tools),
            )
        except (OSError, ValueError, ConnectionError, TimeoutError) as error:
            return GatewayResponse(
                status_code=200,
                body=error_response(message.get("id"), GUARD_BLOCKED,
                                    "mcp-guard could not verify upstream tools"),
                audit_events=(_upstream_event(upstream, "tools/list", "error", context,
                                              error=type(error).__name__,
                                              ms=_elapsed_ms(list_started)),),
            )
        list_events = [_upstream_event(
            upstream, "tools/list", "ok", context, ms=_elapsed_ms(list_started),
            result=digest([item.to_mcp_tool() for item in tools]))] \
            if self._live_catalog is not None and not cached else []
        tool = next((item for item in tools if item.name == params["name"]), None)
        if tool is None:
            return GatewayResponse(
                status_code=200,
                body=error_response(message.get("id"), GUARD_BLOCKED,
                                    "Tool is absent from the verified upstream list"),
                audit_events=tuple(list_events) + (audit_event(
                    "tool_call_checked", server_name=upstream.name, namespace=upstream.namespace,
                    tool_name=params["name"], verdict=Verdict.BLOCK.value,
                    details={"reason": "absent from the verified upstream list",
                             "arguments": digest(arguments)}, **context),),
            )
        decision = self._decide_tool(upstream, tool, user)
        audit_events = self._expired_approvals() + list_events + self._decision_events(
            "tool_call_checked", upstream, tool, decision, context,
            details={"arguments": digest(arguments)})
        if decision.verdict != Verdict.ALLOW:
            held = self._note_held(upstream, tool, decision, user)
            return GatewayResponse(
                status_code=200,
                body=error_response(
                    message.get("id"),
                    GUARD_BLOCKED,
                    self._held_message(tool.name, held) if held else "mcp-guard did not allow this tool call",
                    {"decision": decision.to_dict(),
                     **({"reapproval": {"waiting_for": self._waiting_for(held)}} if held else {})},
                ),
                audit_events=tuple(audit_events),
            )

        tainted = self._tainted(session_id)
        sends, why = is_external_send(upstream.name, tool.name, tool.input_schema, self._registry())
        value_findings = inspect_values(self._registry().m4_value_policy, upstream.name, tool.name, arguments)
        if value_findings:
            audit_events.append(audit_event(
                "value_policy_checked", server_name=upstream.name, namespace=upstream.namespace,
                tool_name=tool.name, verdict=Verdict.REVIEW.value,
                finding_codes=tuple(f.code for f in value_findings),
                findings=tuple(AuditFinding(f.code, f.marker, f.stage) for f in value_findings),
                details={"paths": [f.path for f in value_findings], "arguments": digest(arguments)}, **context))
            designated = self._exceptions is not None and f"{upstream.name}:{tool.name}" in self._exceptions.exceptions_for(user)
            if tainted is not None and sends and not designated:
                return GatewayResponse(status_code=200,
                    body=error_response(message.get("id"), GUARD_BLOCKED,
                        "mcp-guard: tainted session cannot send data out without a designated exception"),
                    audit_events=tuple(audit_events))
            if self._exceptions is None or not user or not session_id or not self._approval_url:
                return GatewayResponse(status_code=200,
                    body=error_response(message.get("id"), GUARD_BLOCKED,
                        "mcp-guard: destination requires user approval; signed-in approval is unavailable"),
                    audit_events=tuple(audit_events))
            waiting, events = self._exception_approval(message, upstream, tool, arguments, user,
                tainted.first_source if tainted else "M4 value policy", ", ".join(f.code for f in value_findings), context)
            audit_events.extend(events)
            if waiting is not None:
                return replace(waiting, audit_events=tuple(audit_events))
        if tainted is not None and sends and self._exceptions is not None \
                and f"{upstream.name}:{tool.name}" in self._exceptions.exceptions_for(user) and not value_findings:
            waiting, events = self._exception_approval(message, upstream, tool, arguments, user,
                                                       tainted.first_source, why, context)
            audit_events.extend(events)
            if waiting is not None:
                return replace(waiting, audit_events=tuple(audit_events))
        elif tainted is not None and sends and not value_findings:
            audit_events.append(audit_event(
                "external_tool_call", server_name=upstream.name, namespace=upstream.namespace,
                tool_name=tool.name, verdict=Verdict.BLOCK.value,
                details={"outcome": "deny", "tainted_by": tainted.first_source, "why": why,
                         "arguments": digest(arguments)}, **context))
            return GatewayResponse(
                status_code=200,
                body=error_response(message.get("id"), GUARD_BLOCKED,
                                    f"mcp-guard: session tainted by {tainted.first_source}; {tool.name} "
                                    "can send data out and is blocked in tainted sessions " + self._how_to_restart()),
                audit_events=tuple(audit_events),
            )

        started = time.monotonic()
        try:
            result = _call_upstream(
                self._tool_call_client, upstream, tool, params,
            )
        except (OSError, ValueError, ConnectionError, TimeoutError) as error:
            if self._live_catalog is not None:
                self._live_catalog.invalidate(upstream.name)
            audit_events.append(_upstream_event(
                upstream, "tools/call", "error", context, tool_name=tool.name,
                error=type(error).__name__, ms=_elapsed_ms(started)))
            return GatewayResponse(
                status_code=200,
                body=error_response(message.get("id"), GUARD_BLOCKED,
                                    "Upstream tool call failed; tool list must be refreshed"),
                audit_events=tuple(audit_events),
            )
        audit_events.append(_upstream_event(
            upstream, "tools/call", "error_result" if result.get("isError") else "ok", context,
            tool_name=tool.name, ms=_elapsed_ms(started), result=digest(result)))
        trusted_output = self._registry().trust_tier(upstream.name) == "trusted_output"
        if self._taint is not None and session_id and not trusted_output and self._taint.get(session_id) is None:
            self._taint.mark(session_id, f"{upstream.name}:{tool.name}")
            audit_events.append(audit_event(
                "response_contaminated", server_name=upstream.name, namespace=upstream.namespace,
                tool_name=tool.name, details={"source": f"{upstream.name}:{tool.name}"}, **context))
        hits = scan_text(response_text(result), RESPONSE_RULES)
        if hits:  # B: recorded, changes nothing (taint is already set by the result itself)
            audit_events.append(audit_event(
                "response_classified", server_name=upstream.name, namespace=upstream.namespace,
                tool_name=tool.name, finding_codes=tuple(h.rule_id for h in hits),
                findings=tuple(AuditFinding(h.rule_id, "B", "3-response") for h in hits),
                details={"flagged": True, "rule": "text_rules", "evidence": digest(hits[0].evidence)},
                **context))
        if self._classifier is not None:
            text = response_text(result)
            signal, score = inspect_text(text, self._classifier, stage="3-response",
                                         threshold=self._b_threshold)
            if text:
                audit_events.append(audit_event(
                    "response_classified", server_name=upstream.name,
                    namespace=upstream.namespace, tool_name=tool.name,
                    finding_codes=(signal.code,) if signal else (),
                    findings=(AuditFinding(signal.code, signal.marker, signal.stage),)
                    if signal else (),
                    details={"score": score, "threshold": self._b_threshold,
                             "flagged": signal is not None,
                             "model_id": self._classifier.model_id,
                             "revision": self._classifier.revision, "content": digest(text),
                             "error_type": signal.metadata.get("error_type", "") if signal else ""},
                    **context,
                ))
        return GatewayResponse(
            status_code=200,
            body=success_response(message.get("id"), result),
            audit_events=tuple(audit_events),
        )

    def _exception_approval(
        self, message: dict[str, Any], upstream: UpstreamServer, tool: ToolDefinition,
        arguments: dict[str, Any], user: str, tainted_by: str, why: str, context: dict[str, str],
    ) -> tuple[GatewayResponse | None, list[AuditEvent]]:
        """3-A4 for a user's exception: run once approved, otherwise ask (D6-49).

        Returns no response when an approval of this exact input was spent and
        the call may go on.
        """
        key = f"{upstream.name}:{tool.name}"
        where = {"server_name": upstream.name, "namespace": upstream.namespace, "tool_name": tool.name}
        value_policy = tainted_by == "M4 value policy"
        cause = f"M4 destination check: {why}" if value_policy else f"session tainted by {tainted_by}"
        base = {"tainted_by": "" if value_policy else tainted_by, "why": why,
                "arguments": digest(arguments)}
        approved = self._exceptions.use(user, context["session_id"], key, arguments_digest(arguments))
        if approved is not None:
            return None, [audit_event(
                "external_tool_call", verdict=Verdict.ALLOW.value, user=user, **where, **context,
                details={**base, "outcome": "approved", "approval": approval_ref(approved)})]

        def refuse(outcome: str, text: str) -> tuple[GatewayResponse, list[AuditEvent]]:
            body = error_response(message.get("id"), GUARD_BLOCKED,
                                  f"mcp-guard: {cause}; {text}")
            return GatewayResponse(status_code=200, body=body), [audit_event(
                "external_tool_call", verdict=Verdict.BLOCK.value, user=user, **where, **context,
                details={**base, "outcome": outcome})]

        if len(json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))) > MAX_SHOWN_ARGUMENTS:
            return refuse("too_large_to_show",
                          f"the input of {tool.name} is too long to show whole for approval, so it is "
                          "blocked in this session " + self._how_to_restart())
        try:
            request = self._exceptions.request(user, context["session_id"], context["request_id"], key,
                                               arguments, tainted_by)
        except OverflowError as error:
            return refuse("too_many_waiting", str(error))
        link = f"{self._approval_url}?request={request.request_id}"
        minutes = max(1, int(request.expires_at - self._exceptions.now()) // 60)
        body = error_response(
            message.get("id"), GUARD_BLOCKED,
            f"mcp-guard: {cause}; {tool.name} waits "
            f"for your approval of this exact input. Open {link} , check the input and approve, then ask "
            f"again with the same input within {minutes} minutes.",
            {"approval": {"url": link, "expires_at": int(request.expires_at)}})
        ref = approval_ref(request)
        return GatewayResponse(status_code=200, body=body), [
            audit_event("external_tool_call", verdict=Verdict.REVIEW.value, user=user, **where, **context,
                        details={**base, "outcome": "ask", "approval": ref}),
            audit_event("approval_requested", verdict=Verdict.REVIEW.value, user=user, **where,
                        session_id=context["session_id"], request_id=ref,
                        details={**base, "rpc_request_id": context["request_id"], "via": "approval_page"})]

    def _how_to_restart(self) -> str:
        if self._new_session_url:
            return f"(open a new chat, then press 'start a new session' at {self._new_session_url})"
        return "(start a new session)"

    def _expired_approvals(self) -> list[AuditEvent]:
        if self._exceptions is None:
            return []
        return [approval_expired_event(item) for item in self._exceptions.sweep()]

    def _decision_events(
        self, event_type: str, upstream: UpstreamServer, tool: ToolDefinition,
        decision: GuardDecision, context: dict[str, str], details: dict[str, Any] | None = None,
    ) -> list[AuditEvent]:
        """The decision event, plus a definition_changed event the first time M3 sees a change."""
        registration = tool.registration()
        event = audit_event_for_decision(registration, decision, event_type=event_type,
                                         details=details or {}, **context)
        events = [event]
        if event_type == "registration_evaluated" and decision.verdict == Verdict.ALLOW:
            # D6-20: an unchanged allowed entry is recorded once, not on every list.
            state = (registration.schema_hash, registration.description)
            with self._reported_lock:
                if self._listed_allowed.get((upstream.name, tool.name)) == state:
                    events = []
                self._listed_allowed[(upstream.name, tool.name)] = state
        elif event_type == "registration_evaluated":
            with self._reported_lock:
                self._listed_allowed.pop((upstream.name, tool.name), None)
        if not DEFINITION_CHANGE_CODES & set(event.finding_codes):
            return events
        key, observed = (upstream.name, tool.name), (registration.schema_hash, registration.description)
        with self._reported_lock:
            if self._reported_changes.get(key) == observed:
                return events
            self._reported_changes[key] = observed
        approved = upstream.find_tool(tool.name)
        events.append(audit_event_for_decision(
            registration, decision, event_type="definition_changed",
            details=definition_change_details(
                registration, approved.registration() if approved else None),
            **context))
        return events

    def _admit(self, upstream: UpstreamServer) -> GuardDecision:
        if self._admission is None:
            return GuardDecision(Verdict.ALLOW)
        return self._admission.check(
            ServerIdentity(
                upstream.name, upstream.namespace, upstream.transport,
                upstream.url, upstream.source,
            ),
            self._config.registry,
        )

    def _tools_for(
        self, upstream: UpstreamServer, *, force: bool = False,
    ) -> tuple[tuple[ToolDefinition, ...], bool]:
        if self._live_catalog is None:
            return upstream.tools, False
        snapshot, cached = self._live_catalog.get_with_source(upstream, force=force)
        return snapshot.tools, cached

    def _decide_tool(self, upstream: UpstreamServer, tool: ToolDefinition, user: str = "") -> GuardDecision:
        registry = self._registry()
        if self._live_catalog is None:
            return evaluate_registration(tool.registration(), registry,
                                         classifier=self._classifier, b_threshold=self._b_threshold,
                                         description_reviewer=self._description_reviewer)
        approved = upstream.find_tool(tool.name)
        decision = self._evaluate(tool, approved, registry)
        if self._reapproval is None or not _held_codes(decision, approved):
            return decision
        # D6-45: an administrator's re-approval, or (where allowed) the user's own
        # acceptance of a low-risk change, lifts only the change findings.
        key, text = f"{upstream.name}:{tool.name}", description_digest(tool.description)
        lifted = self._reapproval.admin_approved(key, tool.schema_hash, text)
        if not lifted and self._reapproval.user_accepted(user, key, tool.schema_hash, text):
            lifted = self._classify(tool, approved, decision)["user_acceptable"]
        if not lifted:
            return decision
        hashes = {**registry.approved_schema_hashes, key: tool.schema_hash or ""}
        return self._evaluate(tool, tool, replace(registry, approved_schema_hashes=hashes))

    def _evaluate(self, tool: ToolDefinition, approved: ToolDefinition | None,
                  registry: GuardRegistry) -> GuardDecision:
        return evaluate_live_registration(
            tool.registration(),
            approved.registration() if approved is not None else None,
            registry,
            classifier=self._classifier, b_threshold=self._b_threshold,
            description_reviewer=self._description_reviewer,
        )

    def _registry(self) -> GuardRegistry:
        """The reviewed policy plus the administrator's D6-42 marks from re-approvals."""
        registry = self._config.registry
        if self._reapproval is None:
            return registry
        marks = {k: v["external_send"] for k, v in self._reapproval.approvals().items() if "external_send" in v}
        if not marks:
            return registry
        return replace(registry,
                       external_send_tools=registry.external_send_tools | {k for k, v in marks.items() if v},
                       not_external_send_tools=registry.not_external_send_tools
                       | {k for k, v in marks.items() if not v})

    def _classify(self, tool: ToolDefinition, approved: ToolDefinition | None,
                  decision: GuardDecision) -> dict[str, Any]:
        return classify(tool.registration(), approved.registration() if approved else None, decision,
                        self._registry(), observed_schema=tool.input_schema,
                        approved_schema=approved.input_schema if approved else None)

    def _note_held(self, upstream: UpstreamServer, tool: ToolDefinition, decision: GuardDecision,
                   user: str) -> dict[str, Any] | None:
        """Record a definition held for re-approval; its classification, or None if not one."""
        approved = upstream.find_tool(tool.name)
        if self._reapproval is None or not _held_codes(decision, approved):
            return None
        classification = self._classify(tool, approved, decision)
        self._reapproval.record_pending(f"{upstream.name}:{tool.name}", {
            "server": upstream.name, "tool": tool.name, "schema_hash": tool.schema_hash,
            "description_sha256": description_digest(tool.description),
            "description": tool.description,  # published by the server, shown to the reviewer as data
            "input_schema": tool.input_schema,
            "finding_codes": sorted({f.code for f in decision.findings}),
            "classification": classification,
            "summary": summary(tool.registration(), approved.registration() if approved else None,
                               observed_schema=tool.input_schema,
                               approved_schema=approved.input_schema if approved else None),
        }, user=user)
        return classification

    def _waiting_for(self, held: dict[str, Any]) -> str:
        return "user" if held["user_acceptable"] and self._reapproval.allow_user else "administrator"

    def _held_message(self, name: str, held: dict[str, Any]) -> str:
        what = "changed since it was approved" if held["held_for_change"] else "is not approved yet"
        if self._waiting_for(held) == "user" and self._review_url:
            return f"mcp-guard is holding {name}: its definition {what}. Review it at {self._review_url}"
        return f"mcp-guard is holding {name}: its definition {what} and waits for the administrator."

    def _tainted(self, session_id: str) -> Any:
        if self._taint is None or not session_id:
            return None
        return self._taint.get(session_id)

    def _approved_new_tool_owner(self, name: str) -> tuple[UpstreamServer, ToolDefinition] | None:
        """A tool absent from the reviewed config that the administrator approved (D6-45)."""
        if self._reapproval is None:
            return None
        for key in sorted(self._reapproval.approvals()):
            server, _, tool = key.partition(":")
            upstream = next((u for u in self._config.upstreams if u.name == server), None)
            if upstream is not None and tool == name:
                return upstream, ToolDefinition(server, upstream.namespace, name, "", {}, None)
        return None


def approval_ref(request: ApprovalRequest) -> str:
    """The audit id of an approval request: never the link token itself."""
    return "approval:" + hashlib.sha256(request.request_id.encode("utf-8")).hexdigest()[:16]


def approval_expired_event(request: ApprovalRequest) -> AuditEvent:
    server, _, tool = request.key.partition(":")
    return audit_event(
        "approval_decided", verdict=Verdict.BLOCK.value, user=request.user, client="mcp-guard",
        session_id=request.session_id, request_id=approval_ref(request), server_name=server,
        tool_name=tool, details={"decision": "expired", "unused_approval": request.decided_at is not None,
                                 "arguments_sha256": request.arguments_sha256})


def approval_decided_event(request: ApprovalRequest) -> AuditEvent:
    """The user's answer on the approval page, with the seconds it took."""
    server, _, tool = request.key.partition(":")
    approved = request.status == "approved"
    return audit_event(
        "approval_decided", verdict=Verdict.ALLOW.value if approved else Verdict.BLOCK.value,
        user=request.user, session_id=request.session_id, request_id=approval_ref(request),
        server_name=server, tool_name=tool,
        details={"decision": "approved" if approved else "refused",
                 "seconds": round((request.decided_at or request.created_at) - request.created_at, 3),
                 "arguments_sha256": request.arguments_sha256})


def _held_codes(decision: GuardDecision, approved: ToolDefinition | None) -> bool:
    """Held because the definition changed (M3) or is new: what re-approval can lift."""
    codes = {f.code for f in decision.findings}
    return bool(codes & CHANGE_CODES) or (approved is None and "S2_UNAPPROVED_TOOL" in codes)


def _request_id(message: dict[str, Any]) -> str:
    return json.dumps(message["id"]) if "id" in message else ""


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def _admission_event(upstream: UpstreamServer, decision: GuardDecision,
                     context: dict[str, str]) -> AuditEvent:
    return audit_event("server_admission", decision, server_name=upstream.name,
                       namespace=upstream.namespace,
                       details={"url": upstream.url, "source": upstream.source}, **context)


def _upstream_event(upstream: UpstreamServer, operation: str, outcome: str,
                    context: dict[str, str], tool_name: str = "", **details: Any) -> AuditEvent:
    return audit_event("upstream_call", server_name=upstream.name, namespace=upstream.namespace,
                       tool_name=tool_name, details={"operation": operation, "outcome": outcome,
                                                     **details}, **context)


def _call_upstream(
    client: ToolCallClient | None,
    upstream: UpstreamServer,
    tool: ToolDefinition,
    params: dict[str, Any],
) -> dict[str, Any]:
    arguments = params.get("arguments")
    arguments = arguments if isinstance(arguments, dict) else {}
    if client is not None:
        return client.call_tool(upstream, tool, arguments)
    return _stub_upstream_call(tool, arguments)


def _stub_upstream_call(tool: ToolDefinition, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": f"mcp-guard passed {tool.name} to {tool.server_name}",
            }
        ],
        "_meta": {
            "mcp_guard": {
                "server_name": tool.server_name,
                "argument_keys": sorted(str(key) for key in arguments),
            }
        },
    }


def _status_for_edge_findings(rule_ids: set[str]) -> int:
    if "S0_GATEWAY_PATH_NOT_ALLOWED" in rule_ids:
        return 404
    if "S0_GATEWAY_METHOD_NOT_ALLOWED" in rule_ids:
        return 405
    if "S0_GATEWAY_UNSUPPORTED_MEDIA_TYPE" in rule_ids:
        return 415
    if "S0_GATEWAY_BODY_TOO_LARGE" in rule_ids:
        return 413
    if "S0_GATEWAY_ORIGIN_NOT_ALLOWED" in rule_ids:
        return 403
    return 400

