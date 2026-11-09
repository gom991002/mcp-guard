from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from dataclasses import replace
from datetime import UTC, datetime
from math import ceil
from typing import Any

from gateway_mvp.gateway import RemoteMcpGateway
from gateway_mvp.live_catalog import LiveToolCatalog
from gateway_mvp.models import GatewayConfig, ToolCallClient
from injection_throttle import RequestRateThrottle
from mcp_guard.admission import Stage0Admission
from mcp_guard.b_signals import TextScorer
from mcp_guard.audit import AuditFinding, AuditRecorder, audit_event
from rule_sets.waf_gateway_rules import GatewayRequest

from .models import HttpRequest, HttpResponse


class HttpGatewayAdapter:
    def __init__(
        self,
        config: GatewayConfig,
        throttle: RequestRateThrottle | None = None,
        tool_call_client: ToolCallClient | None = None,
        admission: Stage0Admission | None = None,
        live_catalog: LiveToolCatalog | None = None,
        sleep_on_delay: bool = False,
        auth: Any | None = None,
        trusted_proxies: tuple[str, ...] = (),
        audit: AuditRecorder | None = None,
        classifier: TextScorer | None = None,
        b_threshold: float = 0.5,
        description_reviewer: Any | None = None,
        reapproval: Any | None = None,
        review_url: str = "",
        review_page: Any | None = None,
        taint: Any | None = None,
        exceptions: Any | None = None,
        approval_url: str = "",
        approval_page: Any | None = None,
        session_epochs: Any | None = None,
        new_session_url: str = "",
    ) -> None:
        """``auth`` is a cloud_entry AuthorizationServer (C2); None keeps /mcp open.

        ``trusted_proxies`` lists CIDRs of reverse proxies whose
        X-Forwarded-For header is believed when computing the client IP.
        ``audit`` receives the M1 events of every request.
        """
        self._gateway = RemoteMcpGateway(
            config, tool_call_client=tool_call_client, admission=admission,
            live_catalog=live_catalog, classifier=classifier, b_threshold=b_threshold,
            description_reviewer=description_reviewer,
            reapproval=reapproval, review_url=review_url, taint=taint,
            exceptions=exceptions, approval_url=approval_url, new_session_url=new_session_url,
        )
        self.reapproval = reapproval
        self._review_page = review_page  # D6-45, only with --allow-user-reapproval
        self._approval_page = approval_page  # D6-49 exceptions and the new-session button
        self._session_epochs = session_epochs  # a user's "start a new session" (session_epochs.py)
        self._config = config
        self._throttle = throttle
        self._sleep_on_delay = sleep_on_delay
        self._auth = auth
        self._trusted_proxies = tuple(ipaddress.ip_network(cidr) for cidr in trusted_proxies)
        self._audit = audit or AuditRecorder()

    def tools_list_changed(self, server_name: str) -> None:
        self._gateway.tools_list_changed(server_name)
        self._audit.record(audit_event("tools_list_changed", server_name=server_name))

    def tools_list_watch_gap(self, server_name: str) -> None:
        """A change subscription reconnected: drop the cached list, record no change."""
        self._gateway.tools_list_changed(server_name)

    def admit(self, request: HttpRequest,
              now: datetime | None = None) -> tuple[HttpRequest, Any, HttpResponse | None]:
        """Resolve the client IP and run the IP delay check, without sleeping.

        Returns the request with its client IP, the throttle decision, and a
        response when the request is answered here (preflight, ban). An async
        server awaits ``decision.delay_seconds`` itself and then calls
        ``handle(request, admitted=...)`` so no thread waits out the delay.
        """
        now = now or datetime.now(UTC)
        request = replace(request, client_ip=self._client_ip(request))
        if request.method.upper() == "OPTIONS":
            return request, None, self._preflight_response(request)
        decision = None
        if self._throttle is not None and request.client_ip:
            decision = self._throttle.check(request.client_ip, request.headers, now,
                                            signed_in=self._signed_in(request))
            if decision.rejected or decision.should_delay:
                self._audit.record(audit_event(
                    "rate_limited", verdict="block" if decision.rejected else "",
                    details={"outcome": "banned" if decision.rejected else "delayed",
                             "client_ip": request.client_ip, "reason": decision.reason,
                             "rule": decision.rule_name,
                             "delay_seconds": round(decision.delay_seconds, 3),
                             "retry_after_seconds": round(decision.retry_after_seconds, 3)}))
            if decision.rejected:
                return request, decision, _rejection(decision)
        return request, decision, None

    def _signed_in(self, request: HttpRequest) -> bool:
        """For the IP delay: an /mcp request with a valid gateway token (always true without C2 auth)."""
        if self._auth is None:
            return True
        return request.path.partition("?")[0] == "/mcp" and             self._auth.verify_bearer(_header(request.headers, "authorization")) is not None

    def handle(self, request: HttpRequest, now: datetime | None = None,
               admitted: tuple[HttpRequest, Any] | None = None) -> HttpResponse:
        """``admitted`` is the request and decision from ``admit``, already waited out."""
        if admitted is None:
            request, decision, answered = self.admit(request, now)
            if answered is not None:
                return answered
            delay_headers = self._delay_headers(decision)
        else:
            request, decision = admitted
            delay_headers = self._delay_headers(decision, sleep=False)
        path, _, query = request.path.partition("?")
        if self._review_page is not None and (path == "/review" or path.startswith("/review/")):
            page = self._review_page.handle(request.method, path, request.headers, request.body)
            return HttpResponse(page.status_code,
                                {**page.headers, **delay_headers, "content-length": str(len(page.body))},
                                page.body)
        if self._approval_page is not None and (path == "/approve" or path.startswith("/approve/")):
            page = self._approval_page.handle(request.method, path, query, request.headers, request.body)
            return HttpResponse(page.status_code,
                                {**page.headers, **delay_headers, "content-length": str(len(page.body))},
                                page.body)
        session_id = _session_id(request.headers)
        claims = None
        if self._auth is not None:
            oauth = self._auth.handle(request.method, path, query, request.headers, request.body)
            if oauth is None and path == "/mcp":
                authorization = _header(request.headers, "authorization")
                claims = self._auth.verify_bearer(authorization)
                if claims is None:
                    oauth = self._auth.challenge(invalid_token=bool(authorization))
                else:
                    # A caller-supplied header must not select another user's
                    # taint/correlation state after authentication.
                    session_id = self._remote_session(claims, request.body)
                    try:
                        missing = self._unlinked_upstreams(str(claims["sub"]), request.body)
                    except ValueError as error:  # the upstream token store failed: fail closed
                        self._audit.record(audit_event(
                            "credential_store_unavailable", verdict="block",
                            details={"error": str(error)}), **_who(claims))
                        return _unavailable(delay_headers)
                    if missing:
                        oauth = self._auth.step_up(missing)
            if oauth is not None:
                return HttpResponse(
                    status_code=oauth.status_code,
                    headers={**oauth.headers, **delay_headers,
                             "content-length": str(len(oauth.body))},
                    body=oauth.body,
                )
        gateway_request = GatewayRequest(
            method=request.method,
            path=path,
            content_type=_content_type(request.headers),
            body=request.body,
            headers=request.headers,
        )
        if claims is not None:
            with self._auth.user_context(str(claims["sub"])):
                response = self._gateway.handle(gateway_request, session_id=session_id,
                                                user=str(claims["sub"]))
        else:
            response = self._gateway.handle(gateway_request, session_id=session_id)
        who = _who(claims)
        if response.edge_findings:
            self._audit.record(audit_event(
                "gateway_edge_rejected", verdict="block", session_id=session_id,
                finding_codes=response.edge_findings,
                findings=tuple(AuditFinding(code, "A", "0-entry") for code in response.edge_findings),
                details={"status": response.status_code, "path": path,
                         "origin": _header(request.headers, "origin") or ""}), **who)
        self._audit.record_all(response.audit_events, **who)

        body = json.dumps(response.body, ensure_ascii=False).encode("utf-8")
        headers = {
            **response.headers,
            **delay_headers,
            "content-length": str(len(body)),
        }
        if response.edge_findings:
            headers["mcp-guard-edge-findings"] = ",".join(response.edge_findings)
        if response.audit_events:
            headers["mcp-guard-audit-events"] = str(len(response.audit_events))
        return HttpResponse(status_code=response.status_code, headers=headers, body=body)

    def _remote_session(self, claims: dict[str, Any], body: bytes) -> str:
        """The mcp-guard session of a signed-in request (D6-26).

        Sessions of different LLM clients are never merged. ChatGPT sends an
        anonymized conversation id (``_meta["openai/session"]``), so its
        sessions follow conversations. Claude and Gemini send none (Claude's
        documentation says so), so their session is the user within that client.
        """
        family = self._auth.client_family(claims.get("client_id"))
        conversation = _openai_session(body) if family == "chatgpt" else ""
        identity = [str(claims["sub"]), str(claims.get("client_id", ""))]
        epoch = self._session_epochs.epoch(str(claims["sub"])) if self._session_epochs is not None else 0
        if epoch:  # the user started a new session on the approval page
            identity.append(f"epoch:{epoch}")
        if conversation:
            digest = hashlib.sha256(json.dumps([*identity, conversation]).encode("utf-8")).hexdigest()[:24]
            return f"{family}:conversation:{digest}"
        digest = hashlib.sha256(json.dumps(identity).encode("utf-8")).hexdigest()[:24]
        return f"{family}:user:{digest}"

    def _unlinked_upstreams(self, subject: str, body: bytes) -> list[str]:
        """Per-user upstream servers this request needs but the user has not linked."""
        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return []
        if not isinstance(message, dict):
            return []
        if message.get("method") == "tools/list":
            return self._auth.missing_upstreams(subject)
        if message.get("method") == "tools/call":
            params = message.get("params")
            name = params.get("name") if isinstance(params, dict) else None
            owner = self._config.find_tool_owner(name) if isinstance(name, str) else None
            if owner is not None:
                return self._auth.missing_upstreams(subject, (owner[0].name,))
        return []

    def _client_ip(self, request: HttpRequest) -> str:
        """Socket address, or the nearest untrusted hop behind trusted proxies."""
        if not self._trusted_proxies or not _in_networks(request.client_ip, self._trusted_proxies):
            return request.client_ip
        forwarded = _header(request.headers, "x-forwarded-for") or ""
        for hop in reversed([part.strip() for part in forwarded.split(",") if part.strip()]):
            if not _in_networks(hop, self._trusted_proxies):
                try:
                    return str(ipaddress.ip_address(hop))
                except ValueError:
                    return request.client_ip
        return request.client_ip

    def _preflight_response(self, request: HttpRequest) -> HttpResponse:
        origin = _header(request.headers, "Origin")
        headers = {
            "allow": "OPTIONS, POST",
            "access-control-allow-methods": "POST, OPTIONS",
            "access-control-allow-headers": (
                "content-type, mcp-protocol-version, mcp-method, mcp-name, "
                "mcp-guard-session-id"
            ),
            "access-control-max-age": "600",
            "content-length": "0",
        }
        if origin in self._config.allowed_origins:
            headers["access-control-allow-origin"] = origin
        return HttpResponse(status_code=204, headers=headers)

    def _delay_headers(self, decision: Any, sleep: bool = True) -> dict[str, str]:
        if decision is None:
            return {}
        if not decision.should_delay:
            return {"mcp-guard-delay-seconds": "0"}
        if self._sleep_on_delay and sleep:
            time.sleep(decision.delay_seconds)
        return {
            "mcp-guard-delay-seconds": str(round(decision.delay_seconds, 3)),
            "retry-after": str(ceil(decision.delay_seconds)),
        }


def _rejection(decision: Any) -> HttpResponse:
    """429 Too Many Requests for a banned client, answered at once without sleeping."""
    body = json.dumps({"error": "rate_limited", "reason": decision.reason}).encode("utf-8")
    return HttpResponse(status_code=429, headers={
        "content-type": "application/json",
        "retry-after": str(ceil(decision.retry_after_seconds)),
        "mcp-guard-delay-seconds": "0",
        "content-length": str(len(body)),
    }, body=body)


def _openai_session(body: bytes) -> str:
    """ChatGPT's anonymized conversation id from the request ``_meta``, if any."""
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    params = message.get("params") if isinstance(message, dict) else None
    meta = params.get("_meta") if isinstance(params, dict) else None
    value = meta.get("openai/session") if isinstance(meta, dict) else None
    return value if isinstance(value, str) and 0 < len(value) <= 512 else ""


def _who(claims: dict[str, Any] | None) -> dict[str, str]:
    """Audit context of a signed-in request: gateway user and OAuth client."""
    if claims is None:
        return {}
    return {"user": str(claims.get("sub", "")), "client": str(claims.get("client_id", ""))}


def _unavailable(delay_headers: dict[str, str]) -> HttpResponse:
    """503 when per-user upstream credentials cannot be read; no upstream is called."""
    body = json.dumps({"error": "upstream_credentials_unavailable"}).encode("utf-8")
    return HttpResponse(status_code=503, headers={
        "content-type": "application/json",
        **delay_headers,
        "content-length": str(len(body)),
    }, body=body)


def _content_type(headers: dict[str, str]) -> str:
    return _header(headers, "content-type") or ""


def _session_id(headers: dict[str, str]) -> str:
    return _header(headers, "mcp-guard-session-id") or ""


def _in_networks(address: str, networks: tuple[Any, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in networks)


def _header(headers: dict[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None

