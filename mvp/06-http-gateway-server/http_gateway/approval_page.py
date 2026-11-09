"""The page where signed-in users approve their exception calls in tainted sessions (D6-49).

Served with --allow-taint-exceptions. A user signs in with the gateway's own
user file and sees two things: the calls waiting for their approval, each
with its input shown raw, and the exceptions they chose among the tools the
administrator allows. Only the user who made a call can answer it; the link a
tool error carries opens the page but approves nothing by itself.

The input is text an AI model wrote after reading third-party content, so it
is shown escaped, whole, in a box, with a reminder to check recipients and
addresses. The page has no scripts; every form post carries a token tied to
the session.
"""

from __future__ import annotations

import hmac
import html
import json
import re
import time
from typing import Any, Callable
from urllib.parse import quote

from gateway_mvp.gateway import approval_decided_event
from gateway_mvp.taint_exceptions import TaintExceptionStore

from .session_epochs import SessionEpochs
from mcp_guard.audit import AuditRecorder, audit_event

from .review_page import _HEADERS, PageResponse, SignedSessions, _form, _html

COOKIE = "mcp_guard_approve"
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class ApprovalPage:
    def __init__(self, store: TaintExceptionStore | None, verify_user: Callable[[str, str], bool], *,
                 audit: AuditRecorder | None = None, clock: Callable[[], float] = time.time,
                 epochs: SessionEpochs | None = None) -> None:
        """``store``: exceptions (D6-49), None when not enabled; ``epochs``: the new-session button."""
        self._store = store
        self._epochs = epochs
        self._verify = verify_user
        self._audit = audit or AuditRecorder()
        self._sessions = SignedSessions(COOKIE, "/approve", clock)

    def handle(self, method: str, path: str, query: str, headers: dict[str, str], body: bytes) -> PageResponse:
        method = method.upper()
        wanted = _wanted(query)
        if path == "/approve" and method == "GET":
            session = self._sessions.get(headers)
            return self._page(session, wanted) if session else self._login(wanted)
        if path == "/approve/login" and method == "POST":
            return self._sign_in(_form(headers, body))
        if path == "/approve/decide" and method == "POST":
            return self._decide(self._sessions.get(headers), _form(headers, body))
        if path == "/approve/exceptions" and method == "POST" and self._store is not None:
            return self._exceptions(self._sessions.get(headers), _form(headers, body))
        if path == "/approve/new-session" and method == "POST" and self._epochs is not None:
            return self._new_session(self._sessions.get(headers), _form(headers, body))
        return PageResponse(404, _HEADERS, _html("찾을 수 없음", "<p>없는 페이지입니다.</p>"))

    # pages -------------------------------------------------------------------

    def _login(self, wanted: str = "", error: str = "", status: int = 200) -> PageResponse:
        message = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return PageResponse(status, _HEADERS, _html("외부 전송 승인 - 로그인", f"""{message}
<form method="post" action="/approve/login">
<input type="hidden" name="request" value="{html.escape(wanted)}">
<label>사용자 이름<input name="username" autocomplete="username" required></label>
<label>비밀번호<input name="password" type="password" autocomplete="current-password" required></label>
<p><button type="submit">로그인</button></p></form>"""))

    def _page(self, session: dict[str, Any], wanted: str = "", note: str = "", status: int = 200) -> PageResponse:
        user, csrf = session["user"], self._sessions.csrf(session)
        content = (f'<p class="ok">{html.escape(note)}</p>' if note else "") + self._new_session_section(user, csrf)
        if self._store is not None:
            content += self._exception_sections(user, csrf, wanted)
        return PageResponse(status, _HEADERS, _html(f"외부 전송 승인 - {user}", content))

    def _new_session_section(self, user: str, csrf: str) -> str:
        if self._epochs is None:
            return ""
        last = self._epochs.last_reset(user)
        return f"""<h2>새 세션 시작</h2><p class="small">외부 내용(메일·웹·파일 등)을 읽은 세션에서는 데이터를
밖으로 보내는 도구가 막힙니다. Claude는 대화를 구분해 알려 주지 않아서, 막힌 상태는 새 대화를 열어도
그대로입니다. <b>대화창에서 새 대화를 먼저 연 다음</b> 아래 버튼을 누르세요. 외부 내용을 읽은 대화를 이어 쓰면
그 대화에 남은 지시 때문에 다시 위험해질 수 있습니다.</p>
<form method="post" action="/approve/new-session"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit">새 세션 시작</button></form>
<p class="small">마지막으로 새로 시작한 때: {html.escape(last) if last else "없음"}</p>"""

    def _exception_sections(self, user: str, csrf: str, wanted: str) -> str:
        assert self._store is not None
        requests = sorted(self._store.open_for(user), key=lambda r: r.request_id != wanted)
        rows = []
        for item in requests:
            shown = json.dumps(json.loads(item.arguments_json), ensure_ascii=False, indent=2)
            left = max(0, int(item.expires_at - self._store.now()))
            buttons = "".join(
                f'<form method="post" action="/approve/decide">'
                f'<input type="hidden" name="request" value="{html.escape(item.request_id)}">'
                f'<input type="hidden" name="decision" value="{value}">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button type="submit">{label}</button></form>'
                for value, label in (("approve", "이 입력 그대로 한 번 승인"), ("refuse", "거부")))
            rows.append(f"""<section><h2>{html.escape(item.key)}</h2>
<ul><li>승인 사유: {html.escape(item.tainted_by)}</li>
<li>남은 시간: {left // 60}분 {left % 60}초 (지나면 자동으로 거부됩니다)</li></ul>
<p class="small">아래 입력은 AI 모델이 만든 것입니다. 받는 사람, 주소, 본문이
의도한 것인지 확인하세요. 승인은 이 입력 그대로 한 번만 쓰입니다.</p>
<pre>{html.escape(shown)}</pre>{buttons}</section>""")
        allowed, mine = self._store.allowed(), self._store.designations().get(user, {})
        choices = []
        for key in sorted(allowed):
            on = key in mine
            choices.append(
                f'<li>{html.escape(key)} — {"예외로 지정함" if on else "지정 안 함"} '
                f'<form method="post" action="/approve/exceptions">'
                f'<input type="hidden" name="key" value="{html.escape(key)}">'
                f'<input type="hidden" name="action" value="{"remove" if on else "add"}">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button type="submit">{"지정 해제" if on else "예외로 지정"}</button></form></li>')
        return "<h2>승인 대기</h2>" + ("".join(rows) or "<p>승인을 기다리는 호출이 없습니다.</p>") + \
            """<h2>내 예외 도구</h2><p class="small">외부 내용이 들어온 세션에서는 데이터를 밖으로 보낼 수 있는
도구가 막힙니다. 여기서 지정한 도구만 호출마다 이 페이지에서 승인을 받고 쓸 수 있습니다.
예외가 많을수록 승인 요청이 늘어납니다. 지정은 내 세션에만 적용됩니다.</p>""" + \
            (f"<ul>{''.join(choices)}</ul>" if choices else "<p>관리자가 허용한 예외 도구가 없습니다.</p>")

    # actions -----------------------------------------------------------------

    def _sign_in(self, form: dict[str, str]) -> PageResponse:
        username, wanted = form.get("username", ""), _wanted("request=" + quote(form.get("request", "")))
        if not self._verify(username, form.get("password", "")):
            self._audit.record(audit_event("sign_in", verdict="block", client="approval-page",
                                           details={"outcome": "failure"}))
            return self._login(wanted, "사용자 이름이나 비밀번호가 맞지 않습니다.", 401)
        self._audit.record(audit_event("sign_in", verdict="allow", user=username, client="approval-page",
                                       details={"outcome": "success"}))
        location = "/approve" + (f"?request={wanted}" if wanted else "")
        return PageResponse(303, {"location": location, "set-cookie": self._sessions.start(username),
                                  "cache-control": "no-store", "content-length": "0"})

    def _new_session(self, session: dict[str, Any] | None, form: dict[str, str]) -> PageResponse:
        refused = self._check(session, form)
        if refused is not None:
            return refused
        assert session is not None and self._epochs is not None
        epoch = self._epochs.start_new(session["user"])
        self._audit.record(audit_event("session_reset", user=session["user"], client="approval-page",
                                       details={"epoch": epoch}))
        return self._page(session, note="새 세션을 시작했습니다. 새로 연 대화에서 계속하세요.")

    def _decide(self, session: dict[str, Any] | None, form: dict[str, str]) -> PageResponse:
        refused = self._check(session, form)
        if refused is not None:
            return refused
        assert session is not None
        if self._store is None:
            return self._page(session, note="예외 승인이 켜져 있지 않습니다.", status=404)
        approve = form.get("decision") == "approve"
        try:
            item = self._store.decide(session["user"], form.get("request", ""), approve)
        except KeyError:
            return self._page(session, note="승인할 요청을 찾을 수 없습니다.", status=404)
        except ValueError as error:
            return self._page(session, note=f"처리하지 못했습니다: {error}", status=409)
        self._audit.record(approval_decided_event(item), client="approval-page")
        note = (f"{item.key} 호출을 승인했습니다. 대화로 돌아가 같은 입력으로 다시 요청하세요."
                if approve else f"{item.key} 호출을 거부했습니다.")
        return self._page(session, note=note)

    def _exceptions(self, session: dict[str, Any] | None, form: dict[str, str]) -> PageResponse:
        refused = self._check(session, form)
        if refused is not None:
            return refused
        assert session is not None
        user, key, action = session["user"], form.get("key", ""), form.get("action")
        try:
            if action == "add":
                self._store.designate(user, key)
            elif action == "remove":
                self._store.remove(user, key)
            else:
                return self._page(session, note="알 수 없는 요청입니다.", status=400)
        except (KeyError, PermissionError) as error:
            return self._page(session, note=f"처리하지 못했습니다: {error}", status=403)
        server, _, tool = key.partition(":")
        self._audit.record(audit_event("taint_exception_changed", verdict="", user=user, client="approval-page",
                                       server_name=server, tool_name=tool,
                                       details={"action": action}))
        return self._page(session, note=f"{key}: {'예외로 지정했습니다' if action == 'add' else '지정을 해제했습니다'}.")

    def _check(self, session: dict[str, Any] | None, form: dict[str, str]) -> PageResponse | None:
        if not session:
            return self._login(error="로그인이 만료되었습니다. 다시 로그인하세요.", status=401)
        if not hmac.compare_digest(form.get("csrf", ""), self._sessions.csrf(session)):
            return PageResponse(403, _HEADERS, _html("거부됨", "<p>요청을 확인할 수 없습니다.</p>"))
        return None


def _wanted(query: str) -> str:
    """The request id a link points at, if it looks like one."""
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if name == "request" and _REQUEST_ID.fullmatch(value):
            return value
    return ""
