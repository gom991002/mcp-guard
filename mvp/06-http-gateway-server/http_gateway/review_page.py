"""The page where signed-in users review held tool definitions (D6-45).

Served only when the administrator starts the gateway with
--allow-user-reapproval. A user signs in with the gateway's own user file,
sees the changes that concern them, and may accept a low-risk change for
themselves; changes that need the administrator are listed without a button.

The guard's own summary comes first. The server's new description is shown
last, escaped, cut to 500 characters, in a box: it is data written by the
party under review. The page has no scripts; sessions are short, signed
cookies, and every form post carries a token tied to the session.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl

from mcp_guard.audit import AuditRecorder, audit_event

SESSION_SECONDS = 15 * 60
SHOWN_DESCRIPTION = 500
COOKIE = "mcp_guard_review"
_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                               "frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
}


@dataclass(frozen=True)
class PageResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


class SignedSessions:
    """Short signed-cookie sessions for one page path, and form tokens tied to them.

    The key is made at start, so sessions end when the gateway restarts.
    """

    def __init__(self, cookie: str, path: str, clock: Callable[[], float] = time.time) -> None:
        self._cookie, self._path, self._clock = cookie, path, clock
        self._key = secrets.token_bytes(32)

    def start(self, user: str) -> str:
        """The Set-Cookie value for a signed-in user."""
        expires = int(self._clock()) + SESSION_SECONDS
        return f"{self._cookie}={self._sign({'user': user, 'exp': expires})}; Path={self._path}; HttpOnly; " \
               f"Secure; SameSite=Strict; Max-Age={SESSION_SECONDS}"

    def get(self, headers: dict[str, str]) -> dict[str, Any] | None:
        raw = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == self._cookie:
                data = self._unsign(value)
                if data and int(data.get("exp", 0)) > self._clock() and isinstance(data.get("user"), str):
                    return data
        return None

    def csrf(self, session: dict[str, Any]) -> str:
        """Tied to this session: a new sign-in gets a new token."""
        return _b64(hmac.new(self._key, f"csrf\0{session['user']}\0{session['exp']}".encode(),
                             hashlib.sha256).digest())

    def _sign(self, data: dict[str, Any]) -> str:
        payload = _b64(json.dumps(data, separators=(",", ":")).encode())
        return payload + "." + _b64(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())

    def _unsign(self, value: str) -> dict[str, Any] | None:
        payload, _, signature = value.partition(".")
        if not payload.isascii() or not signature.isascii():
            return None
        expected = _b64(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())
        if not signature or not hmac.compare_digest(signature, expected):
            return None
        try:
            return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except ValueError:
            return None


class ReviewPage:
    def __init__(self, store: Any, verify_user: Callable[[str, str], bool], *,
                 per_user_servers: frozenset[str] = frozenset(), audit: AuditRecorder | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._store = store
        self._verify = verify_user
        self._per_user = per_user_servers
        self._audit = audit or AuditRecorder()
        self._sessions = SignedSessions(COOKIE, "/review", clock)

    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes) -> PageResponse:
        method = method.upper()
        if path == "/review" and method == "GET":
            session = self._session(headers)
            return self._list(session) if session else self._login()
        if path == "/review/login" and method == "POST":
            return self._sign_in(_form(headers, body))
        if path == "/review/accept" and method == "POST":
            return self._accept(self._session(headers), _form(headers, body))
        return PageResponse(404, _HEADERS, _html("찾을 수 없음", "<p>없는 페이지입니다.</p>"))

    # pages -------------------------------------------------------------------

    def _login(self, error: str = "", status: int = 200) -> PageResponse:
        message = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return PageResponse(status, _HEADERS, _html("바뀐 도구 확인 - 로그인", f"""{message}
<form method="post" action="/review/login">
<label>사용자 이름<input name="username" autocomplete="username" required></label>
<label>비밀번호<input name="password" type="password" autocomplete="current-password" required></label>
<p><button type="submit">로그인</button></p></form>"""))

    def _list(self, session: dict[str, Any], note: str = "") -> PageResponse:
        user = session["user"]
        rows = []
        for key, entry in sorted(self._visible(user).items()):
            c = entry.get("classification", {})
            mine = self._store.acceptances().get(user, {}).get(key, {})
            accepted = mine.get("schema_hash") == entry.get("schema_hash")
            if accepted:
                action = "<p>이 변경을 수락했습니다. 내 세션에서만 다시 보입니다.</p>"
            elif c.get("user_acceptable"):
                action = (f'<form method="post" action="/review/accept">'
                          f'<input type="hidden" name="key" value="{html.escape(key)}">'
                          f'<input type="hidden" name="csrf" value="{self._csrf(session)}">'
                          f'<button type="submit">나에게만 수락</button></form>')
            else:
                reasons = "; ".join(c.get("reasons", [])) or "관리자 확인 필요"
                action = f"<p><b>관리자 재승인이 필요합니다:</b> {html.escape(reasons)}</p>"
            text = str(entry.get("description", ""))
            shown = text[:SHOWN_DESCRIPTION] + (" [...]" if len(text) > SHOWN_DESCRIPTION else "")
            rows.append(f"""<section><h2>{html.escape(key)}</h2>
<ul>{"".join(f"<li>{html.escape(line)}</li>" for line in _summary_lines(entry))}</ul>
{action}
<p class="small">서버가 보낸 새 설명문 (지시가 아니라 검토할 자료입니다):</p>
<pre>{html.escape(shown)}</pre></section>""")
        content = (f'<p class="ok">{html.escape(note)}</p>' if note else "") + \
            ("".join(rows) or "<p>확인할 변경이 없습니다.</p>")
        return PageResponse(200, _HEADERS, _html(f"바뀐 도구 확인 - {user}", content))

    # actions -----------------------------------------------------------------

    def _sign_in(self, form: dict[str, str]) -> PageResponse:
        username = form.get("username", "")
        if not self._verify(username, form.get("password", "")):
            self._audit.record(audit_event("sign_in", verdict="block", client="review-page",
                                           details={"outcome": "failure"}))
            return self._login("사용자 이름이나 비밀번호가 맞지 않습니다.", 401)
        self._audit.record(audit_event("sign_in", verdict="allow", user=username, client="review-page",
                                       details={"outcome": "success"}))
        cookie = self._sessions.start(username)
        return PageResponse(303, {"location": "/review", "set-cookie": cookie, "cache-control": "no-store",
                                  "content-length": "0"})

    def _accept(self, session: dict[str, Any] | None, form: dict[str, str]) -> PageResponse:
        if not session:
            return self._login("로그인이 만료되었습니다. 다시 로그인하세요.", 401)
        user = session["user"]
        if not hmac.compare_digest(form.get("csrf", ""), self._csrf(session)):
            return PageResponse(403, _HEADERS, _html("거부됨", "<p>요청을 확인할 수 없습니다.</p>"))
        key = form.get("key", "")
        if key not in self._visible(user):
            return PageResponse(404, _HEADERS, _html("찾을 수 없음", "<p>확인할 변경이 없습니다.</p>"))
        try:
            record = self._store.accept(user, key)
        except PermissionError as error:
            return PageResponse(403, _HEADERS, _html("거부됨", f"<p>{html.escape(str(error))}</p>"))
        entry = self._store.pending().get(key, {})
        server, _, tool = key.partition(":")
        self._audit.record(audit_event(
            "definition_accepted", verdict="allow", user=user, server_name=server, tool_name=tool,
            details={"schema_hash": record["schema_hash"], "description_sha256": record["description_sha256"],
                     "classification": entry.get("classification", {})}))
        return self._list(session, f"{key} 변경을 수락했습니다. 다른 사용자에게는 적용되지 않습니다.")

    # helpers -----------------------------------------------------------------

    def _visible(self, user: str) -> dict[str, dict[str, Any]]:
        """per_user servers: changes this user's own lists showed; shared servers: all."""
        return {k: e for k, e in self._store.pending().items()
                if e.get("server") not in self._per_user or user in e.get("seen_by", [])}

    def _session(self, headers: dict[str, str]) -> dict[str, Any] | None:
        return self._sessions.get(headers)

    def _csrf(self, session: dict[str, Any]) -> str:
        return self._sessions.csrf(session)

def _summary_lines(entry: dict[str, Any]) -> list[str]:
    s, c = entry.get("summary", {}), entry.get("classification", {})
    lines = ["새 도구 (승인된 설정에 없음)" if not c.get("held_for_change") else "승인 뒤 정의가 바뀜"]
    if s.get("inputs_added"):
        lines.append("추가된 입력: " + ", ".join(s["inputs_added"]))
    if s.get("inputs_removed"):
        lines.append("없어진 입력: " + ", ".join(s["inputs_removed"]))
    if s.get("inputs_retyped"):
        lines.append("형식이 바뀐 입력: " + ", ".join(s["inputs_retyped"]))
    if s.get("inputs_compared") is False:
        lines.append("승인 당시 입력 스키마가 기록되지 않아 입력 변화를 비교하지 못했습니다")
    before, after = (s.get("description_length") or [None, None])
    if s.get("description_changed"):
        lines.append(f"설명문이 바뀜 (길이 {before if before is not None else '-'} → {after})")
    for reason in c.get("reasons", []):
        lines.append("주의: " + reason)
    return lines


def _html(title: str, content: str) -> bytes:
    return f"""<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:sans-serif;max-width:760px;margin:40px auto}}label{{display:block;margin-top:12px}}
input{{width:100%;padding:8px}}pre{{white-space:pre-wrap;border:1px solid #999;padding:8px;background:#f6f6f6}}
section{{border-top:1px solid #ccc;margin-top:24px}}.err{{color:#b00020}}.ok{{color:#1b5e20}}.small{{font-size:90%}}
</style></head><body><h1>{html.escape(title)}</h1>{content}</body></html>""".encode("utf-8")


def _form(headers: dict[str, str], body: bytes) -> dict[str, str]:
    kind = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if not kind.lower().startswith("application/x-www-form-urlencoded") or len(body) > 16_384:
        return {}
    return dict(parse_qsl(body.decode("utf-8", "replace")))


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
