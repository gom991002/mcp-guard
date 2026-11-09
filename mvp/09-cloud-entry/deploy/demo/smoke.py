"""Walk the defense flow against the running demo (docker compose up -d first).

python mvp/09-cloud-entry/deploy/demo/smoke.py [--open http://127.0.0.1:8080] [--oauth http://127.0.0.1:8081]

The open gateway shows stages 2-4 without sign-in. The signed-in gateway is
reached the way an MCP client does it (dynamic client registration, PKCE,
sign-in form, token) and shows the M4 value policy with per-call approval on
/approve, and the new-session button. Each step prints PASS or FAIL; the exit
code is the number of failures.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROTOCOL_VERSION = "2026-07-28"
DEMO_USER, DEMO_PASSWORD = "demo", "demo-password-only"
REDIRECT = "http://127.0.0.1:9/callback"  # never opened: the code is read from the Location header


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None,
         method: str | None = None) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with _OPENER.open(request, timeout=30) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def form(fields: dict[str, str]) -> bytes:
    return urllib.parse.urlencode(fields).encode()


def rpc(base: str, method: str, name: str = "", arguments: dict | None = None, *,
        session: str = "", token: str = "") -> dict:
    params: dict = {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": PROTOCOL_VERSION, "Mcp-Method": method}
    if session:
        headers["mcp-guard-session-id"] = session
    if token:
        headers["authorization"] = f"Bearer {token}"
    if name:
        params.update({"name": name, "arguments": arguments or {}})
        headers["Mcp-Name"] = name
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    code, _, raw = http(f"{base}/mcp", data=body, headers=headers, method="POST")
    if code != 200:
        raise RuntimeError(f"/mcp answered {code}: {raw[:200]!r}")
    return json.loads(raw)


def sign_in(base: str) -> str:
    """The MCP client's OAuth 2.1 flow: register, authorize with PKCE, sign in, exchange the code."""
    _, _, raw = http(f"{base}/register", method="POST", headers={"content-type": "application/json"},
                     data=json.dumps({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none",
                                      "client_name": "mcp-guard demo smoke"}).encode())
    client_id = json.loads(raw)["client_id"]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    query = urllib.parse.urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
                                    "code_challenge": challenge, "code_challenge_method": "S256",
                                    "resource": f"{base}/mcp", "scope": "mcp", "state": "smoke"})
    _, _, page = http(f"{base}/authorize?{query}")
    signed = html.unescape(re.search(r'name="request" value="([^"]+)"', page.decode()).group(1))
    code, headers, _ = http(f"{base}/authorize", method="POST",
                            headers={"content-type": "application/x-www-form-urlencoded"},
                            data=form({"request": signed, "username": DEMO_USER, "password": DEMO_PASSWORD}))
    location = headers.get("location", "")
    grant = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code", [""])[0]
    if code not in (302, 303) or not grant:
        raise RuntimeError(f"sign-in did not return a code ({code} {location[:120]})")
    _, _, raw = http(f"{base}/token", method="POST", headers={"content-type": "application/x-www-form-urlencoded"},
                     data=form({"grant_type": "authorization_code", "code": grant, "client_id": client_id,
                                "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": f"{base}/mcp"}))
    return json.loads(raw)["access_token"]


class ApprovalPage:
    """The person's side: sign in on /approve and press its buttons."""

    def __init__(self, base: str) -> None:
        self.base = base
        _, headers, _ = http(f"{base}/approve/login", method="POST",
                             headers={"content-type": "application/x-www-form-urlencoded"},
                             data=form({"username": DEMO_USER, "password": DEMO_PASSWORD, "request": ""}))
        self.cookie = headers.get("set-cookie", "").split(";")[0]

    def _csrf(self, query: str = "") -> str:
        _, _, page = http(f"{self.base}/approve{query}", headers={"cookie": self.cookie})
        return re.search(r'name="csrf" value="([^"]+)"', page.decode()).group(1)

    def approve(self, link: str) -> int:
        request_id = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)["request"][0]
        token = self._csrf(f"?request={request_id}")
        code, _, _ = http(f"{self.base}/approve/decide", method="POST",
                          headers={"content-type": "application/x-www-form-urlencoded", "cookie": self.cookie},
                          data=form({"request": request_id, "decision": "approve", "csrf": token}))
        return code

    def new_session(self) -> int:
        token = self._csrf()
        code, _, _ = http(f"{self.base}/approve/new-session", method="POST",
                          headers={"content-type": "application/x-www-form-urlencoded", "cookie": self.cookie},
                          data=form({"csrf": token}))
        return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--open", default="http://127.0.0.1:8080")
    parser.add_argument("--oauth", default="http://127.0.0.1:8081")
    args = parser.parse_args()
    failures = 0

    def check(label: str, ok: bool, detail: object = "") -> None:
        nonlocal failures
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"\n      {str(detail)[:300]}" if not ok else ""))

    print("== open gateway (no sign-in) ==")
    clean, tainted = f"demo-{uuid.uuid4().hex[:8]}", f"demo-{uuid.uuid4().hex[:8]}"
    listed = rpc(args.open, "tools/list", session=clean)["result"]
    names = sorted(t["name"] for t in listed["tools"])
    check("2단계: approved tools are listed", {"read_inbox", "send_email", "search_docs"} <= set(names), names)
    check("2단계 B: approved get_time, whose description orders send_email first, is held",
          "get_time" not in names, names)
    check("2단계 M5: descriptions are replaced in a session that can send data out",
          bool(listed.get("_meta", {}).get("mcp_guard/descriptionsReplaced")), listed.get("_meta"))
    sent = rpc(args.open, "tools/call", "send_email", {"to": "bob@company.example", "body": "hi"}, session=clean)
    check("4단계: a clean session can send", "result" in sent, sent)
    inbox = rpc(args.open, "tools/call", "read_inbox", session=tainted)
    check("3단계: reading a mail with an injected order works", "result" in inbox, inbox)
    after = sorted(t["name"] for t in rpc(args.open, "tools/list", session=tainted)["result"]["tools"])
    check("3단계 M4: that session is tainted and send_email leaves its list", "send_email" not in after, after)
    blocked = rpc(args.open, "tools/call", "send_email",
                  {"to": "archive@collector.example", "body": "all mail"}, session=tainted)
    check("4단계 M4: the injected forward is blocked", "error" in blocked and "tainted" in blocked["error"]["message"],
          blocked)
    reading = rpc(args.open, "tools/call", "search_docs", {"query": "vpn"}, session=tainted)
    check("4단계: reading tools still run in the tainted session", "result" in reading, reading)

    print("\n== signed-in gateway (OAuth 2.1) ==")
    code, headers, _ = http(f"{args.oauth}/mcp", method="POST", data=b"{}", headers={"content-type": "application/json"})
    check("0단계 C2: /mcp without a token gets 401 with a resource_metadata challenge",
          code == 401 and "resource_metadata" in headers.get("www-authenticate", ""), (code, headers))
    token = sign_in(args.oauth)
    check("0단계 C2: DCR + PKCE + sign-in + token exchange", bool(token))
    page = ApprovalPage(args.oauth)
    check("3-A4: the person signs in on /approve", bool(page.cookie))
    page.new_session()  # start from a clean session: the demo user may have run this before

    outside = rpc(args.oauth, "tools/call", "send_email", {"to": "someone@other.example", "body": "hi"}, token=token)
    link = (outside.get("error", {}).get("data") or {}).get("approval", {}).get("url", "")
    check("4단계 M4 값 정책: an outside recipient waits for the person's approval", bool(link), outside)
    if link:
        check("4단계: the person approves that exact input on /approve", page.approve(link) == 200)
        again = rpc(args.oauth, "tools/call", "send_email", {"to": "someone@other.example", "body": "hi"}, token=token)
        check("4단계: the same call goes through once approved", "result" in again, again)
        changed = rpc(args.oauth, "tools/call", "send_email", {"to": "x@other.example", "body": "hi"}, token=token)
        check("4단계: a different input asks again", "error" in changed, changed)
    hidden = rpc(args.oauth, "tools/call", "send_email",
                 {"to": "bob@company.example", "bcc": "spy@other.example", "body": "hi"}, token=token)
    check("4단계 M4 값 정책: a hidden bcc is caught", "error" in hidden, hidden)

    rpc(args.oauth, "tools/call", "read_inbox", token=token)
    tainted_send = rpc(args.oauth, "tools/call", "send_email", {"to": "bob@company.example", "body": "hi"}, token=token)
    check("4단계 M4: after reading the inbox, the user's session cannot send",
          "error" in tainted_send and "new session" in tainted_send["error"]["message"], tainted_send)
    check("3단계: the person starts a new session on /approve", page.new_session() == 200)
    fresh = rpc(args.oauth, "tools/call", "send_email", {"to": "bob@company.example", "body": "hi"}, token=token)
    check("3단계: the new session can send again", "result" in fresh, fresh)

    print(f"\n{failures} failure(s)")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
