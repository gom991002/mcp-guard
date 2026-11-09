"""Remote 3-A4: users' exceptions to the tainted-session send block and per-call approval (D6-49)."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp", "mvp/03-server-registration-config",
               "mvp/04-tools-list-relay",
               "mvp/05-indirect-injection-throttle", "mvp/06-http-gateway-server", "mvp/07-tools-call-upstream-relay",
               "mvp/08-decision-controls", "mvp/09-cloud-entry"):
    sys.path.insert(0, str(ROOT / folder))

from gateway_mvp.gateway import RemoteMcpGateway  # noqa: E402
from gateway_mvp.models import GatewayConfig, ToolDefinition, UpstreamServer  # noqa: E402
from gateway_mvp.taint_exceptions import (  # noqa: E402
    APPROVAL_SECONDS, MAX_OPEN_PER_USER, MAX_SHOWN_ARGUMENTS, TaintExceptionStore, arguments_digest,
)
from http_gateway.approval_page import ApprovalPage  # noqa: E402
from http_gateway.exceptions import main as exceptions_main  # noqa: E402
from http_gateway.state_storage import prepare_state_dir  # noqa: E402
from mcp_guard.approval_metrics import prompts  # noqa: E402
from mcp_guard.audit import AuditRecorder  # noqa: E402
from mcp_guard.definitions import schema_hash  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from mcp_guard.taint import SessionTaintStore  # noqa: E402
from rule_sets.waf_gateway_rules import GatewayRequest, PROTOCOL_VERSION  # noqa: E402

READ = {"type": "object", "properties": {"path": {"type": "string"}}}
SEND = {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}
MAIL = {"to": "boss@company.example", "body": "Weekly report"}


class _Sink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        self.now = [1000.0]
        self.store = TaintExceptionStore(Path(self._folder.name), clock=lambda: self.now[0])

    def tearDown(self):
        self._folder.cleanup()

    def test_users_choose_only_among_allowed_tools_and_disallowing_ends_them(self):
        with self.assertRaises(PermissionError):
            self.store.designate("alice", "mail:send_email")
        self.store.allow("mail:send_email", "admin")
        self.store.designate("alice", "mail:send_email")
        self.assertEqual(self.store.exceptions_for("alice"), {"mail:send_email"})
        self.assertEqual(self.store.exceptions_for("bob"), set())
        self.store.disallow("mail:send_email")
        self.assertEqual(self.store.exceptions_for("alice"), set())

    def test_an_approval_is_the_owners_once_for_that_exact_input(self):
        request = self.store.request("alice", "s-1", "1", "mail:send_email", MAIL, "mail:read_inbox")
        self.assertIs(self.store.request("alice", "s-1", "2", "mail:send_email", MAIL, "x"), request)
        with self.assertRaises(KeyError):
            self.store.decide("bob", request.request_id, True)
        self.store.decide("alice", request.request_id, True)
        with self.assertRaises(ValueError):
            self.store.decide("alice", request.request_id, True)
        other = arguments_digest({**MAIL, "to": "attacker@evil.example"})
        self.assertIsNone(self.store.use("alice", "s-1", "mail:send_email", other))
        self.assertIsNone(self.store.use("alice", "s-2", "mail:send_email", request.arguments_sha256))
        self.assertIsNotNone(self.store.use("alice", "s-1", "mail:send_email", request.arguments_sha256))
        self.assertIsNone(self.store.use("alice", "s-1", "mail:send_email", request.arguments_sha256))

    def test_requests_run_out_after_ten_minutes(self):
        waiting = self.store.request("alice", "s-1", "1", "mail:send_email", MAIL, "x")
        approved = self.store.request("alice", "s-1", "2", "mail:send_email", {"to": "a"}, "x")
        self.store.decide("alice", approved.request_id, True)
        self.now[0] += APPROVAL_SECONDS
        with self.assertRaises(ValueError):
            self.store.decide("alice", waiting.request_id, True)
        self.assertIsNone(self.store.use("alice", "s-1", "mail:send_email", approved.arguments_sha256))
        expired = self.store.sweep()
        self.assertEqual({(r.request_id, r.decided_at is not None) for r in expired},
                         {(waiting.request_id, False), (approved.request_id, True)})
        self.assertEqual(self.store.sweep(), [])

    def test_open_requests_per_user_are_capped(self):
        for n in range(MAX_OPEN_PER_USER):
            self.store.request("alice", "s-1", str(n), "mail:send_email", {"n": n}, "x")
        with self.assertRaises(OverflowError):
            self.store.request("alice", "s-1", "x", "mail:send_email", {"n": "x"}, "x")
        self.store.request("bob", "s-2", "1", "mail:send_email", {"n": 0}, "x")

    def test_pending_approval_and_one_use_decision_survive_restarts(self):
        folder = Path(self._folder.name)
        waiting = self.store.request("alice", "s-1", "1", "mail:send_email", MAIL, "mail:read_inbox")
        resumed = TaintExceptionStore(folder, clock=lambda: self.now[0])
        self.assertEqual(resumed.open_for("alice")[0].request_id, waiting.request_id)
        self.assertEqual(resumed.open_for("bob"), [])
        resumed.decide("alice", waiting.request_id, True)
        resumed = TaintExceptionStore(folder, clock=lambda: self.now[0])
        self.assertIsNone(resumed.use("bob", "s-1", "mail:send_email", waiting.arguments_sha256))
        self.assertIsNotNone(resumed.use("alice", "s-1", "mail:send_email", waiting.arguments_sha256))
        resumed = TaintExceptionStore(folder, clock=lambda: self.now[0])
        self.assertIsNone(resumed.use("alice", "s-1", "mail:send_email", waiting.arguments_sha256))

    def test_expired_approval_stays_expired_after_restart(self):
        folder = Path(self._folder.name)
        waiting = self.store.request("alice", "s-1", "1", "mail:send_email", MAIL, "x")
        self.now[0] += APPROVAL_SECONDS
        resumed = TaintExceptionStore(folder, clock=lambda: self.now[0])
        self.assertEqual(resumed.open_for("alice"), [])
        with self.assertRaises(ValueError):
            resumed.decide("alice", waiting.request_id, True)
        self.assertEqual([item.request_id for item in resumed.sweep()], [waiting.request_id])
        self.assertEqual(TaintExceptionStore(folder, clock=lambda: self.now[0]).sweep(), [])

    def test_failed_disk_write_does_not_grant_or_spend_approval(self):
        folder = Path(self._folder.name)
        waiting = self.store.request("alice", "s-1", "1", "mail:send_email", MAIL, "x")
        with patch.object(self.store, "_write", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                self.store.decide("alice", waiting.request_id, True)
        resumed = TaintExceptionStore(folder, clock=lambda: self.now[0])
        self.assertEqual(resumed.open_for("alice")[0].status, "pending")
        resumed.decide("alice", waiting.request_id, True)
        with patch.object(resumed, "_write", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                resumed.use("alice", "s-1", "mail:send_email", waiting.arguments_sha256)
        self.assertIsNotNone(TaintExceptionStore(folder, clock=lambda: self.now[0]).use(
            "alice", "s-1", "mail:send_email", waiting.arguments_sha256))

    def test_invalid_saved_request_fails_closed(self):
        folder = Path(self._folder.name)
        (folder / "approval-requests.json").write_text('{"requests":{"x":{"status":"approved"}}}',
                                                      encoding="utf-8")
        with self.assertRaises(ValueError):
            TaintExceptionStore(folder, clock=lambda: self.now[0])

    @unittest.skipUnless(os.name == "nt", "Windows ACL only")
    def test_restart_removes_inherited_access_from_approval_file(self):
        path = Path(self._folder.name) / "approval-requests.json"
        self.store.request("alice", "s-1", "1", "mail:send_email", MAIL, "x")
        subprocess.run(["icacls", str(path), "/inheritance:e"], check=True, capture_output=True)
        inherited = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True)
        self.assertIn("(I)", inherited.stdout)
        TaintExceptionStore(path.parent, clock=lambda: self.now[0])
        protected = subprocess.run(["icacls", str(path)], check=True, capture_output=True, text=True)
        self.assertNotIn("(I)", protected.stdout)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        folder = Path(self._folder.name)
        tools = (ToolDefinition("mail", "company", "read_inbox", "Reads mail.", READ, schema_hash(READ)),
                 ToolDefinition("mail", "company", "send_email", "Sends mail.", SEND, schema_hash(SEND)))
        registry = GuardRegistry.from_dict({
            "trusted_namespaces": ["company"], "registered_servers": ["mail"], "trusted_sources": ["gateway"],
            "approved_schema_hashes": {f"mail:{t.name}": t.schema_hash for t in tools}})
        self.now = [1000.0]
        self.store = TaintExceptionStore(folder, clock=lambda: self.now[0])
        self.store.allow("mail:send_email", "admin")
        self.store.designate("alice", "mail:send_email")
        self.calls = []
        outer = self

        class Calls:
            def call_tool(self, upstream, tool, arguments):
                outer.calls.append((tool.name, dict(arguments)))
                return {"content": [{"type": "text", "text": "done"}]}

        self.taint = SessionTaintStore(folder / "sessions")
        self.config = GatewayConfig(registry, (UpstreamServer("mail", "company", tools),))
        self.call_client = Calls()
        self.gateway = RemoteMcpGateway(self.config,
                                        tool_call_client=self.call_client, taint=self.taint, exceptions=self.store,
                                        approval_url="https://gw.example/approve")

    def tearDown(self):
        self._folder.cleanup()

    def _rpc(self, method, name="", arguments=None, user="alice", session="s-1"):
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}
        headers = {"MCP-Protocol-Version": PROTOCOL_VERSION, "Mcp-Method": method}
        if name:
            params.update({"name": name, "arguments": arguments or {}})
            headers["Mcp-Name"] = name
        return self.gateway.handle(GatewayRequest(method="POST", body=json.dumps({
            "jsonrpc": "2.0", "id": 7, "method": method, "params": params}).encode(),
            content_type="application/json", headers=headers), session_id=session, user=user)

    def _taint(self, user="alice", session="s-1"):
        self._rpc("tools/call", "read_inbox", user=user, session=session)
        self.calls.clear()

    def _approve_open(self, user="alice"):
        (request,) = self.store.open_for(user)
        self.store.decide(user, request.request_id, True)
        return request

    def test_the_exception_stays_listed_only_for_the_user_who_chose_it(self):
        self._taint()
        self._taint(user="bob", session="s-2")
        mine = self._rpc("tools/list").body["result"]
        self.assertEqual([t["name"] for t in mine["tools"]], ["read_inbox", "send_email"])
        self.assertNotIn("mcp_guard/withheldInTaintedSession", mine.get("_meta", {}))
        theirs = self._rpc("tools/list", user="bob", session="s-2").body["result"]
        self.assertEqual([t["name"] for t in theirs["tools"]], ["read_inbox"])
        self.assertIn("blocked in tainted sessions",
                      self._rpc("tools/call", "send_email", MAIL, user="bob", session="s-2").body["error"]["message"])

    def test_each_call_waits_for_the_users_approval_of_that_input(self):
        self._taint()
        asked = self._rpc("tools/call", "send_email", MAIL)
        error = asked.body["error"]
        self.assertIn("waits for your approval", error["message"])
        self.assertTrue(error["data"]["approval"]["url"].startswith("https://gw.example/approve?request="))
        self.assertNotIn("boss@company.example", error["message"])  # the input is shown on the page, not echoed
        self.assertEqual(self.calls, [])
        types = [e.event_type for e in asked.audit_events]
        self.assertIn("approval_requested", types)
        requested = next(e for e in asked.audit_events if e.event_type == "approval_requested")
        self.assertTrue(requested.request_id.startswith("approval:"))
        self.assertNotIn(error["data"]["approval"]["url"].split("=")[1], json.dumps(requested.to_dict()))

        self._approve_open()
        changed = self._rpc("tools/call", "send_email", {**MAIL, "to": "attacker@evil.example"})
        self.assertIn("waits for your approval", changed.body["error"]["message"])  # a new input asks anew
        self.assertEqual(self.calls, [])
        done = self._rpc("tools/call", "send_email", MAIL)
        self.assertIn("result", done.body)
        self.assertEqual(self.calls, [("send_email", MAIL)])
        allowed = [e for e in done.audit_events if e.event_type == "external_tool_call"]
        self.assertEqual((allowed[0].verdict, allowed[0].details["outcome"]), ("allow", "approved"))
        again = self._rpc("tools/call", "send_email", MAIL)
        self.assertIn("waits for your approval", again.body["error"]["message"])  # used once

    def test_gateway_restart_keeps_page_approval_and_spends_it_once(self):
        self._taint()
        asked = self._rpc("tools/call", "send_email", MAIL)
        request_id = asked.body["error"]["data"]["approval"]["url"].split("?request=", 1)[1]
        self.assertEqual(self.calls, [])

        self.store = TaintExceptionStore(Path(self._folder.name), clock=lambda: self.now[0])
        self.gateway = RemoteMcpGateway(self.config, tool_call_client=self.call_client,
                                        taint=SessionTaintStore(Path(self._folder.name) / "sessions"),
                                        exceptions=self.store, approval_url="https://gw.example/approve")
        page = ApprovalPage(self.store, lambda user, password: (user, password) == ("alice", "pw"),
                            clock=lambda: self.now[0])
        login = page.handle("POST", "/approve/login", "", {"content-type": "application/x-www-form-urlencoded"},
                            urlencode({"username": "alice", "password": "pw", "request": request_id}).encode())
        self.assertEqual(login.status_code, 303)
        cookie = login.headers["set-cookie"].split(";")[0]
        view = page.handle("GET", "/approve", f"request={request_id}", {"cookie": cookie}, b"")
        body = view.body.decode()
        self.assertIn("boss@company.example", body)
        token = body.split('name="csrf" value="')[1].split('"')[0]
        decision = page.handle("POST", "/approve/decide", "",
                               {"content-type": "application/x-www-form-urlencoded", "cookie": cookie},
                               urlencode({"request": request_id, "decision": "approve", "csrf": token}).encode())
        self.assertEqual(decision.status_code, 200)
        self.assertIn("result", self._rpc("tools/call", "send_email", MAIL).body)
        self.assertEqual(self.calls, [("send_email", MAIL)])

        self.store = TaintExceptionStore(Path(self._folder.name), clock=lambda: self.now[0])
        self.gateway = RemoteMcpGateway(self.config, tool_call_client=self.call_client,
                                        taint=SessionTaintStore(Path(self._folder.name) / "sessions"),
                                        exceptions=self.store, approval_url="https://gw.example/approve")
        again = self._rpc("tools/call", "send_email", MAIL)
        self.assertIn("waits for your approval", again.body["error"]["message"])
        self.assertEqual(self.calls, [("send_email", MAIL)])

    def test_an_approval_does_not_carry_to_another_session(self):
        self._taint()
        self._rpc("tools/call", "send_email", MAIL)
        self._approve_open()
        self._taint(session="s-9")
        self.assertIn("error", self._rpc("tools/call", "send_email", MAIL, session="s-9").body)
        self.assertEqual(self.calls, [])

    def test_inputs_too_long_to_show_whole_are_blocked(self):
        self._taint()
        long = {**MAIL, "body": "x" * MAX_SHOWN_ARGUMENTS}
        refused = self._rpc("tools/call", "send_email", long)
        self.assertIn("too long to show whole", refused.body["error"]["message"])
        self.assertEqual(self.store.open_for("alice"), [])
        event = next(e for e in refused.audit_events if e.event_type == "external_tool_call")
        self.assertEqual(event.details["outcome"], "too_large_to_show")

    def test_untainted_sessions_and_unchosen_tools_are_unchanged(self):
        self.assertIn("result", self._rpc("tools/call", "send_email", MAIL).body)  # not tainted: no approval
        self.store.remove("alice", "mail:send_email")
        self._taint()
        self.assertIn("blocked in tainted sessions",
                      self._rpc("tools/call", "send_email", MAIL).body["error"]["message"])

    def test_expiry_is_recorded_and_counted_apart_from_refusal(self):
        self._taint()
        first = self._rpc("tools/call", "send_email", MAIL)
        self.now[0] += APPROVAL_SECONDS
        later = self._rpc("tools/call", "read_inbox")
        expired = [e for e in later.audit_events if e.event_type == "approval_decided"]
        self.assertEqual((expired[0].verdict, expired[0].details["decision"], expired[0].user),
                         ("block", "expired", "alice"))
        records = prompts([*first.audit_events, *expired])
        self.assertEqual([r["outcome"] for r in records], ["expired"])


class PageTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        self.now = [1000.0]
        self.store = TaintExceptionStore(Path(self._folder.name), clock=lambda: self.now[0])
        self.store.allow("mail:send_email", "admin")
        self.store.allow("chat:post", "admin")
        self.store.designate("alice", "mail:send_email")
        self.request = self.store.request("alice", "s-1", "7", "mail:send_email",
                                          {"to": "<b>boss</b>@company.example", "body": "hi"}, "mail:read_inbox")
        self.sink = _Sink()
        self.page = ApprovalPage(self.store, lambda u, p: (u, p) in {("alice", "pw"), ("bob", "pw")},
                                 audit=AuditRecorder(self.sink), clock=lambda: self.now[0])

    def tearDown(self):
        self._folder.cleanup()

    def _post(self, path, form, cookie=""):
        headers = {"content-type": "application/x-www-form-urlencoded", **({"cookie": cookie} if cookie else {})}
        return self.page.handle("POST", path, "", headers, urlencode(form).encode())

    def _login(self, user="alice", request=""):
        response = self._post("/approve/login", {"username": user, "password": "pw", "request": request})
        self.assertEqual(response.status_code, 303)
        return response.headers["set-cookie"].split(";")[0], response.headers["location"]

    def _view(self, cookie):
        body = self.page.handle("GET", "/approve", f"request={self.request.request_id}",
                                {"cookie": cookie}, b"").body.decode()
        return body, body.split('name="csrf" value="')[1].split('"')[0]

    def test_the_link_alone_shows_a_sign_in_form(self):
        anonymous = self.page.handle("GET", "/approve", f"request={self.request.request_id}", {}, b"")
        body = anonymous.body.decode()
        self.assertIn('action="/approve/login"', body)
        self.assertNotIn("boss", body)
        self.assertEqual(anonymous.headers["x-frame-options"], "DENY")
        cookie, location = self._login(request=self.request.request_id)
        self.assertEqual(location, f"/approve?request={self.request.request_id}")
        self.assertIn("Path=/approve", self._post("/approve/login", {"username": "alice", "password": "pw"})
                      .headers["set-cookie"])

    def test_the_input_is_shown_whole_and_escaped(self):
        body, _ = self._view(self._login()[0])
        self.assertIn("&lt;b&gt;boss&lt;/b&gt;@company.example", body)
        self.assertNotIn("<b>boss</b>", body)
        self.assertIn("mail:read_inbox", body)

    def test_only_the_owner_answers_with_the_session_token(self):
        bob, _ = self._login("bob")
        bob_body, bob_token = self._view(bob)
        self.assertNotIn("company.example", bob_body)
        refused = self._post("/approve/decide", {"request": self.request.request_id, "decision": "approve",
                                                 "csrf": bob_token}, bob)
        self.assertEqual(refused.status_code, 404)
        alice, _ = self._login()
        _, token = self._view(alice)
        self.assertEqual(self._post("/approve/decide", {"request": self.request.request_id,
                                                        "decision": "approve", "csrf": "x"}, alice).status_code, 403)
        self.now[0] += 12
        done = self._post("/approve/decide", {"request": self.request.request_id, "decision": "approve",
                                              "csrf": token}, alice)
        self.assertEqual(done.status_code, 200)
        decided = [e for e in self.sink.events if e.event_type == "approval_decided"]
        self.assertEqual((decided[0].verdict, decided[0].details["seconds"], decided[0].client),
                         ("allow", 12.0, "approval-page"))
        self.assertIsNotNone(self.store.use("alice", "s-1", "mail:send_email", self.request.arguments_sha256))

    def test_refusal_is_recorded_and_spends_nothing(self):
        alice, _ = self._login()
        _, token = self._view(alice)
        self._post("/approve/decide", {"request": self.request.request_id, "decision": "refuse", "csrf": token},
                   alice)
        decided = [e for e in self.sink.events if e.event_type == "approval_decided"]
        self.assertEqual((decided[0].verdict, decided[0].details["decision"]), ("block", "refused"))
        self.assertIsNone(self.store.use("alice", "s-1", "mail:send_email", self.request.arguments_sha256))

    def test_users_choose_their_own_exceptions_on_the_page(self):
        alice, _ = self._login()
        _, token = self._view(alice)
        self._post("/approve/exceptions", {"key": "chat:post", "action": "add", "csrf": token}, alice)
        self.assertEqual(self.store.exceptions_for("alice"), {"mail:send_email", "chat:post"})
        refused = self._post("/approve/exceptions", {"key": "shell:run", "action": "add", "csrf": token}, alice)
        self.assertEqual(refused.status_code, 403)
        self.assertIn("taint_exception_changed", [e.event_type for e in self.sink.events])
        self.assertEqual(self.store.exceptions_for("bob"), set())


class NewSessionTests(unittest.TestCase):
    """Claude sends no conversation id: a signed-in user starts a new gateway session on the page."""

    def setUp(self):
        from http_gateway.session_epochs import SessionEpochs

        self._folder = tempfile.TemporaryDirectory()
        self.epochs = SessionEpochs(Path(self._folder.name))
        self.sink = _Sink()
        self.page = ApprovalPage(None, lambda u, p: (u, p) in {("alice", "pw"), ("bob", "pw")},
                                 audit=AuditRecorder(self.sink), epochs=self.epochs)

    def tearDown(self):
        self._folder.cleanup()

    def _post(self, path, form, cookie=""):
        headers = {"content-type": "application/x-www-form-urlencoded", **({"cookie": cookie} if cookie else {})}
        return self.page.handle("POST", path, "", headers, urlencode(form).encode())

    def _session_id(self, user):
        from http_gateway.adapter import HttpGatewayAdapter

        class Auth:
            def client_family(self, client_id):
                return "claude"

        adapter = HttpGatewayAdapter(GatewayConfig(GuardRegistry.from_dict({}), ()), auth=Auth(),
                                     session_epochs=self.epochs)
        return adapter._remote_session({"sub": user, "client_id": "https://claude.ai/oauth"}, b"{}")

    def test_the_button_gives_the_user_a_new_session_and_only_that_user(self):
        alice, bob = self._session_id("alice"), self._session_id("bob")
        cookie = self._post("/approve/login", {"username": "alice", "password": "pw"}).headers["set-cookie"].split(";")[0]
        body = self.page.handle("GET", "/approve", "", {"cookie": cookie}, b"").body.decode()
        self.assertIn('action="/approve/new-session"', body)
        self.assertIn("새 대화를 먼저 연 다음", body)
        self.assertNotIn("내 예외 도구", body)  # exceptions are not enabled on this gateway
        token = body.split('name="csrf" value="')[1].split('"')[0]
        self.assertEqual(self._post("/approve/new-session", {"csrf": "x"}, cookie).status_code, 403)
        self.assertEqual(self._session_id("alice"), alice)
        self.assertEqual(self._post("/approve/new-session", {"csrf": token}, cookie).status_code, 200)
        self.assertNotEqual(self._session_id("alice"), alice)
        self.assertEqual(self._session_id("bob"), bob)
        self.assertEqual([e.event_type for e in self.sink.events][-1], "session_reset")

    def test_signing_in_is_needed(self):
        self.assertEqual(self._post("/approve/new-session", {"csrf": "x"}).status_code, 401)

    def test_the_old_sessions_taint_stays_on_record(self):
        taint = SessionTaintStore(Path(self._folder.name) / "sessions")
        old = self._session_id("alice")
        taint.mark(old, "mail:read_inbox")
        self.epochs.start_new("alice")
        self.assertIsNone(taint.get(self._session_id("alice")))
        self.assertEqual(taint.get(old).first_source, "mail:read_inbox")

    def test_the_block_message_says_where_the_button_is(self):
        gateway = GatewayTests()
        gateway.setUp()
        try:
            gateway.gateway._new_session_url = "https://gw.example/approve"
            gateway.store.remove("alice", "mail:send_email")
            gateway._taint()
            message = gateway._rpc("tools/call", "send_email", MAIL).body["error"]["message"]
            self.assertIn("open a new chat, then press 'start a new session' at https://gw.example/approve", message)
        finally:
            gateway.tearDown()


class CommandAndRoutingTests(unittest.TestCase):
    def test_admin_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            state = prepare_state_dir(Path(folder) / "state")
            log = state / "audit.jsonl"
            base = ["--state-dir", str(state), "--audit-log", str(log)]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(exceptions_main([*base, "allow", "mail:send_email"]), 0)
            store = TaintExceptionStore(state)
            store.designate("alice", "mail:send_email")
            with redirect_stdout(out):
                self.assertEqual(exceptions_main([*base, "list"]), 0)
                self.assertEqual(exceptions_main([*base, "revoke", "--user", "alice", "mail:send_email"]), 0)
            self.assertIn("user     alice  mail:send_email", out.getvalue())
            with redirect_stderr(io.StringIO()):
                self.assertEqual(exceptions_main([*base, "allow", "send_email"]), 2)
            events = [json.loads(line)["event_type"] for line in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events, ["taint_exception_changed", "taint_exception_changed"])

    def test_adapter_serves_the_page_only_when_configured(self):
        from http_gateway.adapter import HttpGatewayAdapter
        from http_gateway.models import HttpRequest

        with tempfile.TemporaryDirectory() as folder:
            config = GatewayConfig(GuardRegistry.from_dict({}), ())
            page = ApprovalPage(TaintExceptionStore(Path(folder)), lambda u, p: False)
            served = HttpGatewayAdapter(config, approval_page=page).handle(HttpRequest("GET", "/approve", {}, b""))
            self.assertEqual(served.status_code, 200)
            self.assertIn(b"/approve/login", served.body)
            plain = HttpGatewayAdapter(config).handle(HttpRequest("GET", "/approve", {}, b""))
            self.assertNotEqual(plain.status_code, 200)

    def test_the_server_refuses_exceptions_without_signed_in_users(self):
        from http_gateway.server import main as server_main

        with tempfile.TemporaryDirectory() as folder:
            state = prepare_state_dir(Path(folder) / "state")
            with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                server_main(["--allow-taint-exceptions", "--live-tools", "--state-dir", str(state)])
        self.assertIn("--allow-taint-exceptions needs --auth oauth", err.getvalue())


if __name__ == "__main__":
    unittest.main()
