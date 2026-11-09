"""M1 operation decisions: retention (D6-24), correlation runs (D6-25), sessions (D6-26)."""

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp",
    "mvp/03-server-registration-config", "mvp/04-tools-list-relay",
    "mvp/05-indirect-injection-throttle", "mvp/06-http-gateway-server",
    "mvp/07-tools-call-upstream-relay", "mvp/08-decision-controls", "mvp/09-cloud-entry",
    "mvp/10-local-entry",
):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry import AuthorizationServer, OAuthSettings, UserDirectory, hash_password  # noqa: E402
from cloud_entry.admin import add_client  # noqa: E402
from cloud_entry.oauth import load_static_clients  # noqa: E402
from http_gateway import HttpGatewayAdapter, HttpRequest  # noqa: E402
from http_gateway.correlation import CorrelationRunner  # noqa: E402
from http_gateway.server import _audit_recorder  # noqa: E402
from local_entry.wrapper import wrapper_session  # noqa: E402
from local_entry.manifest import local_recorder  # noqa: E402
from mcp_guard.audit import (  # noqa: E402
    AuditEvent, AuditRecorder, JsonlAuditSink, MemoryAuditSink, RecentEventsSink, audit_event,
    audit_log_files, read_audit_log,
)
from mcp_guard.registry import GuardRegistry  # noqa: E402
from rule_sets.waf_gateway_rules import PROTOCOL_VERSION  # noqa: E402
from server_registry.loader import load_gateway_config  # noqa: E402

GATEWAY = "http://localhost:8800"
GEMINI_CALLBACK = "https://vertexaisearch.cloud.google.com/oauth-redirect"
VERIFIER = "v" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
FORM = {"content-type": "application/x-www-form-urlencoded"}
PASSWORD = "correct horse battery"


class RetentionTests(unittest.TestCase):
    def test_monthly_rotation_keeps_six_months(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "audit.jsonl"
            now = datetime.now(UTC)
            old = Path(folder) / "audit.2001-01.jsonl"  # long past the retention
            old.write_text("", encoding="utf-8")
            recent_month = (now.replace(day=1) - timedelta(days=1))
            log.write_text(json.dumps(audit_event("sign_in", user="last-month").to_dict()) + "\n",
                           encoding="utf-8")
            stamp = recent_month.timestamp()
            os.utime(log, (stamp, stamp))
            JsonlAuditSink(log, retention_days=180).emit(audit_event("sign_in", user="now"))

            rotated = Path(folder) / f"audit.{recent_month.year:04d}-{recent_month.month:02d}.jsonl"
            self.assertTrue(rotated.exists())
            self.assertFalse(old.exists())
            self.assertEqual(audit_log_files(log), [rotated, log])
            self.assertEqual([e.user for e in read_audit_log(log, include_rotated=True)],
                             ["last-month", "now"])

    def test_without_retention_nothing_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "audit.jsonl"
            log.write_text("", encoding="utf-8")
            os.utime(log, (0, 0))
            JsonlAuditSink(log).emit(audit_event("sign_in"))

            self.assertEqual(audit_log_files(log), [log])


class CorrelationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(UTC)
        self.window = RecentEventsSink(24 * 3600)
        self.sink = MemoryAuditSink()
        self.runner = CorrelationRunner(self.window, AuditRecorder(self.sink),
                                        clock=lambda: self.now.timestamp())

    def _taint_then_send(self, session="claude:user:bob"):
        self.window.emit(audit_event("response_contaminated", server_name="github",
                                     session_id=session, timestamp=self.now - timedelta(hours=2)))
        self.window.emit(audit_event("external_tool_call", server_name="mail", tool_name="send",
                                     session_id=session, timestamp=self.now - timedelta(hours=1)))

    def test_a_match_is_alerted_once_while_in_the_look_back(self) -> None:
        self._taint_then_send()
        first = self.runner.run_once()
        second = self.runner.run_once()

        self.assertEqual([m.rule.rule_id for m in first], ["M1_TAINTED_SESSION_EXTERNAL_CALL"])
        self.assertEqual(second, [])
        [alert] = self.sink.events
        self.assertEqual((alert.event_type, alert.stage, alert.marker), ("correlation_alert", "audit", "M1"))
        self.assertEqual(alert.session_id, "claude:user:bob")
        self.assertEqual(alert.details["severity"], "critical")

    def test_events_outside_the_look_back_are_ignored(self) -> None:
        self.window.emit(audit_event("response_contaminated", session_id="s",
                                     timestamp=self.now - timedelta(days=2)))
        self.window.emit(audit_event("external_tool_call", session_id="s",
                                     timestamp=self.now - timedelta(days=2)))

        self.assertEqual(self.runner.run_once(), [])

    def test_restart_reuses_persisted_alert_for_deduplication(self) -> None:
        self._taint_then_send()
        self.runner.run_once()
        self.window.emit(self.sink.events[0])  # startup loads the same alert from JSONL
        restarted = CorrelationRunner(self.window, AuditRecorder(self.sink),
                                      clock=lambda: self.now.timestamp())

        self.assertEqual(restarted.run_once(), [])
        self.assertEqual(len(self.sink.events), 1)

    def test_alert_screen_and_email_filter_match_the_alert_event(self) -> None:
        self._taint_then_send()
        self.runner.run_once()
        alert = self.sink.events[0].to_dict()
        alerts = ROOT / "mvp" / "09-cloud-entry" / "deploy" / "alerts"
        metric_filter = json.loads((alerts / "metric-filter.json").read_text(encoding="utf-8"))
        dashboard = json.loads((alerts / "dashboard.json").read_text(encoding="utf-8"))

        self.assertEqual(metric_filter["filterPattern"], '{ $.event_type = "correlation_alert" }')
        self.assertEqual(alert["event_type"], "correlation_alert")
        query = dashboard["widgets"][1]["properties"]["query"]
        for field in ("details.severity", "details.rule_id", "details.message", "session_id"):
            self.assertIn(field, query)
            value = alert
            for part in field.split("."):
                value = value[part]
            self.assertTrue(value)

    def test_look_back_must_cover_the_interval(self) -> None:
        with self.assertRaises(ValueError):
            CorrelationRunner(self.window, AuditRecorder(), interval=600, lookback=300)

    def test_gateway_preloads_the_look_back_from_the_local_copy(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "audit.jsonl"
            JsonlAuditSink(log).emit(audit_event("sign_in", user="before-restart"))
            args = argparse.Namespace(
                audit_log=str(log), audit_retention_days=180, audit_cloudwatch_group=None,
                correlation_interval=300, correlation_lookback=3600)
            audit, recent = _audit_recorder(args, Path("/"), {})
            audit.record(audit_event("sign_in", user="after-restart"))

            self.assertEqual([e.user for e in recent.events()], ["before-restart", "after-restart"])


class RemoteSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.addCleanup(self._folder.cleanup)
        clients = Path(self._folder.name) / "oauth-clients.json"
        self.secret = add_client(clients, "gemini-enterprise", [GEMINI_CALLBACK], "gemini",
                                 "Gemini Enterprise")
        users = UserDirectory({"bob": hash_password(PASSWORD, iterations=1000)})
        self.server = AuthorizationServer(
            OAuthSettings(issuer=GATEWAY), users, b"k" * 32, clock=lambda: datetime.now(UTC),
            static_clients=load_static_clients(clients))
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
        config = load_gateway_config(
            ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json", policy)
        self.sink = MemoryAuditSink()
        self.adapter = HttpGatewayAdapter(config, auth=self.server, audit=AuditRecorder(self.sink))

    def _session(self, client_id, meta=None, user="bob", extra_headers=None) -> str:
        token = self.server._tokens.issue(user, ("mcp",), audience=f"{GATEWAY}/mcp",
                                          client_id=client_id).token
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION, **(meta or {})}}
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}).encode()
        self.sink.events.clear()
        self.adapter.handle(HttpRequest("POST", "/mcp", {
            "content-type": "application/json", "origin": "https://chat.example",
            "mcp-protocol-version": PROTOCOL_VERSION, "mcp-method": "tools/list",
            "authorization": f"Bearer {token}", **(extra_headers or {})}, body, "203.0.113.10"))
        return self.sink.events[0].session_id

    def _dcr(self, name, redirect):
        return json.loads(self.server.handle("POST", "/register", "", {}, json.dumps(
            {"redirect_uris": [redirect], "client_name": name}).encode()).body)["client_id"]

    def test_each_llm_client_has_its_own_sessions(self) -> None:
        sessions = {
            "claude": self._session("https://claude.ai/oauth/claude-code-client-metadata"),
            "chatgpt": self._session("https://chatgpt.com/oauth/client.json"),
            "codex": self._session("https://chatgpt.com/oauth/codex/client.json"),
            "gemini": self._session("gemini-enterprise"),
            "gemini-cli": self._session(self._dcr("Gemini CLI MCP Client",
                                                  "http://localhost:7777/oauth/callback")),
        }

        self.assertEqual(len(set(sessions.values())), len(sessions))
        for family, session in sessions.items():
            self.assertTrue(session.startswith(f"{family.split('-')[0]}:user:"))
            self.assertNotIn("bob", session)

    def test_chatgpt_sessions_follow_its_conversation_id(self) -> None:
        first = self._session("https://chatgpt.com/oauth/client.json", {"openai/session": "c-1"})
        again = self._session("https://chatgpt.com/oauth/client.json", {"openai/session": "c-1"})
        other = self._session("https://chatgpt.com/oauth/client.json", {"openai/session": "c-2"})
        claude = self._session("https://claude.ai/oauth/claude-code-client-metadata",
                               {"openai/session": "c-1"})

        self.assertTrue(first.startswith("chatgpt:conversation:"))
        self.assertEqual(first, again)
        self.assertNotEqual(first, other)
        self.assertTrue(claude.startswith("claude:user:"))  # only ChatGPT's id is used
        self.assertNotIn("c-1", first)

    def test_authenticated_session_ignores_spoofed_header_and_separates_users(self) -> None:
        client = "https://chatgpt.com/oauth/client.json"
        meta = {"openai/session": "same-conversation"}
        first = self._session(client, meta)
        spoofed = self._session(client, meta, extra_headers={"mcp-guard-session-id": "attacker"})
        other_user = self._session(client, meta, user="alice")

        self.assertEqual(first, spoofed)
        self.assertNotEqual(first, other_user)
        self.assertNotEqual(spoofed, "attacker")


class GeminiEnterpriseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.addCleanup(self._folder.cleanup)
        clients = Path(self._folder.name) / "oauth-clients.json"
        self.secret = add_client(clients, "gemini-enterprise", [GEMINI_CALLBACK], "gemini")
        users = UserDirectory({"bob": hash_password(PASSWORD, iterations=1000)})
        self.server = AuthorizationServer(OAuthSettings(issuer=GATEWAY), users, b"k" * 32,
                                          static_clients=load_static_clients(clients))

    def _code(self) -> str:
        page = self.server.handle("GET", "/authorize", urlencode({
            "response_type": "code", "client_id": "gemini-enterprise", "redirect_uri": GEMINI_CALLBACK,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256",
            "scope": "mcp offline_access"}), {}, b"").body.decode()
        start = page.index('name="request" value="') + len('name="request" value="')
        login = self.server.handle("POST", "/authorize", "", FORM, urlencode({
            "request": page[start:page.index('"', start)], "username": "bob",
            "password": PASSWORD}).encode())
        location = login.headers["location"]
        self.assertTrue(location.startswith(GEMINI_CALLBACK))
        return parse_qs(urlsplit(location).query)["code"][0]

    def _token(self, headers=None, **form):
        return self.server.handle("POST", "/token", "", {**FORM, **(headers or {})}, urlencode({
            "grant_type": "authorization_code", "code": self._code(), "redirect_uri": GEMINI_CALLBACK,
            "code_verifier": VERIFIER, **form}).encode())

    def test_basic_authentication_gets_tokens(self) -> None:
        basic = base64.b64encode(f"gemini-enterprise:{self.secret}".encode()).decode()

        self.assertEqual(self._token({"authorization": f"Basic {basic}"}).status_code, 200)

    def test_secret_in_the_form_also_works(self) -> None:
        response = self._token(client_id="gemini-enterprise", client_secret=self.secret)

        self.assertEqual(response.status_code, 200)

    def test_missing_or_wrong_secret_is_refused(self) -> None:
        self.assertEqual(self._token(client_id="gemini-enterprise").status_code, 401)
        self.assertEqual(self._token(client_id="gemini-enterprise",
                                     client_secret="wrong").status_code, 401)

    def test_secret_is_stored_only_as_a_hash(self) -> None:
        stored = (Path(self._folder.name) / "oauth-clients.json").read_text(encoding="utf-8")

        self.assertNotIn(self.secret, stored)

    def test_public_clients_still_choose_cimd(self) -> None:
        methods = self.server.authorization_server_metadata()["token_endpoint_auth_methods_supported"]

        self.assertIn("none", methods)
        self.assertIn("client_secret_basic", methods)


class LocalWrapperSessionTests(unittest.TestCase):
    def test_each_wrapper_process_is_one_session(self) -> None:
        first, second = wrapper_session("files"), wrapper_session("files")

        self.assertTrue(first.startswith("l2:files:"))
        self.assertNotEqual(first, second)

    def test_wrapper_events_carry_the_process_session(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "audit.jsonl"
            local_recorder(str(log), session_id="l2:files:abc").record(audit_event("tools_list_changed"))
            local_recorder(str(log), session_id="l2:files:abc").record(
                audit_event("tools_list_changed", session_id="claude-code-session"))
            sessions = [e.session_id for e in read_audit_log(log)]

        self.assertEqual(sessions, ["l2:files:abc", "claude-code-session"])


if __name__ == "__main__":
    unittest.main()
