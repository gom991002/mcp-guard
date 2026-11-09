import base64
import hashlib
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp",
    "mvp/03-server-registration-config", "mvp/04-tools-list-relay",
    "mvp/05-indirect-injection-throttle", "mvp/06-http-gateway-server",
    "mvp/07-tools-call-upstream-relay", "mvp/08-decision-controls", "mvp/09-cloud-entry",
):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry import (  # noqa: E402
    AuthorizationServer, OAuthSettings, UpstreamCredentials, UserDirectory, hash_password,
)
from cloud_entry.aws_secrets import SecretManagerError  # noqa: E402
from mcp_guard.audit import AuditRecorder, MemoryAuditSink  # noqa: E402
from cloud_entry.upstream_credentials import PerUserListClient, resolve_secret  # noqa: E402
from cloud_entry.upstream_oauth import (  # noqa: E402
    PerUserServer, SecretManagerTokenStore, UpstreamAuthError, UpstreamOAuth, UpstreamTokenStore,
)
from gateway_mvp.models import ToolDefinition, UpstreamServer  # noqa: E402
from http_gateway import HttpGatewayAdapter, HttpRequest  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from rule_sets.waf_gateway_rules import PROTOCOL_VERSION  # noqa: E402
from server_registry.loader import load_gateway_config  # noqa: E402
from tools_list_relay.client import HttpToolsListClient  # noqa: E402

GATEWAY = "http://localhost:8800"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "v" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
FORM = {"content-type": "application/x-www-form-urlencoded"}
PASSWORD = "correct horse battery"


class FakeUpstream:
    """An upstream MCP server that is also its own OAuth authorization server."""

    def __init__(self) -> None:
        self.codes: dict[str, str] = {}
        self.issued = 0
        self.refresh_ok = True
        self.wrong_iss = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, payload=None, headers=None):
                data = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                if payload is not None:
                    self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                parts = urlsplit(self.path)
                base = outer.base
                if parts.path == "/.well-known/oauth-protected-resource/mcp":
                    return self._send(200, {"resource": f"{base}/mcp", "authorization_servers": [base],
                                            "scopes_supported": ["mail.read"]})
                if parts.path == "/.well-known/oauth-authorization-server":
                    return self._send(200, {
                        "issuer": base, "authorization_endpoint": f"{base}/authorize",
                        "token_endpoint": f"{base}/token", "registration_endpoint": f"{base}/register",
                        "code_challenge_methods_supported": ["S256"],
                        "authorization_response_iss_parameter_supported": True})
                if parts.path == "/authorize":
                    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                    assert query["client_id"] == "up-client" and query["resource"] == f"{base}/mcp"
                    code = f"code-{len(outer.codes)}"
                    outer.codes[code] = query["code_challenge"]
                    iss = "https://evil.example" if outer.wrong_iss else base
                    location = query["redirect_uri"] + "?" + urlencode(
                        {"code": code, "state": query["state"], "iss": iss})
                    return self._send(302, headers={"location": location})
                self._send(404, {})

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                if self.path == "/register":
                    return self._send(201, {"client_id": "up-client"})
                if self.path == "/token":
                    form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
                    if form["grant_type"] == "authorization_code":
                        expected = outer.codes.pop(form["code"])
                        actual = base64.urlsafe_b64encode(
                            hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
                        if actual != expected or form["resource"] != f"{outer.base}/mcp":
                            return self._send(400, {"error": "invalid_grant"})
                    elif not outer.refresh_ok:
                        return self._send(400, {"error": "invalid_grant"})
                    outer.issued += 1
                    return self._send(200, {"access_token": f"up-token-{outer.issued}",
                                            "expires_in": 3600, "refresh_token": "up-refresh"})
                if self.path == "/mcp":
                    if not (self.headers.get("authorization") or "").startswith("Bearer up-token-"):
                        return self._send(401, {"error": "invalid_token"})
                    request = json.loads(body)
                    return self._send(200, {"jsonrpc": "2.0", "id": request["id"], "result": {
                        "resultType": "complete", "cacheScope": "public", "ttlMs": 60000,
                        "tools": [{"name": "mail.read", "description": "Read my mail.", "inputSchema": {}}]}})
                self._send(404, {})

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def _browser_follow(url: str) -> str:
    """Open an upstream authorize URL like a browser and return the Location it redirects to."""
    opener = urllib.request.build_opener(_NoFollow())
    try:
        opener.open(url, timeout=10)
    except urllib.error.HTTPError as error:
        return error.headers["location"]
    raise AssertionError("upstream did not redirect")


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


class DictSecretBackend:
    """MVP 8 SecretStore shape whose get accepts the key given to put, like AWS."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.puts: list[str] = []
        self.fail = False

    def put(self, key: str, secret: str) -> str:
        if self.fail:
            raise SecretManagerError("secret manager is down")
        self.values[key] = secret
        self.puts.append(key)
        return key

    def get(self, reference: str) -> str:
        if self.fail:
            raise SecretManagerError("secret manager is down")
        return self.values[reference]


class UpstreamOAuthTests(unittest.TestCase):
    def _store(self):
        return UpstreamTokenStore(None)

    def setUp(self) -> None:
        self.upstream = FakeUpstream()
        self.clock = Clock()
        self.audit = MemoryAuditSink()
        self.oauth = UpstreamOAuth(
            GATEWAY, {"mail": PerUserServer("mail", f"{self.upstream.base}/mcp")},
            self._store(), resolve_secret, clock=self.clock,
            allow_insecure_loopback=True, audit=AuditRecorder(self.audit),
        )
        users = UserDirectory({"alice": hash_password(PASSWORD, iterations=1000)})
        self.server = AuthorizationServer(OAuthSettings(issuer=GATEWAY), users, b"k" * 32,
                                          upstream=self.oauth, audit=AuditRecorder(self.audit))

    def _events(self, event_type):
        return [e for e in self.audit.events if e.event_type == event_type]

    def tearDown(self) -> None:
        self.upstream.close()

    def _call(self, method, path, query="", body=b"", headers=None):
        return self.server.handle(method, path, query, headers or {}, body)

    def _sign_in(self):
        client = json.loads(self._call("POST", "/register", body=json.dumps(
            {"redirect_uris": [CLAUDE_CALLBACK]}).encode()).body)
        page = self._call("GET", "/authorize", urlencode({
            "response_type": "code", "client_id": client["client_id"], "redirect_uri": CLAUDE_CALLBACK,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256", "state": "s1"}))
        text = page.body.decode()
        start = text.index('name="request" value="') + len('name="request" value="')
        form = urlencode({"request": text[start:text.index('"', start)], "username": "alice",
                          "password": PASSWORD}).encode()
        return client, self._call("POST", "/authorize", body=form, headers=FORM)

    def _link(self):
        client, response = self._sign_in()
        callback = _browser_follow(response.headers["location"])
        parts = urlsplit(callback)
        self.assertEqual(f"{parts.scheme}://{parts.netloc}{parts.path}", f"{GATEWAY}/upstream/callback")
        return client, self._call("GET", "/upstream/callback", parts.query)

    def test_sign_in_continues_into_upstream_authorization(self) -> None:
        _, response = self._sign_in()
        query = parse_qs(urlsplit(response.headers["location"]).query)

        self.assertTrue(response.headers["location"].startswith(f"{self.upstream.base}/authorize"))
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["resource"], [f"{self.upstream.base}/mcp"])
        self.assertEqual(query["scope"], ["mail.read"])
        self.assertEqual(query["client_id"], ["up-client"])  # registered by DCR

    def test_callback_stores_user_token_and_returns_to_claude(self) -> None:
        client, response = self._link()
        location = response.headers["location"]
        query = parse_qs(urlsplit(location).query)

        self.assertTrue(location.startswith(CLAUDE_CALLBACK))
        self.assertEqual(query["state"], ["s1"])
        self.assertEqual(self.oauth.access_token("alice", "mail"), "up-token-1")
        [linked] = self._events("upstream_linked")
        self.assertEqual((linked.user, linked.server_name, linked.client),
                         ("alice", "mail", client["client_id"]))
        self.assertEqual([e.details["outcome"] for e in self._events("sign_in")], ["success"])
        token = self._call("POST", "/token", body=urlencode({
            "grant_type": "authorization_code", "code": query["code"][0], "client_id": client["client_id"],
            "redirect_uri": CLAUDE_CALLBACK, "code_verifier": VERIFIER}).encode(), headers=FORM)
        self.assertEqual(token.status_code, 200)

    def test_upstream_token_only_resolves_inside_the_user_context(self) -> None:
        self._link()
        credentials = UpstreamCredentials(per_user={"mail": {}})
        credentials.attach(self.oauth)
        upstream = UpstreamServer("mail", "personal", (), url=f"{self.upstream.base}/mcp")

        self.assertEqual(credentials.headers_for(upstream), {})
        with self.server.user_context("alice"):
            self.assertEqual(credentials.headers_for(upstream), {"authorization": "Bearer up-token-1"})
            snapshot = PerUserListClient(HttpToolsListClient(header_provider=credentials.headers_for),
                                         frozenset({"mail"})).fetch(upstream)
        with self.server.user_context("bob"):
            with self.assertRaises(UpstreamAuthError):
                credentials.headers_for(upstream)

        self.assertEqual([t.name for t in snapshot.tools], ["mail.read"])
        self.assertEqual(snapshot.cache_scope, "private")  # upstream said public

    def test_wrong_iss_is_rejected(self) -> None:
        self.upstream.wrong_iss = True
        _, response = self._link()

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(self.oauth.access_token("alice", "mail"))
        self.assertEqual([e.details["outcome"] for e in self._events("upstream_linked")], ["failure"])

    def test_expired_token_refreshes_and_failed_refresh_unlinks(self) -> None:
        self._link()
        self.clock.now += 4000
        self.assertEqual(self.oauth.access_token("alice", "mail"), "up-token-2")

        self.clock.now += 4000
        self.upstream.refresh_ok = False
        self.assertIsNone(self.oauth.access_token("alice", "mail"))
        self.assertEqual(self.oauth.missing("alice"), ["mail"])
        [unlinked] = self._events("upstream_unlinked")
        self.assertEqual((unlinked.user, unlinked.server_name), ("alice", "mail"))
        self.assertTrue(unlinked.details["reason"].startswith("refresh failed"))

    def test_gateway_serves_its_client_metadata_document(self) -> None:
        document = json.loads(self._call("GET", "/oauth/client-metadata.json").body)

        self.assertEqual(document["client_id"], f"{GATEWAY}/oauth/client-metadata.json")
        self.assertEqual(document["redirect_uris"], [f"{GATEWAY}/upstream/callback"])

    def test_ssrf_guard_rejects_plain_http_and_private_addresses(self) -> None:
        strict = UpstreamOAuth(GATEWAY, {}, UpstreamTokenStore(None), resolve_secret)
        for url in ("http://example.com/x", "https://127.0.0.1/x", "https://10.0.0.5/x"):
            with self.subTest(url=url):
                with self.assertRaises(UpstreamAuthError):
                    strict._check_url(url)


class SecretManagerUpstreamOAuthTests(UpstreamOAuthTests):
    """The same per-user flows with tokens kept in a secret manager."""

    def _store(self):
        self.backend = DictSecretBackend()
        return SecretManagerTokenStore(self.backend, clock=self.clock)

    def test_restarted_gateway_refreshes_from_the_stored_refresh_token(self) -> None:
        self._link()
        stored = [json.loads(v) for v in self.backend.values.values()]
        restarted = UpstreamOAuth(
            GATEWAY, {"mail": PerUserServer("mail", f"{self.upstream.base}/mcp")},
            SecretManagerTokenStore(self.backend, clock=self.clock), resolve_secret,
            clock=self.clock, allow_insecure_loopback=True,
        )

        self.assertFalse(any("access_token" in record for record in stored))
        self.assertEqual(restarted.access_token("alice", "mail"), "up-token-2")


RECORD = {"access_token": "at", "refresh_token": "rt", "expires_at": 1.0,
          "token_endpoint": "https://up.example/token", "client_id": "c", "client_secret": ""}


class SecretManagerTokenStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = DictSecretBackend()
        self.clock = Clock()
        self.store = SecretManagerTokenStore(self.backend, prefix="mcp-guard/test", clock=self.clock)
        self.name = self.store._name("token", "alice|mail")

    def _restarted(self):
        return SecretManagerTokenStore(self.backend, prefix="mcp-guard/test", clock=self.clock)

    def test_access_token_stays_in_memory_when_a_refresh_token_exists(self) -> None:
        self.store.set_token("alice|mail", RECORD)
        stored = json.loads(self.backend.values[self.name])

        self.assertEqual(self.store.token("alice|mail"), RECORD)
        self.assertTrue(self.name.startswith("mcp-guard/test/token/"))
        self.assertNotIn("alice", self.name)
        self.assertNotIn("access_token", stored)
        self.assertEqual(stored["refresh_token"], "rt")
        self.assertNotIn("access_token", self._restarted().token("alice|mail"))

    def test_access_token_is_stored_without_a_refresh_token(self) -> None:
        self.store.set_token("alice|mail", {**RECORD, "refresh_token": ""})

        self.assertEqual(self._restarted().token("alice|mail")["access_token"], "at")

    def test_writes_to_one_secret_wait_for_the_interval(self) -> None:
        self.store.set_token("alice|mail", RECORD)
        self.store.set_token("alice|mail", {**RECORD, "refresh_token": "rt2"})

        self.assertEqual(len(self.backend.puts), 1)
        self.assertEqual(self.store.token("alice|mail")["refresh_token"], "rt2")
        self.clock.now += 600
        self.store.token("bob|mail")  # any store call writes what is due
        self.assertEqual(len(self.backend.puts), 2)
        self.assertEqual(json.loads(self.backend.values[self.name])["refresh_token"], "rt2")

    def test_flush_writes_waiting_values_now(self) -> None:
        self.store.set_token("alice|mail", RECORD)
        self.store.set_token("alice|mail", {**RECORD, "refresh_token": "rt2"})
        self.store.flush()

        self.assertEqual(json.loads(self.backend.values[self.name])["refresh_token"], "rt2")

    def test_new_access_token_alone_is_not_written(self) -> None:
        self.store.set_token("alice|mail", RECORD)
        self.clock.now += 600
        self.store.set_token("alice|mail", {**RECORD, "access_token": "at2", "expires_at": 2.0})

        self.assertEqual(len(self.backend.puts), 1)

    def test_forget_overwrites_with_an_empty_object(self) -> None:
        self.store.set_token("alice|mail", RECORD)
        self.clock.now += 600
        self.store.forget_token("alice|mail")
        self.store.forget_token("bob|mail")  # never stored: nothing to write

        self.assertEqual(self.backend.values[self.name], "{}")
        self.assertEqual(len(self.backend.puts), 2)
        self.assertIsNone(self.store.token("alice|mail"))
        self.assertIsNone(self._restarted().token("alice|mail"))

    def test_backend_failure_fails_closed_and_the_write_is_retried(self) -> None:
        self.assertIsNone(self.store.token("alice|mail"))
        self.backend.fail = True
        with self.assertRaises(UpstreamAuthError):
            self.store.token("bob|mail")
        with self.assertRaises(UpstreamAuthError):
            self.store.set_token("alice|mail", RECORD)

        self.backend.fail = False
        self.assertIsNone(self.store.token("carol|mail"))
        self.assertIn(self.name, self.backend.values)

    def test_prefix_is_limited_to_secret_name_characters(self) -> None:
        with self.assertRaises(ValueError):
            SecretManagerTokenStore(self.backend, prefix="bad prefix!")


class StepUpTests(unittest.TestCase):
    def _sender(self, store):
        oauth = UpstreamOAuth(GATEWAY, {"company-tools": PerUserServer("company-tools", "https://x/mcp")},
                              store, resolve_secret)
        server = AuthorizationServer(OAuthSettings(issuer=GATEWAY), UserDirectory({}), b"k" * 32,
                                     upstream=oauth, clock=lambda: datetime.now(UTC))
        token = server._tokens.issue("bob", ("mcp",), audience=f"{GATEWAY}/mcp").token
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
        config = load_gateway_config(
            ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json", policy)
        adapter = HttpGatewayAdapter(config, auth=server)

        def send(method, params):
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {
                **params, "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}}).encode()
            return adapter.handle(HttpRequest("POST", "/mcp", {
                "content-type": "application/json", "origin": "https://chat.example",
                "mcp-protocol-version": PROTOCOL_VERSION, "mcp-method": method,
                "authorization": f"Bearer {token}"}, body, "203.0.113.10"))
        return send

    def test_unreadable_token_store_answers_503(self) -> None:
        backend = DictSecretBackend()
        backend.fail = True
        response = self._sender(SecretManagerTokenStore(backend))("tools/list", {})

        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.body)["error"], "upstream_credentials_unavailable")

    def test_sign_in_with_unreadable_token_store_answers_503(self) -> None:
        backend = DictSecretBackend()
        backend.fail = True
        oauth = UpstreamOAuth(GATEWAY, {"mail": PerUserServer("mail", "https://x/mcp")},
                              SecretManagerTokenStore(backend), resolve_secret)
        users = UserDirectory({"alice": hash_password(PASSWORD, iterations=1000)})
        server = AuthorizationServer(OAuthSettings(issuer=GATEWAY), users, b"k" * 32, upstream=oauth)
        client = json.loads(server.handle("POST", "/register", "", {}, json.dumps(
            {"redirect_uris": [CLAUDE_CALLBACK]}).encode()).body)
        text = server.handle("GET", "/authorize", urlencode({
            "response_type": "code", "client_id": client["client_id"], "redirect_uri": CLAUDE_CALLBACK,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256"}), {}, b"").body.decode()
        start = text.index('name="request" value="') + len('name="request" value="')
        login = server.handle("POST", "/authorize", "", FORM, urlencode({
            "request": text[start:text.index('"', start)], "username": "alice",
            "password": PASSWORD}).encode())

        self.assertEqual(login.status_code, 503)

    def test_unlinked_per_user_server_gets_403_step_up(self) -> None:
        send = self._sender(UpstreamTokenStore(None))

        for response in (send("tools/list", {}),
                         send("tools/call", {"name": "company.search", "arguments": {}})):
            self.assertEqual(response.status_code, 403)
            self.assertIn('error="insufficient_scope"', response.headers["www-authenticate"])
            self.assertIn("upstream:company-tools", response.headers["www-authenticate"])

    def test_upstream_scope_is_accepted_at_authorize(self) -> None:
        oauth = UpstreamOAuth(GATEWAY, {"mail": PerUserServer("mail", "https://x/mcp")},
                              UpstreamTokenStore(None), resolve_secret)
        server = AuthorizationServer(OAuthSettings(issuer=GATEWAY), UserDirectory({}), b"k" * 32,
                                     upstream=oauth)
        client = json.loads(server.handle("POST", "/register", "", {}, json.dumps(
            {"redirect_uris": [CLAUDE_CALLBACK]}).encode()).body)
        page = server.handle("GET", "/authorize", urlencode({
            "response_type": "code", "client_id": client["client_id"], "redirect_uri": CLAUDE_CALLBACK,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256",
            "scope": "mcp upstream:mail"}), {}, b"")

        self.assertEqual(page.status_code, 200)


CLAUDE_CODE_CIMD = "https://claude.ai/oauth/claude-code-client-metadata"
CHATGPT_CIMD = "https://chatgpt.com/oauth/client.json"
CHATGPT_CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"
CODEX_CIMD = "https://chatgpt.com/oauth/codex/client.json"
GRANTS = {"grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]}
# Field values as published at CHATGPT_CIMD and CODEX_CIMD (fetched 2026-11-02).
CHATGPT_DOCUMENT = {"client_id": CHATGPT_CIMD, "client_name": "ChatGPT",
                    "redirect_uris": [CHATGPT_CALLBACK],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"], **GRANTS}
CODEX_DOCUMENT = {"client_id": CODEX_CIMD, "client_name": "Codex",
                  "redirect_uris": ["http://127.0.0.1/callback", "http://localhost/callback"],
                  "token_endpoint_auth_method": "none",
                  "token_endpoint_auth_methods_supported": ["none"], **GRANTS}


class CimdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fetches = []
        self.document = {"client_id": CLAUDE_CODE_CIMD, "client_name": "Claude Code",
                         "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
                         "grant_types": ["authorization_code", "refresh_token"],
                         "response_types": ["code"], "token_endpoint_auth_method": "none"}

        def fetch(url):
            self.fetches.append(url)
            return json.dumps(self.document).encode(), "max-age=300"

        users = UserDirectory({"alice": hash_password(PASSWORD, iterations=1000)})
        self.server = AuthorizationServer(OAuthSettings(issuer="https://mcp.example.com"), users,
                                          b"k" * 32, fetch_document=fetch)

    def _authorize(self, client_id=CLAUDE_CODE_CIMD, redirect="http://localhost:53682/callback"):
        return self.server.handle("GET", "/authorize", urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256", "state": "x"}), {}, b"")

    def test_metadata_advertises_cimd(self) -> None:
        metadata = self.server.authorization_server_metadata()

        self.assertTrue(metadata["client_id_metadata_document_supported"])
        self.assertIn("none", metadata["token_endpoint_auth_methods_supported"])

    def _sign_in(self, client_id, redirect):
        page = self._authorize(client_id, redirect)
        self.assertEqual(page.status_code, 200)
        text = page.body.decode()
        start = text.index('name="request" value="') + len('name="request" value="')
        login = self.server.handle("POST", "/authorize", "", FORM, urlencode({
            "request": text[start:text.index('"', start)], "username": "alice",
            "password": PASSWORD}).encode())
        location = login.headers["location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        token = self.server.handle("POST", "/token", "", FORM, urlencode({
            "grant_type": "authorization_code", "code": code, "client_id": client_id,
            "redirect_uri": redirect, "code_verifier": VERIFIER}).encode())
        return page, location, token

    def test_claude_code_cimd_signs_in_without_registration(self) -> None:
        page, _, token = self._sign_in(CLAUDE_CODE_CIMD, "http://localhost:53682/callback")

        self.assertIn("claude.ai", page.body.decode())  # named by host, not client_name
        self.assertEqual(token.status_code, 200)
        self.assertEqual(self.fetches, [CLAUDE_CODE_CIMD])  # cached after the first fetch

    def test_chatgpt_cimd_signs_in_as_public_client(self) -> None:
        # ChatGPT prefers private_key_jwt but also lists none, the only method offered here.
        self.document = CHATGPT_DOCUMENT
        _, location, token = self._sign_in(CHATGPT_CIMD, CHATGPT_CALLBACK)

        self.assertTrue(location.startswith(CHATGPT_CALLBACK + "?"))
        self.assertEqual(parse_qs(urlsplit(location).query)["iss"], ["https://mcp.example.com"])
        self.assertEqual(token.status_code, 200)

    def test_codex_cimd_signs_in_on_loopback_port(self) -> None:
        self.document = CODEX_DOCUMENT
        _, _, token = self._sign_in(CODEX_CIMD, "http://127.0.0.1:49152/callback")

        self.assertEqual(token.status_code, 200)

    def test_document_without_public_client_method_is_refused(self) -> None:
        self.document = {**CHATGPT_DOCUMENT, "token_endpoint_auth_methods_supported": ["private_key_jwt"]}

        self.assertEqual(self._authorize(CHATGPT_CIMD, CHATGPT_CALLBACK).status_code, 400)

    def test_untrusted_host_or_mismatched_document_is_refused(self) -> None:
        self.assertEqual(self._authorize("https://evil.example/client.json").status_code, 400)
        self.document["client_id"] = "https://claude.ai/other"
        self.assertEqual(self._authorize().status_code, 400)

    def test_unlisted_redirect_is_refused(self) -> None:
        self.assertEqual(self._authorize(redirect="http://localhost:5000/elsewhere").status_code, 400)


if __name__ == "__main__":
    unittest.main()
