import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup",
    "mvp/02-remote-gateway-mcp",
    "mvp/03-server-registration-config",
    "mvp/04-tools-list-relay",
    "mvp/05-indirect-injection-throttle",
    "mvp/06-http-gateway-server",
    "mvp/07-tools-call-upstream-relay",
    "mvp/08-decision-controls",
    "mvp/09-cloud-entry",
):
    sys.path.insert(0, str(ROOT / folder))

from cloud_entry import (  # noqa: E402
    AuthorizationServer,
    OAuthSettings,
    OAuthStateStore,
    SecretUnavailable,
    UpstreamCredential,
    UpstreamCredentials,
    UserDirectory,
    hash_password,
)
from gateway_mvp.models import ToolDefinition, UpstreamServer  # noqa: E402
from http_gateway import HttpGatewayAdapter, HttpRequest  # noqa: E402
from http_gateway.server import main as gateway_main  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from rule_sets.waf_gateway_rules import PROTOCOL_VERSION  # noqa: E402
from server_registry.loader import load_gateway_config  # noqa: E402
from tools_call_relay.client import HttpJsonRpcToolCallClient  # noqa: E402
from tools_list_relay.client import HttpToolsListClient  # noqa: E402

ISSUER = "https://mcp.example.com"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "v" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
FORM = {"content-type": "application/x-www-form-urlencoded"}


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _server(clock=None, state=None):
    users = UserDirectory({"alice": hash_password("correct horse battery", iterations=1000)})
    return AuthorizationServer(
        OAuthSettings(issuer=ISSUER), users, b"k" * 32, state=state, clock=clock or Clock()
    )


def _call(server, method, path, query="", body=b"", headers=None):
    return server.handle(method, path, query, headers or {}, body)


def _register(server, redirect=CLAUDE_CALLBACK):
    response = _call(server, "POST", "/register",
                     body=json.dumps({"redirect_uris": [redirect], "client_name": "Claude"}).encode())
    return response, json.loads(response.body)


def _authorize_query(client_id, redirect=CLAUDE_CALLBACK, **extra):
    params = {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
        "code_challenge": CHALLENGE, "code_challenge_method": "S256", "state": "xyz",
        "resource": f"{ISSUER}/mcp", **extra,
    }
    return urlencode(params)


def _signed_request(page_body: bytes) -> str:
    text = page_body.decode()
    marker = 'name="request" value="'
    start = text.index(marker) + len(marker)
    return text[start:text.index('"', start)]


def _login(server, client_id, redirect=CLAUDE_CALLBACK, password="correct horse battery"):
    page = _call(server, "GET", "/authorize", _authorize_query(client_id, redirect))
    form = urlencode({"request": _signed_request(page.body), "username": "alice",
                      "password": password}).encode()
    return _call(server, "POST", "/authorize", body=form, headers=FORM)


def _code_from(response):
    query = parse_qs(urlsplit(response.headers["location"]).query)
    return query["code"][0], query


def _exchange(server, client_id, code, redirect=CLAUDE_CALLBACK, verifier=VERIFIER):
    form = urlencode({"grant_type": "authorization_code", "code": code, "client_id": client_id,
                      "redirect_uri": redirect, "code_verifier": verifier,
                      "resource": f"{ISSUER}/mcp"}).encode()
    return _call(server, "POST", "/token", body=form, headers=FORM)


class OAuthServerTests(unittest.TestCase):
    def test_discovery_metadata_names_resource_and_issuer(self) -> None:
        server = _server()
        prm = json.loads(_call(server, "GET", "/.well-known/oauth-protected-resource/mcp").body)
        asm = json.loads(_call(server, "GET", "/.well-known/oauth-authorization-server").body)

        self.assertEqual(prm["resource"], f"{ISSUER}/mcp")
        self.assertEqual(prm["authorization_servers"], [ISSUER])
        self.assertEqual(asm["code_challenge_methods_supported"], ["S256"])
        self.assertTrue(asm["authorization_response_iss_parameter_supported"])
        self.assertEqual(asm["registration_endpoint"], f"{ISSUER}/register")

    def test_registration_accepts_claude_chatgpt_and_loopback_rejects_others(self) -> None:
        server = _server()
        for redirect, status in ((CLAUDE_CALLBACK, 201), ("http://localhost:4567/callback", 201),
                                 ("https://chatgpt.com/connector_platform_oauth_redirect", 201),
                                 ("https://chatgpt.com/connector/oauth/abc_123-X", 201),
                                 ("https://chatgpt.com/connector/oauth/a/b", 400),
                                 ("https://chatgpt.com/elsewhere", 400),
                                 ("https://evil.example/callback", 400),
                                 ("http://attacker.example/callback", 400)):
            with self.subTest(redirect=redirect):
                self.assertEqual(_register(server, redirect)[0].status_code, status)

    def test_registration_rejects_confidential_clients(self) -> None:
        body = json.dumps({"redirect_uris": [CLAUDE_CALLBACK],
                           "token_endpoint_auth_method": "client_secret_basic"}).encode()
        response = _call(_server(), "POST", "/register", body=body)

        self.assertEqual(json.loads(response.body)["error"], "invalid_client_metadata")

    def test_full_authorization_code_flow_with_pkce(self) -> None:
        server = _server()
        _, client = _register(server)

        page = _call(server, "GET", "/authorize", _authorize_query(client["client_id"]))
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["x-frame-options"], "DENY")
        self.assertIn("claude.ai", page.body.decode())

        response = _login(server, client["client_id"])
        self.assertEqual(response.status_code, 302)
        code, query = _code_from(response)
        self.assertEqual(query["state"], ["xyz"])
        self.assertEqual(query["iss"], [ISSUER])

        token = _exchange(server, client["client_id"], code)
        payload = json.loads(token.body)
        self.assertEqual(token.status_code, 200)
        self.assertEqual(token.headers["cache-control"], "no-store")
        claims = server.verify_bearer(f"Bearer {payload['access_token']}")
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(claims["aud"], f"{ISSUER}/mcp")

    def test_wrong_password_shows_form_without_redirect(self) -> None:
        server = _server()
        _, client = _register(server)

        response = _login(server, client["client_id"], password="wrong password!!")

        self.assertEqual(response.status_code, 401)
        self.assertNotIn("location", response.headers)

    def test_unknown_client_or_redirect_never_redirects(self) -> None:
        server = _server()
        _, client = _register(server)
        unknown = _call(server, "GET", "/authorize", _authorize_query("nope"))
        foreign = _call(server, "GET", "/authorize",
                        _authorize_query(client["client_id"], "https://evil.example/cb"))

        for response in (unknown, foreign):
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("location", response.headers)

    def test_missing_pkce_is_redirected_as_error(self) -> None:
        server = _server()
        _, client = _register(server)

        response = _call(server, "GET", "/authorize",
                         _authorize_query(client["client_id"], code_challenge_method="plain"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(parse_qs(urlsplit(response.headers["location"]).query)["error"],
                         ["invalid_request"])

    def test_wrong_verifier_fails_and_code_is_single_use(self) -> None:
        server = _server()
        _, client = _register(server)
        code, _ = _code_from(_login(server, client["client_id"]))

        wrong = _exchange(server, client["client_id"], code, verifier="w" * 50)
        retry = _exchange(server, client["client_id"], code)

        self.assertEqual(json.loads(wrong.body)["error"], "invalid_grant")
        self.assertEqual(json.loads(retry.body)["error"], "invalid_grant")

    def test_expired_code_is_rejected(self) -> None:
        clock = Clock()
        server = _server(clock)
        _, client = _register(server)
        code, _ = _code_from(_login(server, client["client_id"]))
        clock.now += timedelta(seconds=61)

        self.assertEqual(json.loads(_exchange(server, client["client_id"], code).body)["error"],
                         "invalid_grant")

    def test_loopback_redirect_matches_any_port(self) -> None:
        server = _server()
        _, client = _register(server, "http://127.0.0.1/callback")

        response = _login(server, client["client_id"], "http://127.0.0.1:53111/callback")
        code, _ = _code_from(response)

        token = _exchange(server, client["client_id"], code, "http://127.0.0.1:53111/callback")
        self.assertEqual(token.status_code, 200)

    def test_refresh_token_rotates(self) -> None:
        server = _server()
        _, client = _register(server)
        code, _ = _code_from(_login(server, client["client_id"]))
        first = json.loads(_exchange(server, client["client_id"], code).body)

        def refresh(token):
            form = urlencode({"grant_type": "refresh_token", "refresh_token": token,
                              "client_id": client["client_id"]}).encode()
            return _call(server, "POST", "/token", body=form, headers=FORM)

        second = refresh(first["refresh_token"])
        reused = refresh(first["refresh_token"])

        self.assertEqual(second.status_code, 200)
        self.assertNotEqual(json.loads(second.body)["refresh_token"], first["refresh_token"])
        self.assertEqual(json.loads(reused.body)["error"], "invalid_grant")

    def test_bearer_rejects_other_audience_and_garbage(self) -> None:
        server = _server()
        # Same signing key, different resource: only the audience differs.
        other = AuthorizationServer(OAuthSettings(issuer="https://other.example.com"),
                                    UserDirectory({}), b"k" * 32)
        token = other._tokens.issue("alice", ("mcp",), audience="https://other.example.com/mcp")

        self.assertIsNone(server.verify_bearer(f"Bearer {token.token}"))
        self.assertIsNone(server.verify_bearer("Bearer not-a-token"))
        self.assertIsNone(server.verify_bearer("Basic abc"))
        self.assertIsNone(server.verify_bearer(None))

    def test_tampered_login_request_is_rejected(self) -> None:
        server = _server()
        _, client = _register(server)
        page = _call(server, "GET", "/authorize", _authorize_query(client["client_id"]))
        signed = _signed_request(page.body)
        tampered = signed[:-2] + ("AA" if not signed.endswith("AA") else "BB")
        form = urlencode({"request": tampered, "username": "alice",
                          "password": "correct horse battery"}).encode()

        response = _call(server, "POST", "/authorize", body=form, headers=FORM)

        self.assertEqual(response.status_code, 400)

    def test_clients_and_refresh_tokens_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"
            server = _server(state=OAuthStateStore(path))
            _, client = _register(server)
            code, _ = _code_from(_login(server, client["client_id"]))
            tokens = json.loads(_exchange(server, client["client_id"], code).body)

            restarted = _server(state=OAuthStateStore(path))
            form = urlencode({"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                              "client_id": client["client_id"]}).encode()
            response = _call(restarted, "POST", "/token", body=form, headers=FORM)

            self.assertEqual(response.status_code, 200)
            self.assertNotIn(tokens["refresh_token"], path.read_text())

    def test_issuer_must_be_https_origin(self) -> None:
        for issuer in ("http://mcp.example.com", "https://mcp.example.com/mcp"):
            with self.subTest(issuer=issuer):
                with self.assertRaises(ValueError):
                    OAuthSettings(issuer=issuer)


class AdapterAuthTests(unittest.TestCase):
    def _adapter(self, **kwargs):
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
        config = load_gateway_config(
            ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json", policy
        )
        return HttpGatewayAdapter(config, **kwargs)

    def _mcp(self, headers=None, client_ip="203.0.113.10"):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {
            "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}}).encode()
        return HttpRequest("POST", "/mcp", {
            "content-type": "application/json", "origin": "https://chat.example",
            "mcp-protocol-version": PROTOCOL_VERSION, "mcp-method": "tools/list",
            **(headers or {}),
        }, body, client_ip=client_ip)

    def test_mcp_without_token_gets_401_challenge(self) -> None:
        response = self._adapter(auth=_server()).handle(self._mcp())

        self.assertEqual(response.status_code, 401)
        self.assertIn('resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"',
                      response.headers["www-authenticate"])
        self.assertNotIn("invalid_token", response.headers["www-authenticate"])

    def test_invalid_token_is_marked_in_challenge(self) -> None:
        response = self._adapter(auth=_server()).handle(
            self._mcp({"authorization": "Bearer forged"}))

        self.assertEqual(response.status_code, 401)
        self.assertIn('error="invalid_token"', response.headers["www-authenticate"])

    def test_valid_token_reaches_gateway(self) -> None:
        server = _server(clock=lambda: datetime.now(UTC))
        token = server._tokens.issue("alice", ("mcp",), audience=f"{ISSUER}/mcp")

        response = self._adapter(auth=server).handle(
            self._mcp({"authorization": f"Bearer {token.token}"}))

        self.assertEqual(response.status_code, 200)
        self.assertIn("company.search", response.body.decode())

    def test_oauth_endpoints_are_served_before_the_path_firewall(self) -> None:
        response = self._adapter(auth=_server()).handle(
            HttpRequest("GET", "/.well-known/oauth-authorization-server", {}, b"", "203.0.113.10"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)["issuer"], ISSUER)

    def test_without_auth_other_paths_stay_blocked(self) -> None:
        response = self._adapter().handle(
            HttpRequest("GET", "/.well-known/oauth-authorization-server", {}, b"", "203.0.113.10"))

        self.assertEqual(response.status_code, 404)

    def test_trusted_proxy_forwarded_for_sets_client_ip(self) -> None:
        adapter = self._adapter(trusted_proxies=("172.28.0.0/24",))
        trusted = HttpRequest("GET", "/x", {"x-forwarded-for": "198.51.100.9, 172.28.0.5"},
                              b"", "172.28.0.2")
        untrusted = HttpRequest("GET", "/x", {"x-forwarded-for": "198.51.100.9"},
                                b"", "203.0.113.10")

        self.assertEqual(adapter._client_ip(trusted), "198.51.100.9")
        self.assertEqual(adapter._client_ip(untrusted), "203.0.113.10")

    def test_server_refuses_public_bind_without_auth(self) -> None:
        for argv in (["--host", "0.0.0.0"], ["--host", "0.0.0.0", "--auth", "oauth"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    gateway_main(argv)


class UpstreamCredentialTests(unittest.TestCase):
    def test_rejects_literal_secrets_and_reserved_headers(self) -> None:
        with self.assertRaises(ValueError):
            UpstreamCredential(header="authorization", secret_ref="ghp_literal_token")
        with self.assertRaises(ValueError):
            UpstreamCredential(header="Mcp-Method", secret_ref="env:X")

    def test_missing_secret_fails_closed_as_value_error(self) -> None:
        credentials = UpstreamCredentials({
            "company-tools": UpstreamCredential("authorization", "env:MCP_GUARD_TEST_UNSET", "Bearer"),
        })
        upstream = UpstreamServer("company-tools", "company", ())
        os.environ.pop("MCP_GUARD_TEST_UNSET", None)

        with self.assertRaises(SecretUnavailable):
            credentials.headers_for(upstream)
        self.assertTrue(issubclass(SecretUnavailable, ValueError))

    def test_list_and_call_clients_send_gateway_credential_only(self) -> None:
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append(dict(self.headers.items()))
                if body["method"] == "tools/list":
                    result = {"resultType": "complete", "tools": [
                        {"name": "company.search", "description": "d", "inputSchema": {}}]}
                else:
                    result = {"content": [{"type": "text", "text": "ok"}]}
                data = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["MCP_GUARD_TEST_UPSTREAM"] = "upstream-secret"
        try:
            credentials = UpstreamCredentials({
                "company-tools": UpstreamCredential("authorization", "env:MCP_GUARD_TEST_UPSTREAM",
                                                    "Bearer"),
            })
            tool = ToolDefinition("company-tools", "company", "company.search", "d", {}, schema_hash=None)
            upstream = UpstreamServer("company-tools", "company", (tool,),
                                      url=f"http://127.0.0.1:{server.server_port}/mcp")
            HttpToolsListClient(header_provider=credentials.headers_for).fetch(upstream)
            HttpJsonRpcToolCallClient(header_provider=credentials.headers_for).call_tool(
                upstream, tool, {})
        finally:
            os.environ.pop("MCP_GUARD_TEST_UPSTREAM", None)
            server.shutdown()
            server.server_close()

        self.assertEqual(len(received), 2)
        for headers in received:
            lowered = {k.lower(): v for k, v in headers.items()}
            self.assertEqual(lowered["authorization"], "Bearer upstream-secret")


if __name__ == "__main__":
    unittest.main()
