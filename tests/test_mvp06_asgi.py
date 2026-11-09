import asyncio
import json
import socket
import sys
import threading
import time
import unittest
import urllib.request
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp",
    "mvp/03-server-registration-config", "mvp/05-indirect-injection-throttle",
    "mvp/06-http-gateway-server", "mvp/07-tools-call-upstream-relay",
):
    sys.path.insert(0, str(ROOT / folder))

from http_gateway import HttpGatewayAdapter  # noqa: E402
from http_gateway.asgi import GatewayAsgiApp  # noqa: E402
from injection_throttle.models import ThrottleDecision  # noqa: E402
from mcp_guard.audit import AuditRecorder, MemoryAuditSink  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from rule_sets.waf_gateway_rules import MAX_MCP_BODY_BYTES, PROTOCOL_VERSION  # noqa: E402
from server_registry.loader import load_gateway_config  # noqa: E402
from tools_call_relay.client import HttpJsonRpcToolCallClient  # noqa: E402


def _config():
    policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
    return load_gateway_config(
        ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json", policy)


def _list_body() -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {
        "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}}).encode()


HEADERS = [(b"content-type", b"application/json"), (b"origin", b"https://chat.example"),
           (b"mcp-protocol-version", PROTOCOL_VERSION.encode()), (b"mcp-method", b"tools/list")]


def _call(app, method="POST", body=b"", headers=HEADERS, chunks=None, client=("203.0.113.10", 5000)):
    """Run one HTTP request through the ASGI app; return (status, headers, body)."""
    parts = chunks or [body]
    messages = [{"type": "http.request", "body": part, "more_body": i < len(parts) - 1}
                for i, part in enumerate(parts)]
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": "/mcp", "query_string": b"",
             "headers": headers, "client": client}
    asyncio.run(app(scope, receive, send))
    start, body_message = sent
    return (start["status"], {k.decode(): v.decode() for k, v in start["headers"]},
            body_message["body"])


class _Throttle:
    def __init__(self, decision):
        self.decision = decision

    def check(self, ip, headers, now, signed_in=True):
        return self.decision


class AsgiAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sink = MemoryAuditSink()

    def _app(self, throttle=None, on_shutdown=None):
        adapter = HttpGatewayAdapter(_config(), throttle=throttle, sleep_on_delay=True,
                                     audit=AuditRecorder(self.sink))
        return GatewayAsgiApp(adapter, on_shutdown=on_shutdown)

    def test_tools_list_matches_the_adapter(self) -> None:
        status, headers, body = _call(self._app(), body=_list_body())

        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertIn("result", json.loads(body))
        self.assertEqual(self.sink.events[0].event_type, "registration_evaluated")

    def test_tools_call_consumes_upstream_sse_and_returns_one_json_result(self) -> None:
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["content-length"])))
                received.append(request)
                progress = {"jsonrpc": "2.0", "method": "notifications/progress",
                            "params": {"progress": 1, "message": "still running"}}
                final = {"jsonrpc": "2.0", "id": request["id"],
                         "result": {"content": [{"type": "text", "text": "completed"}]}}
                payload = ("data: " + json.dumps(progress) + "\n\n" +
                           "data: " + json.dumps(final) + "\n\n").encode()
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        try:
            config = _config()
            config = replace(config, upstreams=(replace(
                config.upstreams[0], url=f"http://127.0.0.1:{upstream.server_port}/mcp"),))
            adapter = HttpGatewayAdapter(
                config, tool_call_client=HttpJsonRpcToolCallClient(),
                audit=AuditRecorder(self.sink))
            request = {"jsonrpc": "2.0", "id": 77, "method": "tools/call", "params": {
                "name": "company.search", "arguments": {"query": "mcp"},
                "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}}
            headers = [(b"content-type", b"application/json"),
                       (b"origin", b"https://chat.example"),
                       (b"mcp-protocol-version", PROTOCOL_VERSION.encode()),
                       (b"mcp-method", b"tools/call"),
                       (b"mcp-name", b"company.search")]
            status, response_headers, body = _call(
                GatewayAsgiApp(adapter), body=json.dumps(request).encode(), headers=headers)
        finally:
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=5)

        self.assertEqual(status, 200)
        self.assertEqual(response_headers["content-type"], "application/json")
        self.assertEqual(json.loads(body), {"jsonrpc": "2.0", "id": 77,
                                          "result": {"content": [{"type": "text", "text": "completed"}]}})
        self.assertNotIn(b"still running", body)
        self.assertEqual(received[0]["method"], "tools/call")
        self.assertIn("upstream_call", [event.event_type for event in self.sink.events])

    def test_body_sent_in_chunks_is_joined(self) -> None:
        body = _list_body()
        status, _, _ = _call(self._app(), chunks=[body[:10], body[10:30], body[30:]])

        self.assertEqual(status, 200)

    def test_delay_is_awaited_once_without_a_sleeping_thread(self) -> None:
        delay = ThrottleDecision("203.0.113.10", True, 0.2, "per-ip", rule_name="per-ip")
        started = time.monotonic()
        status, headers, _ = _call(self._app(_Throttle(delay)), body=_list_body())
        elapsed = time.monotonic() - started

        self.assertEqual(status, 200)
        self.assertEqual(headers["mcp-guard-delay-seconds"], "0.2")
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 0.39)  # not slept a second time in the handler thread

    def test_ban_is_answered_before_the_gateway(self) -> None:
        ban = ThrottleDecision("203.0.113.10", False, 0.0, "banned", rejected=True,
                               retry_after_seconds=600)
        status, headers, _ = _call(self._app(_Throttle(ban)), body=_list_body())

        self.assertEqual(status, 429)
        self.assertEqual(headers["retry-after"], "600")
        self.assertEqual([e.event_type for e in self.sink.events], ["rate_limited"])

    def test_oversized_body_reaches_the_edge_rule(self) -> None:
        huge = b"x" * (MAX_MCP_BODY_BYTES + 5000)
        status, _, _ = _call(self._app(), chunks=[huge[:600_000], huge[600_000:]])

        self.assertEqual(status, 413)
        self.assertIn("S0_GATEWAY_BODY_TOO_LARGE", self.sink.events[-1].finding_codes)

    def test_preflight_is_answered(self) -> None:
        status, _, _ = _call(self._app(), method="OPTIONS")

        self.assertEqual(status, 204)

    def test_lifespan_shutdown_runs_the_shutdown_hook(self) -> None:
        called = []
        app = self._app(on_shutdown=lambda: called.append(True))
        messages = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        sent = []

        async def receive():
            return messages.pop(0)

        async def send(message):
            sent.append(message["type"])

        asyncio.run(app({"type": "lifespan"}, receive, send))

        self.assertEqual(sent, ["lifespan.startup.complete", "lifespan.shutdown.complete"])
        self.assertEqual(called, [True])


class UvicornTests(unittest.TestCase):
    def test_uvicorn_serves_the_app_with_the_socket_peer_as_client(self) -> None:
        try:
            import uvicorn
        except ImportError:
            self.skipTest("uvicorn is not installed")
        seen_ips = []

        class Recording:
            def check(self, ip, headers, now, signed_in=True):
                seen_ips.append(ip)
                return ThrottleDecision(ip, False, 0.0, "ok")

        app = GatewayAsgiApp(HttpGatewayAdapter(_config(), throttle=Recording()))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, proxy_headers=False, server_header=False,
            lifespan="on", log_level="warning"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.addCleanup(setattr, server, "should_exit", True)
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/mcp", data=_list_body(), method="POST",
            headers={k.decode(): v.decode() for k, v in HEADERS} | {"x-forwarded-for": "198.51.100.7"})
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read())
            server_header = response.headers.get("server")

        self.assertIn("result", payload)
        self.assertIsNone(server_header)
        # proxy_headers=False: a forged X-Forwarded-For does not become the client IP
        # (the adapter trusts it only from --trusted-proxy networks).
        self.assertEqual(seen_ips, ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
