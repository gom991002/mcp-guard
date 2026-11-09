import json
import sys
import threading
import unittest
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "01-policy-engine-cleanup"))
sys.path.insert(0, str(ROOT / "mvp" / "02-remote-gateway-mcp"))
sys.path.insert(0, str(ROOT / "mvp" / "03-server-registration-config"))
sys.path.insert(0, str(ROOT / "mvp" / "05-indirect-injection-throttle"))
sys.path.insert(0, str(ROOT / "mvp" / "06-http-gateway-server"))

from http_gateway import HttpGatewayAdapter, HttpRequest, build_server  # noqa: E402
from injection_throttle import BanPolicy, RateRule, RequestRateThrottle, ThrottlePolicy  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from rule_sets.waf_gateway_rules import PROTOCOL_VERSION  # noqa: E402
from server_registry.loader import load_gateway_config  # noqa: E402


class HttpGatewayMvpTests(unittest.TestCase):
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)

    def _adapter(self, **kwargs):
        policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
        config = load_gateway_config(
            ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json",
            policy,
        )
        return HttpGatewayAdapter(config, **kwargs)

    def _body(self, method: str = "tools/list", params: dict[str, object] | None = None) -> bytes:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": {
                    **(params or {}),
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                    },
                },
            }
        ).encode("utf-8")

    def _headers(self, method: str = "tools/list") -> dict[str, str]:
        return {
            "content-type": "application/json",
            "origin": "https://chat.example",
            "mcp-protocol-version": PROTOCOL_VERSION,
            "mcp-method": method,
            "mcp-guard-session-id": "s-1",
        }

    def test_post_mcp_reaches_gateway_core(self) -> None:
        response = self._adapter().handle(
            HttpRequest(
                method="POST",
                path="/mcp",
                headers=self._headers(),
                body=self._body(),
                client_ip="203.0.113.10",
            ),
            now=self.now,
        )

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.body.decode("utf-8"))
        self.assertEqual(
            [tool["name"] for tool in body["result"]["tools"]],
            ["company.search", "helper.summarize"],
        )
        self.assertEqual(response.headers["mcp-guard-audit-events"], "3")

    def test_tools_call_can_use_injected_upstream_client(self) -> None:
        class RecordingClient:
            def __init__(self) -> None:
                self.calls = []

            def call_tool(self, upstream, tool, arguments):
                self.calls.append((upstream.name, tool.name, arguments))
                return {"content": [{"type": "text", "text": "from http upstream"}]}

        client = RecordingClient()
        response = self._adapter(tool_call_client=client).handle(
            HttpRequest(
                method="POST",
                path="/mcp",
                headers={**self._headers("tools/call"), "mcp-name": "company.search"},
                body=self._body("tools/call", {"name": "company.search", "arguments": {"query": "mcp"}}),
                client_ip="203.0.113.10",
            ),
            now=self.now,
        )

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.body.decode("utf-8"))
        self.assertEqual(
            body["result"],
            {"content": [{"type": "text", "text": "from http upstream"}]},
        )
        self.assertEqual(client.calls, [("company-tools", "company.search", {"query": "mcp"})])

    def test_options_preflight_does_not_parse_jsonrpc(self) -> None:
        response = self._adapter().handle(
            HttpRequest(
                method="OPTIONS",
                path="/mcp",
                headers={"origin": "https://chat.example"},
                client_ip="203.0.113.10",
            ),
            now=self.now,
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.body, b"")
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "https://chat.example",
        )

    def test_wrong_path_and_content_type_are_blocked_by_gateway_rules(self) -> None:
        wrong_path = self._adapter().handle(
            HttpRequest(
                method="POST",
                path="/direct",
                headers=self._headers(),
                body=self._body(),
                client_ip="203.0.113.10",
            ),
            now=self.now,
        )
        wrong_type = self._adapter().handle(
            HttpRequest(
                method="POST",
                path="/mcp",
                headers={**self._headers(), "content-type": "text/plain"},
                body=self._body(),
                client_ip="203.0.113.10",
            ),
            now=self.now,
        )

        self.assertEqual(wrong_path.status_code, 404)
        self.assertEqual(
            wrong_path.headers["mcp-guard-edge-findings"],
            "S0_GATEWAY_PATH_NOT_ALLOWED",
        )
        self.assertEqual(wrong_type.status_code, 415)
        self.assertEqual(
            wrong_type.headers["mcp-guard-edge-findings"],
            "S0_GATEWAY_UNSUPPORTED_MEDIA_TYPE",
        )

    def test_request_rate_feeds_ip_delay_middleware(self) -> None:
        adapter = self._adapter(
            throttle=RequestRateThrottle(
                ThrottlePolicy(rules=(RateRule("per-ip", window_seconds=60, limit=2),))
            ),
        )
        request = HttpRequest(
            method="POST",
            path="/mcp",
            headers=self._headers(),
            body=self._body(),
            client_ip="203.0.113.10",
        )

        first = adapter.handle(request, now=self.now)
        adapter.handle(request, now=self.now + timedelta(seconds=10))
        response = adapter.handle(request, now=self.now + timedelta(seconds=20))

        self.assertEqual(first.headers["mcp-guard-delay-seconds"], "0")
        self.assertEqual(response.headers["mcp-guard-delay-seconds"], "30.0")
        self.assertEqual(response.headers["retry-after"], "30")

    def test_client_that_keeps_getting_delayed_is_rejected_with_429(self) -> None:
        adapter = self._adapter(throttle=RequestRateThrottle(ThrottlePolicy(
            rules=(RateRule("per-ip", window_seconds=60, limit=1),),
            ban=BanPolicy(strikes=2),
        )))
        request = HttpRequest("POST", "/mcp", self._headers(), self._body(), client_ip="203.0.113.10")

        statuses = [adapter.handle(request, now=self.now + timedelta(seconds=i)).status_code
                    for i in range(4)]
        rejected = adapter.handle(request, now=self.now + timedelta(seconds=5))

        self.assertEqual(statuses[:2], [200, 200])
        self.assertEqual(rejected.status_code, 429)
        self.assertEqual(statuses[2:], [429, 429])  # banned at the 2nd strike (t=2) until t=602
        self.assertEqual(rejected.headers["retry-after"], "597")

    def test_standard_library_server_handles_one_http_request(self) -> None:
        server = build_server(("127.0.0.1", 0), self._adapter())
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/mcp"
            request = urllib.request.Request(
                url,
                data=self._body(),
                headers=self._headers(),
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["result"]["tools"][0]["name"], "company.search")
        finally:
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

