import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "02-remote-gateway-mcp"))
sys.path.insert(0, str(ROOT / "mvp" / "07-tools-call-upstream-relay"))

from gateway_mvp.models import ToolDefinition, UpstreamServer  # noqa: E402
from tools_call_relay import HttpJsonRpcToolCallClient  # noqa: E402


class ToolsCallClientMvpTests(unittest.TestCase):
    # The per-call policy check runs in the gateway core (tests/test_mvp02_gateway.py);
    # this file covers the upstream HTTP client the gateway uses.

    def test_http_jsonrpc_client_posts_tool_call_to_upstream_url(self) -> None:
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received["headers"] = dict(self.headers.items())
                received["body"] = json.loads(body.decode("utf-8"))
                payload = {
                    "jsonrpc": "2.0",
                    "id": received["body"]["id"],
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                }
                data = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        try:
            tool = ToolDefinition(
                server_name="company-tools",
                namespace="company",
                name="company.search",
                description="Search approved company knowledge.",
                input_schema={},
                schema_hash="sha256:example",
            )
            upstream = UpstreamServer(
                name="company-tools",
                namespace="company",
                tools=(tool,),
                url=f"http://127.0.0.1:{server.server_port}/mcp",
            )
            response = HttpJsonRpcToolCallClient().call_tool(upstream, tool, {"query": "mcp"})
        finally:
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(response, {"content": [{"type": "text", "text": "ok"}]})
        self.assertEqual(received["body"]["method"], "tools/call")
        self.assertEqual(received["body"]["params"]["name"], "company.search")
        self.assertEqual(received["body"]["params"]["arguments"], {"query": "mcp"})
        self.assertEqual(received["headers"]["Mcp-Method"], "tools/call")
        self.assertEqual(received["headers"]["Mcp-Name"], "company.search")


if __name__ == "__main__":
    unittest.main()
