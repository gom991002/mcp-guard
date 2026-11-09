"""Server trust tiers kept in the policy (state: "정책·신뢰 등급"), on both paths."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp", "mvp/08-decision-controls",
               "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from gateway_mvp.gateway import RemoteMcpGateway  # noqa: E402
from gateway_mvp.models import GatewayConfig, ToolDefinition, UpstreamServer  # noqa: E402
from mcp_guard.definitions import schema_hash  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from mcp_guard.taint import SessionTaintStore  # noqa: E402
from rule_sets.waf_gateway_rules import GatewayRequest, PROTOCOL_VERSION  # noqa: E402

READ = {"type": "object", "properties": {"q": {"type": "string"}}}


def _tool(server, name, description="Does a thing."):
    return ToolDefinition(server, "company", name, description, READ, schema_hash(READ))


class RegistryTests(unittest.TestCase):
    def test_tiers_default_to_standard_and_unknown_tiers_are_refused(self):
        registry = GuardRegistry.from_dict({"server_trust": {"clock": "trusted_output", "web": "restricted"}})
        self.assertEqual((registry.trust_tier("clock"), registry.trust_tier("web"), registry.trust_tier("mail")),
                         ("trusted_output", "restricted", "standard"))
        with self.assertRaises(ValueError):
            GuardRegistry.from_dict({"server_trust": {"clock": "trusted"}})


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        tools = {"clock": (_tool("clock", "now"),), "web": (_tool("web", "read_page", "Reads a page."),),
                 "mail": (_tool("mail", "lookup"),)}
        registry = GuardRegistry.from_dict({
            "trusted_namespaces": ["company"], "registered_servers": list(tools), "trusted_sources": ["gateway"],
            "approved_schema_hashes": {f"{s}:{t.name}": t.schema_hash for s, ts in tools.items() for t in ts},
            "server_trust": {"clock": "trusted_output", "web": "restricted"}})

        class Calls:
            def call_tool(self, upstream, tool, arguments):
                return {"content": [{"type": "text", "text": "data"}]}

        self.taint = SessionTaintStore(Path(self._folder.name))
        self.gateway = RemoteMcpGateway(
            GatewayConfig(registry, tuple(UpstreamServer(s, "company", ts) for s, ts in tools.items())),
            tool_call_client=Calls(), taint=self.taint)

    def tearDown(self):
        self._folder.cleanup()

    def _rpc(self, method, name="", session="s-1"):
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}
        headers = {"MCP-Protocol-Version": PROTOCOL_VERSION, "Mcp-Method": method}
        if name:
            params.update({"name": name, "arguments": {}})
            headers["Mcp-Name"] = name
        return self.gateway.handle(GatewayRequest(method="POST", body=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
            content_type="application/json", headers=headers), session_id=session).body

    def test_a_trusted_output_server_does_not_taint(self):
        self._rpc("tools/call", "now")
        self.assertIsNone(self.taint.get("s-1"))
        self._rpc("tools/call", "lookup")
        self.assertEqual(self.taint.get("s-1").first_source, "mail:lookup")

    def test_a_restricted_servers_descriptions_are_always_replaced(self):
        listed = self._rpc("tools/list")["result"]
        tools = {t["name"]: t for t in listed["tools"]}
        self.assertNotEqual(tools["read_page"]["description"], "Reads a page.")
        self.assertEqual(tools["lookup"]["description"], "Does a thing.")  # no sending tool: not sensitive
        self.assertEqual(listed["_meta"]["mcp_guard/descriptionsReplaced"], ["web:read_page"])


class HookTests(unittest.TestCase):
    def test_a_trusted_output_server_does_not_taint_a_claude_code_session(self):
        from local_entry.hook import record_result
        from local_entry.manifest import GuardManifest

        with tempfile.TemporaryDirectory() as folder:
            manifest_path = Path(folder) / "manifest.json"
            manifest_path.write_text(json.dumps({"policy": "p.json", "approvals": "a.json",
                                                 "state_dir": str(Path(folder) / "sessions"),
                                                 "servers": {}}), encoding="utf-8")
            manifest = GuardManifest.from_path(manifest_path)
            taint = SessionTaintStore(manifest.state_dir)
            registry = GuardRegistry.from_dict({"server_trust": {"clock": "trusted_output"}})
            record_result({"tool_name": "mcp__clock__now", "session_id": "s-1"}, manifest, taint, registry=registry)
            self.assertIsNone(taint.get("s-1"))
            record_result({"tool_name": "mcp__clock__now", "session_id": "s-1"}, manifest, taint, registry=None)
            self.assertIsNotNone(taint.get("s-1"))  # policy unreadable: taint as usual


if __name__ == "__main__":
    unittest.main()
