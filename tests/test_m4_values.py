"""M4 value checks and one-use local approval before forwarding calls."""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp",
               "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from mcp_guard.m4_values import ValuePolicy, inspect_values
from mcp_guard.registry import GuardRegistry
from local_entry.approvals import LocalApprovals
from local_entry.value_approvals import LocalValueApprovals
from local_entry.wrapper import StdioGuard
from local_entry.hook import decide
from local_entry.manifest import GuardManifest
from gateway_mvp.gateway import RemoteMcpGateway
from gateway_mvp.models import GatewayConfig, ToolDefinition, UpstreamServer
from gateway_mvp.taint_exceptions import TaintExceptionStore
from mcp_guard.taint import SessionTaintStore
from rule_sets.waf_gateway_rules import GatewayRequest
from mcp_guard.protocol import PROTOCOL_VERSION


class ValuePolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = ValuePolicy.from_dict({
            "internal_domains": ["company.example"],
            "allowed_url_hosts": ["hooks.company.example"],
            "tool_fields": {"files:publish": {"visibility": ["share.level"]}},
        })

    def codes(self, args, tool="send"):
        return {f.code for f in inspect_values(self.policy, "files", tool, args)}

    def test_recipient_bcc_public_and_webhook(self):
        self.assertEqual(self.codes({"to": "alice@company.example"}), set())
        self.assertIn("M4_EXTERNAL_RECIPIENT", self.codes({"to": "a@outside.example"}))
        self.assertIn("M4_BCC_RECIPIENT", self.codes({"bcc": ["hidden@company.example"]}))
        self.assertIn("M4_PUBLIC_DESTINATION", self.codes({"share": {"level": "anyone_with_link"}}, "publish"))
        self.assertIn("M4_UNAPPROVED_URL", self.codes({"webhook": "https://outside.example/hook"}))
        self.assertEqual(self.codes({"webhook": "https://hooks.company.example/hook"}), set())

    def test_nested_and_malformed_destinations(self):
        findings = inspect_values(self.policy, "files", "send", {
            "payload": {"to": ["bad", "a@outside.example"], "url": "not a url"}})
        self.assertEqual({f.code for f in findings},
                         {"M4_DESTINATION_UNVERIFIABLE", "M4_EXTERNAL_RECIPIENT"})
        self.assertIn("M4_DESTINATION_UNVERIFIABLE", self.codes({"url": "https://[bad"}))
        self.assertTrue(all(f.marker == "M4" and f.stage == "4-containment" for f in findings))

    def test_bad_policy_rejected(self):
        with self.assertRaises(ValueError):
            ValuePolicy.from_dict({"tool_fields": {"files:send": {"unknown": ["x"]}}})


class LocalApprovalTests(unittest.TestCase):
    def test_wrapper_holds_then_allows_exact_input_once(self):
        with tempfile.TemporaryDirectory() as folder:
            store = LocalValueApprovals(folder)
            registry = GuardRegistry.from_dict({"m4_value_policy": {
                "internal_domains": ["company.example"], "allowed_url_hosts": []}})
            output = io.BytesIO()
            guard = StdioGuard("files", "company", registry, LocalApprovals({}), output,
                               log=io.StringIO(), value_approvals=store)
            guard._allowed.add("send")
            def call(args):
                return guard.from_client(json.dumps({"jsonrpc": "2.0", "id": 1,
                    "method": "tools/call", "params": {"name": "send", "arguments": args}}).encode())
            risky = {"to": "a@outside.example"}
            self.assertIsNone(call(risky))
            pending = store.pending()
            self.assertEqual(len(pending), 1)
            self.assertTrue(store.approve(pending[0][0]))
            self.assertIsNotNone(call(risky))
            self.assertIsNone(call(risky))
            self.assertIsNotNone(call({"to": "a@company.example"}))

    def test_claude_code_builtin_checks_value_before_any_taint(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy = root / "policy.json"
            policy.write_text(json.dumps({"m4_value_policy": {
                "internal_domains": [], "allowed_url_hosts": ["internal.example"]}}), encoding="utf-8")
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({"policy": str(policy),
                "approvals": str(root / "approvals.json"), "servers": {}}), encoding="utf-8")
            verdict = decide({"tool_name": "WebFetch", "tool_input": {
                "url": "https://outside.example/data"}}, GuardManifest.from_path(manifest_path),
                LocalApprovals({}), registry=GuardRegistry.from_path(policy))
            self.assertEqual(verdict[0], "ask")


class RemoteApprovalTests(unittest.TestCase):
    def test_untainted_call_needs_one_approval_and_taint_still_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            schema = {"type": "object", "properties": {"to": {"type": "string"}}}
            from mcp_guard.definitions import schema_hash
            tool = ToolDefinition("mail", "company", "send", "send", schema, schema_hash(schema))
            registry = GuardRegistry.from_dict({
                "trusted_namespaces": ["company"], "registered_servers": ["mail"],
                "trusted_sources": ["gateway"],
                "approved_schema_hashes": {"mail:send": tool.schema_hash},
                "m4_value_policy": {"internal_domains": ["company.example"], "allowed_url_hosts": []}})
            store = TaintExceptionStore(folder)
            calls = []
            class Client:
                def call_tool(self, upstream, selected, arguments):
                    calls.append(dict(arguments))
                    return {"content": [{"type": "text", "text": "ok"}]}
            taint = SessionTaintStore(Path(folder) / "sessions")
            gateway = RemoteMcpGateway(GatewayConfig(registry, (UpstreamServer("mail", "company", (tool,)),)),
                tool_call_client=Client(), exceptions=store, taint=taint,
                approval_url="https://gateway.example/approve")
            def call(args):
                message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "send", "arguments": args,
                    "_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}}
                return gateway.handle(GatewayRequest(method="POST", body=json.dumps(message).encode(),
                    content_type="application/json", headers={"MCP-Protocol-Version": PROTOCOL_VERSION,
                    "Mcp-Method": "tools/call", "Mcp-Name": "send"}), session_id="s1", user="alice")
            risky = {"to": "a@outside.example"}
            first = call(risky)
            self.assertIn("approval", first.body["error"]["data"])
            self.assertEqual(calls, [])
            (pending,) = store.open_for("alice")
            store.decide("alice", pending.request_id, True)
            self.assertIn("result", call(risky).body)
            self.assertEqual(calls, [risky])
            self.assertIn("error", call(risky).body)  # tainted, and no designated exception


if __name__ == "__main__":
    unittest.main()
