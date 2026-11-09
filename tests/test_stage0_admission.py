import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "01-policy-engine-cleanup"))
sys.path.insert(0, str(ROOT / "mvp" / "02-remote-gateway-mcp"))
sys.path.insert(0, str(ROOT / "mvp" / "03-server-registration-config"))
sys.path.insert(0, str(ROOT / "mvp" / "05-indirect-injection-throttle"))
sys.path.insert(0, str(ROOT / "mvp" / "06-http-gateway-server"))

from gateway_mvp.gateway import RemoteMcpGateway  # noqa: E402
from http_gateway.server import main as gateway_main  # noqa: E402
from http_gateway.state_storage import prepare_state_dir  # noqa: E402
from mcp_guard.admission import ServerIdentity, Stage0Admission  # noqa: E402
from mcp_guard.registry import GuardRegistry  # noqa: E402
from rule_sets.waf_gateway_rules import GatewayRequest, PROTOCOL_VERSION  # noqa: E402
from server_registry.loader import load_gateway_config  # noqa: E402


class Stage0AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = GuardRegistry.from_path(ROOT / "configs" / "example-policy.json")
        self.config = load_gateway_config(
            ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json",
            self.policy,
        )
        self.company = self.config.upstreams[0]
        self.identity = ServerIdentity(
            self.company.name, self.company.namespace, self.company.transport,
            self.company.url, self.company.source,
        )

    def _request(self, method="tools/call", name="company.search"):
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION}}
        headers = {"MCP-Protocol-Version": PROTOCOL_VERSION, "Mcp-Method": method}
        if method == "tools/call":
            params.update({"name": name, "arguments": {"query": "hi"}})
            headers["Mcp-Name"] = name
        return GatewayRequest(
            method="POST", content_type="application/json", headers=headers,
            body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        )

    def test_first_use_is_recorded_and_reused_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            admission = Stage0Admission(path, enroll=True)
            self.assertEqual(admission.check(self.identity, self.policy).verdict.value, "allow")
            self.assertEqual(admission.check(self.identity, self.policy).verdict.value, "allow")
            self.assertTrue(path.exists())
            self.assertEqual(
                Stage0Admission(path).check(self.identity, self.policy).verdict.value,
                "allow",
            )

    def test_changed_url_is_blocked_on_reconnect_until_explicit_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            admission = Stage0Admission(path, enroll=True)
            admission.check(self.identity, self.policy)
            changed = replace(self.identity, url="https://new.example/mcp")
            denied = Stage0Admission(path).check(changed, self.policy)
            self.assertEqual(denied.findings[0].code, "S0_SERVER_IDENTITY_CHANGED")
            self.assertEqual(admission.approve(changed, self.policy).verdict.value, "allow")
            self.assertEqual(Stage0Admission(path).check(changed, self.policy).verdict.value, "allow")
            self.assertEqual(Stage0Admission(path).check(self.identity, self.policy).verdict.value, "block")

    def test_unapproved_name_and_invalid_identity_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            admission = Stage0Admission(path, enroll=True)
            admission.check(self.identity, self.policy)
            self.assertEqual(
                Stage0Admission(path).check(
                    ServerIdentity("helper", "company", "streamable_http", "https://helper.example/mcp", "gateway"),
                    self.policy,
                ).findings[0].code,
                "S0_SERVER_NOT_APPROVED",
            )
            for invalid in (
                replace(self.identity, namespace="other"),
                replace(self.identity, url="http://remote.example/mcp"),
                replace(self.identity, source="untrusted"),
            ):
                self.assertEqual(admission.approve(invalid, self.policy).verdict.value, "block")

    def test_gateway_blocks_changed_identity_before_upstream_call(self):
        class RecordingClient:
            def __init__(self):
                self.calls = 0

            def call_tool(self, *args):
                self.calls += 1
                return {"content": []}

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            admission = Stage0Admission(path, enroll=True)
            admission.check(self.identity, self.policy)
            changed = replace(self.company, url="https://new.example/mcp")
            config = replace(self.config, upstreams=(changed, *self.config.upstreams[1:]))
            client = RecordingClient()
            gateway = RemoteMcpGateway(config, tool_call_client=client, admission=Stage0Admission(path))
            response = gateway.handle(self._request())
            self.assertEqual(response.body["error"]["code"], -32001)
            self.assertEqual(response.audit_events[0].finding_codes, ("S0_SERVER_IDENTITY_CHANGED",))
            self.assertEqual(client.calls, 0)
            listed = gateway.handle(self._request("tools/list"))
            self.assertNotIn("company.search", [t["name"] for t in listed.body["result"]["tools"]])

    def test_corrupt_approval_file_does_not_silently_reenroll(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            path.write_text('{"version": 1, "servers": [{"name": "company-tools"}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                Stage0Admission(path)

    def test_missing_record_does_not_auto_enroll_without_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            decision = Stage0Admission(path).check(self.identity, self.policy)
            self.assertEqual(decision.findings[0].code, "S0_SERVER_NOT_APPROVED")
            self.assertFalse(path.exists())

    def test_policy_revocation_blocks_even_with_recorded_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.json"
            Stage0Admission(path, enroll=True).check(self.identity, self.policy)
            admission = Stage0Admission(path)
            revoked = replace(self.policy, registered_servers=frozenset())
            decision = admission.check(self.identity, revoked)
            self.assertEqual(decision.findings[0].code, "S0_SERVER_IDENTITY_INVALID")

    def test_unwritable_approval_target_blocks_first_use(self):
        with tempfile.TemporaryDirectory() as directory:
            parent_file = Path(directory) / "not-a-directory"
            parent_file.write_text("occupied", encoding="utf-8")
            admission = Stage0Admission(parent_file / "approved.json", enroll=True)
            decision = admission.check(self.identity, self.policy)
            self.assertEqual(decision.findings[0].code, "S0_APPROVAL_STORE_UNAVAILABLE")

    def test_main_requires_first_enrollment_and_exposes_explicit_reapproval(self):
        with tempfile.TemporaryDirectory() as directory:
            state = prepare_state_dir(Path(directory) / "state")
            path = state / "approved.json"
            arguments = [
                "--policy", str(ROOT / "configs" / "example-policy.json"),
                "--servers", str(ROOT / "mvp" / "03-server-registration-config" / "configs" / "servers.json"),
                "--state-dir", str(state),
                "--approvals", str(path),
            ]
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
                gateway_main(arguments)
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(path.exists())
            with redirect_stdout(StringIO()):
                self.assertEqual(gateway_main(arguments + ["--approve-server", "company-tools"]), 0)
            self.assertEqual(Stage0Admission(path).check(self.identity, self.policy).verdict.value, "allow")


if __name__ == "__main__":
    unittest.main()
