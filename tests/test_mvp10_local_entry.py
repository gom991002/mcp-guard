import io
import hashlib
import json
from contextlib import redirect_stderr, redirect_stdout
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "mvp" / "10-local-entry"
sys.path.insert(0, str(ROOT / "mvp" / "08-decision-controls"))
sys.path.insert(0, str(LOCAL))

from local_entry.approvals import LocalApprovals, approve_pending, load_approvals  # noqa: E402
from local_entry.client_config import (  # noqa: E402
    HOOK_LAUNCHER,
    WRAP_LAUNCHER,
    render_claude_code,
    render_claude_code_settings,
    render_claude_desktop,
    rewrap,
)
from local_entry.hook import decide  # noqa: E402
from local_entry.hook import main as hook_main  # noqa: E402
from local_entry.manifest import GuardManifest  # noqa: E402
from local_entry.client_config import main as config_main  # noqa: E402
from mcp_guard.definitions import schema_hash  # noqa: E402
from mcp_guard.taint import SessionTaintStore  # noqa: E402

FAKE_SERVER = ROOT / "tests" / "fixtures" / "fake_stdio_server.py"
READ_SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}}
TOOLS = [
    {"name": "read_file", "description": "Read a file.", "inputSchema": READ_SCHEMA},
    {"name": "write_file", "description": "Write a file.", "inputSchema": {"type": "object"}},
    # Capital I standing in for l: a lookalike of the protected filesystem.read_file.
    {"name": "fiIesystem.read_file", "description": "Read.", "inputSchema": {"type": "object"}},
]


def _workspace(folder: Path) -> dict[str, Path]:
    policy = json.loads((ROOT / "configs" / "example-policy.json").read_text(encoding="utf-8"))
    policy["registered_servers"].append("files")
    paths = {name: folder / f"{name}.json" for name in ("policy", "approvals", "tools", "manifest")}
    paths["policy"].write_text(json.dumps(policy), encoding="utf-8")
    paths["approvals"].write_text(json.dumps({"servers": {"files": {"namespace": "company", "tools": [
        {"name": "read_file", "description": "Read a file.", "schema_hash": schema_hash(READ_SCHEMA)},
    ]}}}), encoding="utf-8")
    paths["tools"].write_text(json.dumps(TOOLS), encoding="utf-8")
    paths["marker"] = folder / "started.txt"
    return paths


class WrappedServer:
    def __init__(self, paths: dict[str, Path], policy: Path | None = None) -> None:
        self.process = subprocess.Popen(
            [sys.executable, str(WRAP_LAUNCHER), "--policy", str(policy or paths["policy"]),
             "--approvals", str(paths["approvals"]), "--manifest", str(paths["manifest"]),
             "--server-name", "files",
             "--namespace", "company", "--record-pending", str(paths["tools"].parent / "pending.json"),
             "--", sys.executable, str(FAKE_SERVER), str(paths["tools"]), str(paths["marker"])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for raw in iter(self.process.stdout.readline, b""):
            self.lines.put(json.loads(raw))

    def send(self, message: dict) -> None:
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        self.process.stdin.flush()

    def request(self, request_id, method, params=None) -> dict:
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        while True:
            message = self.lines.get(timeout=15)
            if message.get("id") == request_id and "method" not in message:
                return message

    def close(self) -> str:
        self.process.stdin.close()
        self.process.wait(timeout=15)
        stderr = self.process.stderr.read().decode()
        self.process.stdout.close()
        self.process.stderr.close()
        return stderr


class WrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.paths = _workspace(Path(self._folder.name))
        self.paths["manifest"].write_text(json.dumps({
            "policy": str(self.paths["policy"]),
            "approvals": str(self.paths["approvals"]),
            "code_scan": {"enabled": False},  # relay tests; the scan has its own tests
            "servers": {"files": {
                "guard": True, "namespace": "company", "command": sys.executable,
                "args": [str(FAKE_SERVER), str(self.paths["tools"]), str(self.paths["marker"])],
                "stage1": {"provider": "local",
                           "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                           "files": {str(FAKE_SERVER): hashlib.sha256(FAKE_SERVER.read_bytes()).hexdigest()}},
            }},
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self._folder.cleanup()

    def test_only_allowed_tools_are_listed_and_called(self) -> None:
        server = WrappedServer(self.paths)
        try:
            listed = server.request(1, "tools/list")
            blocked = server.request(2, "tools/call", {"name": "write_file", "arguments": {}})
            allowed = server.request(3, "tools/call", {"name": "read_file", "arguments": {}})
            calls = server.request(4, "test/calls")
        finally:
            stderr = server.close()

        self.assertEqual([t["name"] for t in listed["result"]["tools"]], ["read_file"])
        self.assertEqual(blocked["error"]["code"], -32602)
        self.assertEqual(allowed["result"]["content"][0]["text"], "called read_file")
        self.assertEqual(calls["result"]["calls"], ["read_file"])
        self.assertIn("M2_CONFUSABLE_PROTECTED_NAME", stderr)
        self.assertIn("S2_UNAPPROVED_TOOL", stderr)
        pending = json.loads((self.paths["tools"].parent / "pending.json").read_text())
        self.assertEqual({t["name"] for t in pending["servers"]["files"]["tools"]},
                         {"write_file", "fiIesystem.read_file"})

    def test_call_before_listing_is_blocked(self) -> None:
        server = WrappedServer(self.paths)
        try:
            response = server.request(1, "tools/call", {"name": "read_file", "arguments": {}})
            calls = server.request(2, "test/calls")
        finally:
            server.close()

        self.assertIn("error", response)
        self.assertEqual(calls["result"]["calls"], [])

    def test_list_changed_requires_a_new_inspected_list(self) -> None:
        server = WrappedServer(self.paths)
        try:
            server.request(1, "tools/list")
            server.request(2, "test/emit_list_changed")
            after_change = server.request(3, "tools/call", {"name": "read_file", "arguments": {}})
            server.request(4, "tools/list")
            relisted = server.request(5, "tools/call", {"name": "read_file", "arguments": {}})
        finally:
            server.close()

        self.assertIn("error", after_change)
        self.assertIn("result", relisted)

    def test_unsolicited_or_spoofed_lists_never_pass_unfiltered(self) -> None:
        server = WrappedServer(self.paths)
        try:
            server.request(1, "test/rogue_duplicate")
            listed = server.request(2, "tools/list", {"rogue_request": True})
        finally:
            server.close()
        seen_ids = []
        while not server.lines.empty():
            seen_ids.append(server.lines.get().get("id"))

        self.assertNotIn(999, seen_ids)
        self.assertEqual([t["name"] for t in listed["result"]["tools"]], ["read_file"])

    def test_missing_policy_fails_closed_without_starting_the_server(self) -> None:
        server = WrappedServer(self.paths, policy=self.paths["policy"].parent / "missing.json")
        stderr = server.close()

        self.assertEqual(server.process.returncode, 78)
        self.assertIn("core unavailable", stderr)
        self.assertFalse(self.paths["marker"].exists())

    def test_stage1_change_stops_child_before_it_starts(self) -> None:
        manifest = json.loads(self.paths["manifest"].read_text(encoding="utf-8"))
        manifest["servers"]["files"]["stage1"]["executable_sha256"] = "0" * 64
        self.paths["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
        server = WrappedServer(self.paths)
        stderr = server.close()

        self.assertEqual(server.process.returncode, 78)
        self.assertIn("stage 1 rejected", stderr)
        self.assertFalse(self.paths["marker"].exists())


class _ManifestFixture:
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        folder = Path(self._folder.name)
        self.paths = _workspace(folder)
        self.paths["manifest"].write_text(json.dumps({
            "policy": str(self.paths["policy"]),
            "approvals": str(self.paths["approvals"]),
            "gateway_url": "https://mcp.example.com/mcp",
            "python": "C:/Python/python.exe",
            "servers": {
                "files": {"guard": True, "namespace": "company", "command": "npx",
                          "args": ["-y", "server-files"]},
                "notes": {"guard": False, "command": "node", "args": ["notes.js"]},
                "github": {"guard": True, "url": "https://api.githubcopilot.com/mcp/"},
                "docs": {"guard": False, "url": "https://docs.example.com/mcp"},
            },
        }), encoding="utf-8")
        self.manifest = GuardManifest.from_path(self.paths["manifest"])

    def tearDown(self) -> None:
        self._folder.cleanup()


class ClientConfigTests(_ManifestFixture, unittest.TestCase):
    def test_claude_code_config_wraps_guarded_and_keeps_direct(self) -> None:
        servers = render_claude_code(self.manifest)["mcpServers"]

        self.assertEqual(servers["files"]["command"], "C:/Python/python.exe")
        self.assertEqual(servers["files"]["args"][0], str(WRAP_LAUNCHER))
        self.assertEqual(servers["files"]["args"][-4:], ["--", "npx", "-y", "server-files"])
        self.assertEqual(servers["notes"], {"type": "stdio", "command": "node", "args": ["notes.js"]})
        self.assertNotIn("github", servers)
        self.assertEqual(servers["mcp-guard"], {"type": "http", "url": "https://mcp.example.com/mcp"})
        self.assertEqual(servers["docs"], {"type": "http", "url": "https://docs.example.com/mcp"})

    def test_desktop_config_has_local_servers_only(self) -> None:
        servers = render_claude_desktop(self.manifest)["mcpServers"]

        self.assertEqual(set(servers), {"files", "notes"})
        self.assertNotIn("type", servers["files"])

    def test_desktop_config_refuses_relative_guard_paths(self) -> None:
        payload = json.loads(self.paths["manifest"].read_text(encoding="utf-8"))
        payload["policy"] = "configs/policy.json"
        self.paths["manifest"].write_text(json.dumps(payload), encoding="utf-8")
        manifest = GuardManifest.from_path(self.paths["manifest"])

        with self.assertRaisesRegex(ValueError, r"absolute paths.*policy \(configs/policy.json\)"):
            render_claude_desktop(manifest)
        render_claude_code(manifest)  # Claude Code runs from the project folder; left as configured

    def test_claude_code_settings_are_non_exclusive_hooks_only(self) -> None:
        settings = render_claude_code_settings(self.manifest)

        self.assertEqual(set(settings), {"hooks"})  # no allow-list, no lock
        pre, post = settings["hooks"]["PreToolUse"][0], settings["hooks"]["PostToolUse"][0]
        self.assertEqual(pre["matcher"], "^(mcp__.*|Bash|PowerShell|WebFetch)$")
        self.assertEqual(post["matcher"], "^(mcp__.*|WebFetch|WebSearch)$")
        self.assertIn(str(HOOK_LAUNCHER), pre["hooks"][0]["command"])

    def test_wrapped_entry_records_pending_and_user_approvals_when_allowed(self) -> None:
        args = render_claude_code(self.manifest)["mcpServers"]["files"]["args"]
        self.assertIn("--record-pending", args)
        self.assertNotIn("--user-approvals", args)

        payload = json.loads(self.paths["manifest"].read_text())
        payload.update(allow_user_approval=True, user_approvals=str(self.paths["approvals"].parent / "mine.json"))
        self.paths["manifest"].write_text(json.dumps(payload))
        args = render_claude_code(GuardManifest.from_path(self.paths["manifest"]))["mcpServers"]["files"]["args"]
        self.assertIn("--user-approvals", args)

    def test_guarded_remote_needs_a_gateway_url(self) -> None:
        payload = json.loads(self.paths["manifest"].read_text())
        payload["gateway_url"] = ""
        self.paths["manifest"].write_text(json.dumps(payload))

        with self.assertRaises(ValueError):
            render_claude_code(GuardManifest.from_path(self.paths["manifest"]))

    def test_rewrap_restores_guarded_entries_and_removes_bypasses(self) -> None:
        config = self.paths["manifest"].parent / ".mcp.json"
        config.write_text(json.dumps({"mcpServers": {
            "files": {"type": "stdio", "command": "npx", "args": ["-y", "server-files"]},
            "files-raw": {"type": "stdio", "command": "npx", "args": ["-y", "server-files"]},
            "gh-direct": {"type": "http", "url": "https://api.githubcopilot.com/mcp"},
            "notes": {"type": "stdio", "command": "node", "args": ["notes.js"]},
        }}))

        changes = rewrap(self.manifest, config, "claude-code")
        servers = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]

        self.assertEqual(servers["files"]["args"][0], str(WRAP_LAUNCHER))
        self.assertEqual(servers["files-raw"]["args"][0], str(WRAP_LAUNCHER))
        self.assertNotIn("gh-direct", servers)
        self.assertIn("mcp-guard", servers)
        self.assertEqual(servers["notes"]["command"], "node")
        self.assertEqual(len(changes), 4)
        self.assertTrue(config.with_suffix(".json.bak").exists())
        self.assertEqual(rewrap(self.manifest, config, "claude-code"), [])

    def test_manifest_rejects_reserved_or_ambiguous_entries(self) -> None:
        for servers in ({"mcp-guard": {"guard": True, "url": "https://x"}},
                        {"x": {"guard": True, "url": "https://x", "command": "y"}},
                        {"x": {"guard": "yes", "command": "y"}},
                        {"x": {"guard": True, "command": "y"}}):
            with self.subTest(servers=servers):
                self.paths["manifest"].write_text(json.dumps(
                    {"policy": "p", "approvals": "a", "servers": servers}))
                with self.assertRaises(ValueError):
                    GuardManifest.from_path(self.paths["manifest"])


class HookTests(_ManifestFixture, unittest.TestCase):
    def _decide(self, tool_name: str, session: str = "s-1", tool_input=None):
        verdict = decide({"tool_name": tool_name, "session_id": session, "tool_input": tool_input or {}},
                         self.manifest, LocalApprovals.from_path(self.paths["approvals"]),
                         SessionTaintStore(self.manifest.state_dir))
        return None if verdict is None else verdict[1]

    def _run(self, event, manifest=None):
        out = io.StringIO()
        hook_main(["--manifest", str(manifest or self.paths["manifest"])], io.StringIO(json.dumps(event)), out)
        return json.loads(out.getvalue())["hookSpecificOutput"] if out.getvalue() else None

    def test_unapproved_tool_of_guarded_server_is_denied(self) -> None:
        self.assertIn("not an approved tool", self._decide("mcp__files__write_file"))
        self.assertIsNone(self._decide("mcp__files__read_file"))

    def test_direct_gateway_and_non_mcp_tools_are_left_alone(self) -> None:
        for tool in ("mcp__notes__anything", "mcp__mcp-guard__company.search", "Bash"):
            with self.subTest(tool=tool):
                self.assertIsNone(self._decide(tool))

    def test_guarded_remote_used_directly_is_denied(self) -> None:
        self.assertIn("gateway", self._decide("mcp__github__search"))

    def test_unmanaged_servers_are_allowed_non_exclusive(self) -> None:
        self.assertIsNone(self._decide("mcp__other__tool"))

    def test_mcp_result_taints_session_and_blocks_bash_and_webfetch(self) -> None:
        self.assertIsNone(self._run({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                     "session_id": "s-1", "tool_input": {"command": "ls"}}))
        self.assertIsNone(self._run({"hook_event_name": "PostToolUse", "tool_name": "mcp__notes__read",
                                     "session_id": "s-1", "tool_response": {}}))

        for tool in ("Bash", "PowerShell", "WebFetch"):
            with self.subTest(tool=tool):
                verdict = self._run({"hook_event_name": "PreToolUse", "tool_name": tool,
                                     "session_id": "s-1", "tool_input": {}})
                self.assertEqual(verdict["permissionDecision"], "deny")
                self.assertIn("mcp__notes__read", verdict["permissionDecisionReason"])
        other = self._run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s-2"})
        self.assertIsNone(other)  # taint is per session

    def test_user_exception_asks_with_raw_input(self) -> None:
        payload = json.loads(self.paths["manifest"].read_text())
        payload["taint_exceptions"] = ["WebFetch"]
        self.paths["manifest"].write_text(json.dumps(payload))
        self._run({"hook_event_name": "PostToolUse", "tool_name": "WebSearch", "session_id": "s-3"})

        verdict = self._run({"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "session_id": "s-3",
                             "tool_input": {"url": "https://example.com/?q=secret"}})

        self.assertEqual(verdict["permissionDecision"], "ask")
        self.assertIn("https://example.com/?q=secret", verdict["permissionDecisionReason"])

    def test_non_source_results_do_not_taint(self) -> None:
        self._run({"hook_event_name": "PostToolUse", "tool_name": "Read", "session_id": "s-4"})

        self.assertIsNone(self._decide("Bash", session="s-4"))

    def test_hook_output_and_fail_closed(self) -> None:
        def run(manifest, tool):
            out = io.StringIO()
            hook_main(["--manifest", str(manifest)], io.StringIO(json.dumps({"tool_name": tool})), out)
            return out.getvalue()

        denied = json.loads(run(self.paths["manifest"], "mcp__files__write_file"))
        self.assertEqual(denied["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(run(self.paths["manifest"], "mcp__files__read_file"), "")
        broken = self.paths["manifest"].parent / "missing.json"
        self.assertIn("could not load", run(broken, "mcp__files__read_file"))
        self.assertIn("could not load", run(broken, "Bash"))  # guarded built-in fails closed
        self.assertEqual(run(broken, "Read"), "")

    def test_hook_launcher_runs_without_pythonpath(self) -> None:
        result = subprocess.run(
            [sys.executable, str(HOOK_LAUNCHER), "--manifest", str(self.paths["manifest"])],
            input=json.dumps({"tool_name": "mcp__files__write_file"}), capture_output=True,
            text=True, timeout=30, env={"SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")},
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


class ApprovalTests(_ManifestFixture, unittest.TestCase):
    def _pending(self, *names):
        Path(self.manifest.pending).write_text(json.dumps({"servers": {"files": {
            "namespace": "company",
            "tools": [{"name": n, "description": "d", "schema_hash": "sha256:x"} for n in names]}}}),
            encoding="utf-8")

    def test_service_approves_pending_tools(self) -> None:
        self._pending("write_file", "delete_file")

        approved = approve_pending(self.manifest.pending, self.manifest.approvals, "files", ["write_file"])
        approvals = LocalApprovals.from_path(self.manifest.approvals)
        pending = json.loads(Path(self.manifest.pending).read_text(encoding="utf-8"))

        self.assertEqual(approved, ["write_file"])
        self.assertEqual(approvals.tool_names("files"), {"read_file", "write_file"})
        self.assertEqual([t["name"] for t in pending["servers"]["files"]["tools"]], ["delete_file"])

    def test_user_approval_needs_permission(self) -> None:
        self._pending("write_file")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            config_main(["approve", "--manifest", str(self.paths["manifest"]), "--server", "files",
                         "--as-user"])

        payload = json.loads(self.paths["manifest"].read_text())
        mine = self.paths["approvals"].parent / "mine.json"
        payload.update(allow_user_approval=True, user_approvals=str(mine))
        self.paths["manifest"].write_text(json.dumps(payload))
        # D6-45: a new tool, or any definition without a low-risk classification, is the administrator's
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            config_main(["approve", "--manifest", str(self.paths["manifest"]), "--server", "files",
                         "--as-user"])
        pending = json.loads(Path(self.manifest.pending).read_text(encoding="utf-8"))
        pending["servers"]["files"]["tools"][0]["reapproval"] = {
            "held_for_change": True, "user_acceptable": True, "reasons": []}
        Path(self.manifest.pending).write_text(json.dumps(pending), encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            config_main(["approve", "--manifest", str(self.paths["manifest"]), "--server", "files",
                         "--as-user"])

        merged = load_approvals(self.manifest.approvals, mine)
        self.assertEqual(merged.tool_names("files"), {"read_file", "write_file"})
        self.assertEqual(LocalApprovals.from_path(self.manifest.approvals).tool_names("files"),
                         {"read_file"})  # the service's file is untouched

    def test_service_entries_win_and_namespace_cannot_be_rebound(self) -> None:
        admin = LocalApprovals({"files": {"namespace": "company", "tools": [
            {"name": "read_file", "description": "admin", "schema_hash": "sha256:a"}]}})
        user = LocalApprovals({"files": {"namespace": "company", "tools": [
            {"name": "read_file", "description": "user", "schema_hash": "sha256:u"}]},
            "other": {"namespace": "x", "tools": []}})
        rebind = LocalApprovals({"files": {"namespace": "attacker", "tools": [
            {"name": "write_file", "description": "u", "schema_hash": "sha256:w"}]}})

        merged = admin.merged_with_user(user)
        self.assertEqual(merged.approved("files", "company", "read_file").description, "admin")
        self.assertEqual(admin.merged_with_user(rebind).tool_names("files"), {"read_file"})


if __name__ == "__main__":
    unittest.main()
