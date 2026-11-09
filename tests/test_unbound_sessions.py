import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for folder in (
    "mvp/01-policy-engine-cleanup",
    "mvp/02-remote-gateway-mcp",
    "mvp/03-server-registration-config",
    "mvp/04-tools-list-relay",
    "mvp/05-indirect-injection-throttle",
    "mvp/06-http-gateway-server",
    "mvp/07-tools-call-upstream-relay",
):
    sys.path.insert(0, str(ROOT / folder))

from http_gateway import unbound_sessions  # noqa: E402
from http_gateway.server import main as gateway_main  # noqa: E402
from http_gateway.state_storage import prepare_state_dir  # noqa: E402


def _confirm(flag=False, window=None, reply=None, tty=False):
    def prompt(_text):
        if reply is None:
            raise EOFError
        return reply
    lines = []
    how = unbound_sessions.confirm(flag, window=lambda: window, prompt=prompt,
                                   interactive=lambda: tty, out=lines.append)
    return how, lines


class ConfirmTests(unittest.TestCase):
    def test_flag_accepts_without_asking_but_still_warns(self) -> None:
        how, lines = _confirm(flag=True, window=False)
        self.assertEqual(how, "flag")
        self.assertIn("--auth oauth", lines[0])

    def test_window_answer_is_final(self) -> None:
        self.assertEqual(_confirm(window=True)[0], "window")
        # "No" in the window is not asked again in the terminal
        self.assertEqual(_confirm(window=False, reply="y", tty=True)[0], "")

    def test_terminal_when_no_window(self) -> None:
        self.assertEqual(_confirm(reply="y", tty=True)[0], "terminal")
        self.assertEqual(_confirm(reply="YES ", tty=True)[0], "terminal")
        for reply in ("", "n", "네", None):  # default no; EOF refuses
            with self.subTest(reply=reply):
                self.assertEqual(_confirm(reply=reply, tty=True)[0], "")

    def test_nobody_to_ask_refuses(self) -> None:
        self.assertEqual(_confirm(reply="y", tty=False)[0], "")

    def test_no_display_on_linux_means_no_window(self) -> None:
        with patch.object(unbound_sessions.sys, "platform", "linux"), \
                patch.dict(unbound_sessions.os.environ, {}, clear=True):
            self.assertIsNone(unbound_sessions.desktop_window())


class _FakeServer:
    def serve_forever(self):
        pass

    def server_close(self):
        pass


class GatewayStartTests(unittest.TestCase):
    def _run(self, folder: Path, extra: list[str]) -> int:
        policy, servers = folder / "policy.json", folder / "servers.json"
        policy.write_text(json.dumps({
            "trusted_namespaces": ["company"], "registered_servers": ["company-tools"],
            "trusted_sources": ["gateway"],
        }), encoding="utf-8")
        servers.write_text(json.dumps({"servers": [{
            "name": "company-tools", "namespace": "company", "transport": "streamable_http",
            "url": "http://127.0.0.1:1234/mcp", "source": "gateway", "tools": [],
        }]}), encoding="utf-8")
        state = prepare_state_dir(folder / "state")
        with patch("http_gateway.server.build_server", return_value=_FakeServer()), \
                patch("tools_list_relay.client.HttpToolsListClient.run_change_watcher"), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return gateway_main(["--policy", str(policy), "--servers", str(servers),
                                 "--state-dir", str(state),
                                 "--approvals", str(state / "approvals.json"),
                                 "--audit-log", str(state / "audit.jsonl"),
                                 "--live-tools", "--enroll", *extra])

    def _overrides(self, folder: Path) -> list[dict]:
        events = [json.loads(line) for line in
                  (folder / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        return [e for e in events if e["event_type"] == "startup_override"]

    def test_refuses_without_auth_when_nobody_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(unbound_sessions, "desktop_window", return_value=None), \
                patch.object(unbound_sessions.sys, "stdin", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self._run(Path(folder), [])
            self.assertEqual(raised.exception.code, 2)

    def test_window_yes_starts_and_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(unbound_sessions, "desktop_window", return_value=True):
            self.assertEqual(self._run(Path(folder), []), 0)
            [event] = self._overrides(Path(folder))
            self.assertEqual(event["details"]["accepted_by"], "window")
            self.assertEqual(event["details"]["override"], "unbound_sessions")

    def test_flag_starts_without_window(self) -> None:
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(unbound_sessions, "desktop_window") as window:
            self.assertEqual(self._run(Path(folder), ["--accept-unbound-sessions"]), 0)
            window.assert_not_called()
            self.assertEqual(self._overrides(Path(folder))[0]["details"]["accepted_by"], "flag")


if __name__ == "__main__":
    unittest.main()
