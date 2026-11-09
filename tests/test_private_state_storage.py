"""Private folder setup for the single remote gateway."""

import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/01-policy-engine-cleanup", "mvp/02-remote-gateway-mcp",
               "mvp/03-server-registration-config", "mvp/04-tools-list-relay",
               "mvp/05-indirect-injection-throttle", "mvp/06-http-gateway-server"):
    sys.path.insert(0, str(ROOT / folder))

from http_gateway.state_storage import (  # noqa: E402
    check_legacy_state, default_state_dir, prepare_state_dir, verify_state_dir,
)
from http_gateway.server import main as gateway_main  # noqa: E402
from gateway_mvp.taint_exceptions import TaintExceptionStore  # noqa: E402


class PrivateStateTests(unittest.TestCase):
    def test_new_folder_is_private_and_legacy_state_is_copied(self):
        with tempfile.TemporaryDirectory() as base:
            old = Path(base) / "old"
            old.mkdir()
            (old / "stage0-approvals.json").write_text('{"approved": []}', encoding="utf-8")
            (old / "sessions").mkdir()
            (old / "sessions" / "taint.json").write_text('{"session_id": "a"}', encoding="utf-8")
            request = TaintExceptionStore(old).request(
                "alice", "session", "1", "mail:send_email", {"to": "boss@example.com"}, "mail:read")
            new = prepare_state_dir(Path(base) / "private", migrate_from=old)
            self.assertEqual(verify_state_dir(new), new)
            self.assertEqual(json.loads((new / "stage0-approvals.json").read_text(encoding="utf-8")),
                             {"approved": []})
            self.assertTrue((new / "sessions" / "taint.json").exists())
            self.assertEqual(TaintExceptionStore(new).open_for("alice")[0].request_id, request.request_id)
            self.assertTrue((old / "stage0-approvals.json").exists())
            if os.name != "nt":
                self.assertEqual(new.stat().st_mode & 0o777, 0o700)
                self.assertEqual((new / "sessions" / "taint.json").stat().st_mode & 0o777, 0o600)

    def test_insecure_folder_and_nonempty_destination_are_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            folder = Path(base) / "state"
            folder.mkdir()
            with self.assertRaises(PermissionError):
                verify_state_dir(folder)
            (folder / "keep.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                prepare_state_dir(folder)
            self.assertEqual((folder / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_parent_with_other_writers_is_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            parent = Path(base) / "writable-parent"
            parent.mkdir()
            if os.name == "nt":
                subprocess.run(["icacls", str(parent), "/grant",
                                "*S-1-1-0:(OI)(CI)M"], check=True, capture_output=True)
            else:
                parent.chmod(0o777)
            with self.assertRaises(PermissionError):
                prepare_state_dir(parent / "state")

    def test_migration_refuses_links(self):
        with tempfile.TemporaryDirectory() as base:
            old = Path(base) / "old"
            old.mkdir()
            secret = Path(base) / "outside.txt"
            secret.write_text("secret", encoding="utf-8")
            try:
                (old / "linked.txt").symlink_to(secret)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                prepare_state_dir(Path(base) / "private", migrate_from=old)

    def test_migration_refuses_destination_inside_source(self):
        with tempfile.TemporaryDirectory() as base:
            old = Path(base) / "old"
            old.mkdir()
            with self.assertRaises(ValueError):
                prepare_state_dir(old / "private", migrate_from=old)
            self.assertFalse((old / "private").exists())

    def test_gateway_requires_prepared_folder_and_keeps_paths_together(self):
        with tempfile.TemporaryDirectory() as base:
            insecure = Path(base) / "insecure"
            insecure.mkdir()
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit):
                gateway_main(["--state-dir", str(insecure)])
            self.assertIn("private state folder check failed", err.getvalue())

            private = prepare_state_dir(Path(base) / "private")
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit):
                gateway_main(["--state-dir", str(private)])
            self.assertIn("approval file is missing", err.getvalue())
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit):
                gateway_main(["--state-dir", str(private), "--approvals", "other.json"])
            self.assertIn("--migrate-from", err.getvalue())

            class NoNetworkServer:
                def serve_forever(self):
                    pass

                def server_close(self):
                    pass

            with patch("http_gateway.server.build_server", return_value=NoNetworkServer()):
                self.assertEqual(gateway_main(["--state-dir", str(private), "--enroll"]), 0)

    def test_default_start_stops_for_old_state_until_explicit_migration(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            old = root / ".mcp-guard"
            old.mkdir()
            (old / "stage0-approvals.json").write_text(
                '{"version": 1, "servers": []}', encoding="utf-8")
            app = root / "appdata"
            app.mkdir()
            env_name = "LOCALAPPDATA" if os.name == "nt" else "XDG_STATE_HOME"
            options = ["--policy", str(ROOT / "configs/example-policy.json"),
                       "--servers", str(ROOT / "mvp/03-server-registration-config/configs/servers.json")]
            with patch.dict(os.environ, {env_name: str(app)}), \
                    patch("http_gateway.server.Path.cwd", return_value=root):
                destination = default_state_dir()
                err = io.StringIO()
                with redirect_stderr(err), self.assertRaises(SystemExit):
                    gateway_main(options)
                self.assertIn("--migrate-from", err.getvalue())
                self.assertFalse(destination.exists())
                prepare_state_dir(destination, migrate_from=old)
                check_legacy_state(old, destination)
                self.assertTrue((old / "stage0-approvals.json").exists())
                class NoNetworkServer:
                    def serve_forever(self):
                        pass

                    def server_close(self):
                        pass

                with patch("http_gateway.server.build_server", return_value=NoNetworkServer()):
                    self.assertEqual(gateway_main([*options, "--enroll"]), 0)


if __name__ == "__main__":
    unittest.main()
