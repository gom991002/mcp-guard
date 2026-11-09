"""OS isolation for guarded local servers (mvp/10-local-entry/local_entry/sandbox.py)."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("src", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry.manifest import GuardManifest  # noqa: E402
from local_entry.sandbox import describe, docker_command, validate  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_mvp10_local_entry import FAKE_SERVER, WrappedServer, _workspace  # noqa: E402

IMAGE = "python:3.12-slim"
SPEC = {"image": "node:22-slim@sha256:" + "a" * 64, "command": ["node", "/srv/index.js"],
        "mounts": [{"source": "C:/mcp/files", "target": "/srv"},
                   {"source": "C:/work", "target": "/work", "mode": "rw"}]}


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False)
    return probe.returncode == 0


class CommandTests(unittest.TestCase):
    def test_the_container_is_locked_down_by_default(self):
        argv = docker_command(SPEC, docker="docker")
        joined = " ".join(argv)
        for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                     "--pids-limit 128", "--memory 512m", "--user 65534:65534", "-i"):
            self.assertIn(flag, joined)
        self.assertIn("type=bind,source=C:/mcp/files,target=/srv,readonly", argv)
        self.assertIn("type=bind,source=C:/work,target=/work", argv)  # rw only when asked
        self.assertEqual(argv[-3:], [SPEC["image"], "node", "/srv/index.js"])
        self.assertEqual(describe(SPEC)["mounts"], ["/srv:ro", "/work:rw"])
        self.assertTrue(describe(SPEC)["image_pinned"])

    def test_bad_blocks_are_refused(self):
        for bad in ({"command": ["x"]}, {"image": "i"}, {"image": "-v", "command": ["x"]},
                    {**SPEC, "network": "host"}, {**SPEC, "memory": "lots"},
                    {**SPEC, "mounts": [{"source": "C:/x", "target": "relative"}]},
                    {**SPEC, "mounts": [{"source": "C:/x", "target": "/a/../etc"}]},
                    {**SPEC, "mounts": [{"source": "C:/x,y", "target": "/a"}]}):
            with self.assertRaises(ValueError, msg=bad):
                validate(bad)

    def test_the_manifest_checks_the_block(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "m.json"
            path.write_text(json.dumps({"policy": "p", "approvals": "a", "servers": {"files": {
                "guard": True, "namespace": "company", "command": "node", "sandbox": {"image": "x"}}}}),
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sandbox needs a command"):
                GuardManifest.from_path(path)


@unittest.skipUnless(_docker_ready(), f"needs Docker and the {IMAGE} image")
class DockerTests(unittest.TestCase):
    """The wrapper starts the verified server inside the container; MCP traffic still passes the guard."""

    def test_a_sandboxed_server_lists_only_approved_tools(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = _workspace(Path(folder))
            paths["manifest"].write_text(json.dumps({
                "policy": str(paths["policy"]), "approvals": str(paths["approvals"]),
                "code_scan": {"enabled": False},
                "servers": {"files": {
                    "guard": True, "namespace": "company", "command": sys.executable,
                    "args": [str(FAKE_SERVER), str(paths["tools"]), str(paths["marker"])],
                    "stage1": {"provider": "local",
                               "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                               "files": {str(FAKE_SERVER): hashlib.sha256(FAKE_SERVER.read_bytes()).hexdigest()}},
                    "sandbox": {"image": IMAGE,
                                "command": ["python", "/srv/fake_stdio_server.py", "/data/tools.json",
                                            "/data/started.txt"],
                                "mounts": [{"source": str(FAKE_SERVER.parent), "target": "/srv"},
                                           {"source": str(Path(folder)), "target": "/data", "mode": "rw"}]},
                }},
            }), encoding="utf-8")
            server = WrappedServer(paths)
            try:
                listed = server.request(1, "tools/list")
            finally:
                server.close()
            self.assertEqual([t["name"] for t in listed["result"]["tools"]], ["read_file"])
            self.assertTrue(paths["marker"].exists())  # written from inside the container


if __name__ == "__main__":
    unittest.main()
