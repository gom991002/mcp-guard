"""D6-37: GuardDog per package, manifest metadata, import-time rules."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for folder in ("mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry import code_scan  # noqa: E402
from mcp_guard.b_score import score  # noqa: E402


class ManifestMetadataTests(unittest.TestCase):
    def test_npm_manifest_gaps(self) -> None:
        bare = code_scan.manifest_metadata("npm", ["index.js"], {"name": "x", "version": "0.0.0"})
        full = code_scan.manifest_metadata("npm", ["README.md", "index.js"], {
            "name": "x", "version": "1.2.0", "description": "Does x", "license": "MIT",
            "repository": {"type": "git", "url": "https://github.com/o/x"}})
        self.assertEqual(bare, {name: 1 for name in code_scan.META_FEATURES})
        self.assertEqual(full, {name: 0 for name in code_scan.META_FEATURES})

    def test_pypi_metadata_text(self) -> None:
        bare = "Metadata-Version: 2.1\nName: x\nVersion: 0.0.0\nSummary: UNKNOWN\nHome-page: UNKNOWN\nLicense: UNKNOWN\n\n"
        full = ("Metadata-Version: 2.1\nName: x\nVersion: 2.0\nSummary: Does x\n"
                "Project-URL: Source, https://github.com/o/x\nClassifier: License :: OSI Approved :: MIT License\n"
                "\nLong description here.\n")
        self.assertEqual(code_scan.manifest_metadata("pypi", [], metadata_text=bare),
                         {name: 1 for name in code_scan.META_FEATURES})
        self.assertEqual(code_scan.manifest_metadata("pypi", [], metadata_text=full),
                         {name: 0 for name in code_scan.META_FEATURES})


class GuardDogTests(unittest.TestCase):
    def _completed(self, payload: dict) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess([], 0, json.dumps(payload).encode(), b"")

    def test_result_and_features(self) -> None:
        payload = {"results": {"threat-network-exfil-sysinfo": [{"location": "a.js:1"}],
                               "capability-network-outbound": [{}], "capability-process-spawn": []},
                   "errors": {}, "risk_score": {"score": 8.2, "label": "high_risk"}}
        with mock.patch.object(code_scan.subprocess, "run", lambda *a, **k: self._completed(payload)):
            result = code_scan.run_guarddog_dir(Path("."), "npm")
        self.assertEqual(result["rules"], ["capability-network-outbound", "threat-network-exfil-sysinfo"])
        self.assertEqual(code_scan.guarddog_features(result),
                         {"GD_CAPABILITY": 1, "GD_THREAT": 1, "GD_RISK_LOW": 0, "GD_RISK_SUSPICIOUS": 0,
                          "GD_RISK_HIGH": 1})
        self.assertEqual(code_scan.guarddog_features(None), {n: 0 for n in code_scan.GD_FEATURES})

    def test_silent_guarddog_fails_the_canary(self) -> None:
        clean = {"results": {}, "errors": {}, "risk_score": {"score": 0, "label": "no_risks_detected"}}
        with mock.patch.object(code_scan.subprocess, "run", lambda *a, **k: self._completed(clean)):
            self.assertIn("canary", code_scan.guarddog_canary())
        with mock.patch.object(code_scan.subprocess, "run", side_effect=OSError("no docker")):
            self.assertIn("did not run", code_scan.guarddog_canary())

    def test_unavailable_guarddog_is_reported_not_silent(self) -> None:
        with mock.patch.object(code_scan, "guarddog_canary", lambda command=None: "no docker"):
            result = code_scan.guarddog_packages({"stage1": {"provider": "npm", "install_root": "."}}, {})
        self.assertEqual(result["status"], "unavailable")
        self.assertIn(code_scan.GUARDDOG_UNAVAILABLE, code_scan.GAP_CODES)

    def test_model_decision_does_not_lean_on_missing_guarddog(self) -> None:
        model = {"model": "t", "version": "v", "intercept": -2.0, "threshold": 0.5, "decision": "model",
                 "review_signals": ["install_script", "GD_RISK_HIGH"],
                 "weights": {"install_script": 0.5, "GD_RISK_HIGH": 4.0}, "means": {}}
        result = score({"install_script": 1, "GD_RISK_HIGH": 0}, model, missing=set(code_scan.GD_FEATURES))
        self.assertTrue(result["raise_review"])  # falls back to the review signals
        self.assertEqual(result["not_computed"], sorted(code_scan.GD_FEATURES))


class GuardDogDefaultTests(unittest.TestCase):
    def test_guarddog_is_on_unless_the_manifest_turns_it_off(self) -> None:  # D6-47
        from local_entry.manifest import GuardManifest

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            base = {"policy": "p.json", "approvals": "a.json", "servers": {}}
            path.write_text(json.dumps(base), encoding="utf-8")
            self.assertTrue(GuardManifest.from_path(path).code_scan["guarddog"]["enabled"])
            path.write_text(json.dumps({**base, "code_scan": {"guarddog": {"enabled": False}}}), encoding="utf-8")
            self.assertFalse(GuardManifest.from_path(path).code_scan["guarddog"]["enabled"])


class FeatureListTests(unittest.TestCase):
    def test_features_include_new_signals(self) -> None:
        for name in ("B_CODE_IMPORT_TIME_EXECUTION", *code_scan.META_FEATURES, *code_scan.GD_FEATURES):
            self.assertIn(name, code_scan.FEATURES)
        features = code_scan.package_features("x", "npm", ["index.js"], set(), {"name": "x"}, popular=())
        self.assertEqual(set(features), set(code_scan.FEATURES))


if __name__ == "__main__":
    unittest.main()
