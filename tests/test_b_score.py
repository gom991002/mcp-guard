"""Stage 1 B score (D6-35): combine B signals per package; raise to review only."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for folder in ("mvp/01-policy-engine-cleanup", "mvp/08-decision-controls", "mvp/10-local-entry"):
    sys.path.insert(0, str(ROOT / folder))

from local_entry import code_scan  # noqa: E402
from mcp_guard.b_score import MODEL_PATH, load_model, score  # noqa: E402

MODEL = {"model": "test", "version": "v1", "intercept": -3.0, "threshold": 0.5, "decision": "model",
         "weights": {"lookalike_name": 2.0, "install_script": 2.5, "B_CODE_PROCESS_EXECUTION": 0.5},
         "means": {"lookalike_name": 0.1, "install_script": 0.2, "B_CODE_PROCESS_EXECUTION": 0.4}}


class ScoreTests(unittest.TestCase):
    def test_signals_combine_and_contributions_explain_the_score(self) -> None:
        weak = score({"B_CODE_PROCESS_EXECUTION": 1, "lookalike_name": 0}, MODEL)
        strong = score({"lookalike_name": 1, "install_script": 1}, MODEL)

        self.assertFalse(weak["raise_review"])  # one weak signal alone stays a record
        self.assertTrue(strong["raise_review"])
        self.assertEqual(strong["contributions"], {"lookalike_name": 1.8, "install_script": 2.0})
        self.assertEqual(strong["signals"], ["install_script", "lookalike_name"])

    def test_rule_decision_raises_on_review_signals_and_records_the_rest(self) -> None:
        rule = {**MODEL, "decision": "rule", "review_signals": ["install_script", "B_CODE_PROCESS_EXECUTION"],
                "weights": {**MODEL["weights"], "B_CODE_ENV_HARVEST": 0.0}}
        held = score({"B_CODE_PROCESS_EXECUTION": 1}, rule)
        recorded = score({"B_CODE_ENV_HARVEST": 1}, rule)  # record-only signal

        self.assertTrue(held["raise_review"])
        self.assertLess(held["probability"], held["threshold"])  # the score only ranks it
        self.assertFalse(recorded["raise_review"])
        self.assertEqual(recorded["signals"], ["B_CODE_ENV_HARVEST"])

    def test_ecosystem_threshold_only_changes_that_ecosystem(self) -> None:
        model = {**MODEL, "threshold_by_ecosystem": {"pypi": 0.05}}
        npm = score({"B_CODE_PROCESS_EXECUTION": 1}, model, ecosystem="npm")
        pypi = score({"B_CODE_PROCESS_EXECUTION": 1}, model, ecosystem="pypi")

        self.assertEqual(npm["threshold"], 0.5)
        self.assertFalse(npm["raise_review"])
        self.assertEqual(pypi["threshold"], 0.05)
        self.assertTrue(pypi["raise_review"])

    def test_no_model_falls_back_to_any_signal(self) -> None:
        from unittest import mock

        with mock.patch("mcp_guard.b_score.load_model", lambda *a: None):
            result = score({"B_CODE_PROCESS_EXECUTION": 1})
            quiet = score({"B_CODE_PROCESS_EXECUTION": 0})
        self.assertTrue(result["raise_review"])
        self.assertEqual(result["model"], "rule-any-signal")
        self.assertFalse(quiet["raise_review"])

    def test_signal_the_model_never_saw_raises_review(self) -> None:
        result = score({"B_CODE_NEW_RULE": 1}, MODEL)
        self.assertTrue(result["raise_review"])
        self.assertEqual(result["untrained_signals"], ["B_CODE_NEW_RULE"])

    def test_without_guarddog_variant_decides_when_guarddog_did_not_run(self) -> None:
        with_gd = {**MODEL, "weights": {**MODEL["weights"], "GD_RISK_HIGH": 3.0},
                   "review_signals": ["lookalike_name", "install_script", "B_CODE_PROCESS_EXECUTION", "GD_RISK_HIGH"],
                   "without_guarddog": {"weights": {"lookalike_name": 2.0, "install_script": 4.0,
                                                    "B_CODE_PROCESS_EXECUTION": 0.5},
                                        "intercept": -3.0, "threshold": 0.5, "decision": "model",
                                        "review_signals": ["lookalike_name", "install_script"]}}
        features = {"install_script": 1, "B_CODE_PROCESS_EXECUTION": 0, "GD_RISK_HIGH": 0}
        missing = frozenset({"GD_RISK_HIGH"})

        variant = score(features, with_gd, missing=missing)
        no_variant = score(features, {k: v for k, v in with_gd.items() if k != "without_guarddog"},
                           missing=missing)

        self.assertEqual(variant["model"], "test-without-guarddog")
        self.assertEqual(variant["probability"], 0.7311)  # sigmoid(-3 + 4)
        self.assertTrue(variant["raise_review"])
        self.assertNotIn("untrained_signals", variant)
        self.assertTrue(no_variant["raise_review"])  # falls back to the review signals
        self.assertEqual(no_variant["model"], "test")
        quiet = score({"B_CODE_PROCESS_EXECUTION": 1}, with_gd, missing=missing)
        self.assertFalse(quiet["raise_review"])  # the variant's threshold decides, not the signal

    def test_tree_model_scores_and_contributions_add_up(self) -> None:
        import math

        # one boosted tree: install_script, then GD_RISK_HIGH; leaves in log-odds
        trees = {"model": "trees", "version": "t1", "kind": "gradient_boosting", "baseline": -2.0,
                 "columns": ["install_script", "GD_RISK_HIGH", "@pypi"],
                 "features": ["install_script", "GD_RISK_HIGH"], "threshold": 0.5, "decision": "model",
                 "review_signals": ["install_script", "GD_RISK_HIGH"],
                 "trees": [[[0, 0.5, 1, 2, 0.0], [-1, 0, 0, 0, 0.0], [1, 0.5, 3, 4, 0.0],
                            [-1, 0, 0, 0, 1.5], [-1, 0, 0, 0, 3.0]],
                           [[2, 0.5, 1, 2, 0.0], [-1, 0, 0, 0, 0.0], [-1, 0, 0, 0, -0.5]]],
                 "without_guarddog": {"kind": "logistic_by_ecosystem", "columns": ["install_script@npm",
                                                                                   "install_script@pypi", "@npm", "@pypi"],
                                      "weights": {"install_script@npm": 3.0, "install_script@pypi": 1.0,
                                                  "@npm": 0.0, "@pypi": 0.0},
                                      "intercept": -2.0, "threshold": 0.5, "decision": "model",
                                      "features": ["install_script"], "review_signals": ["install_script"]}}
        both = score({"install_script": 1, "GD_RISK_HIGH": 1}, trees, ecosystem="npm")
        pypi = score({"install_script": 1, "GD_RISK_HIGH": 1}, trees, ecosystem="pypi")

        self.assertEqual(both["probability"], round(1 / (1 + math.exp(-1.0)), 4))  # -2 + 3
        self.assertEqual(pypi["probability"], round(1 / (1 + math.exp(-0.5)), 4))  # ecosystem is an input
        self.assertTrue(both["raise_review"])
        self.assertAlmostEqual(sum(both["contributions"].values()), 1.0 - (-2.0), places=3)
        self.assertEqual(both["contributions"], {"GD_RISK_HIGH": 0.75, "install_script": 2.25})  # GD counts only after install_script

        npm = score({"install_script": 1}, trees, missing=frozenset({"GD_RISK_HIGH"}), ecosystem="npm")
        weak = score({"install_script": 1}, trees, missing=frozenset({"GD_RISK_HIGH"}), ecosystem="pypi")
        self.assertEqual(npm["model"], "trees-without-guarddog")
        self.assertEqual(npm["probability"], round(1 / (1 + math.exp(-1.0)), 4))
        self.assertTrue(npm["raise_review"])
        self.assertFalse(weak["raise_review"])  # weighed per ecosystem, not by the parent's trees
        self.assertNotIn("untrained_signals", weak)

    def test_shipped_model_matches_the_scan_features(self) -> None:
        model = load_model()
        if model is None:
            self.skipTest("no trained model shipped")
        self.assertEqual(model["features"], list(code_scan.FEATURES))
        self.assertTrue(0 < model["threshold"] < 1)
        self.assertTrue(all(0 < float(value) < 1
                            for value in model.get("threshold_by_ecosystem", {}).values()))
        variant = model.get("without_guarddog")
        if variant:
            from mcp_guard.b_score import _used

            self.assertFalse(_used(variant) & set(code_scan.GD_FEATURES))
            self.assertTrue(0 < variant["threshold"] < 1)
            self.assertTrue(all(0 < float(value) < 1
                                for value in variant.get("threshold_by_ecosystem", {}).values()))


class PackageFeatureTests(unittest.TestCase):
    def test_features_from_package_files(self) -> None:
        npm = code_scan.package_features("crossenv", "npm", ["index.js"], {"B_CODE_PROCESS_EXECUTION"},
                                         {"scripts": {"postinstall": "node x.js"}}, popular=("cross-env",))
        pypi = code_scan.package_features("tool", "pypi", ["evil.pth", "tool/__init__.py"], set(),
                                          popular=())

        self.assertEqual((npm["lookalike_name"], npm["install_script"],
                          npm["B_CODE_PROCESS_EXECUTION"]), (1, 1, 1))
        self.assertEqual(pypi["ships_pth"], 1)
        self.assertEqual(set(npm), set(code_scan.FEATURES))

    def test_scan_assigns_findings_to_installed_packages(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, scripts in (("good-lib", {}), ("bad-lib", {"preinstall": "node a.js"})):
                package = root / "node_modules" / name
                package.mkdir(parents=True)
                (package / "package.json").write_text(json.dumps(  # a complete manifest: no meta_* signal
                    {"name": name, "version": "1.0.0", "scripts": scripts, "description": "d",
                     "license": "MIT", "repository": "https://github.com/o/" + name}), encoding="utf-8")
                (package / "README.md").write_text("readme", encoding="utf-8")
                (package / "index.js").write_text("x", encoding="utf-8")
            body = {"findings": [{"code": "B_CODE_PROCESS_EXECUTION",
                                  "path": str(root / "node_modules" / "bad-lib" / "index.js")}]}
            entry = {"stage1": {"provider": "npm", "install_root": str(root)}}
            from unittest import mock

            with mock.patch("mcp_guard.b_score.load_model", lambda *a: MODEL):
                packages = code_scan.score_packages(entry, body)

        self.assertEqual([p["name"] for p in packages], ["bad-lib"])  # good-lib has no signal
        self.assertEqual(packages[0]["score"]["signals"], ["B_CODE_PROCESS_EXECUTION", "install_script"])


class ReviewTests(unittest.TestCase):
    def _report(self, packages, findings=()):
        return {"pin": "p", "rules_sha256": code_scan.rules_sha256(), "findings": list(findings),
                "packages": packages, "accepted": None}

    def test_only_held_packages_and_gaps_need_review(self) -> None:
        held = {"name": "bad", "version": "1", "score": score({"lookalike_name": 1, "install_script": 1}, MODEL)}
        quiet = {"name": "ok", "version": "1", "score": score({"B_CODE_PROCESS_EXECUTION": 1}, MODEL)}
        gap = {"code": code_scan.INCOMPLETE, "path": "x.js", "line": 0, "message": "m"}
        signal = {"code": "B_CODE_PROCESS_EXECUTION", "path": "y.js", "line": 1, "message": "m"}

        self.assertEqual(code_scan.review_items(self._report([quiet], [signal])), [])
        self.assertEqual(code_scan.review_items(self._report([held, quiet], [signal, gap])), [gap, held])
        self.assertEqual(code_scan.review_codes(self._report([held])), (code_scan.SCORE_HELD,))

    def test_acceptance_covers_the_held_items(self) -> None:
        held = {"name": "bad", "version": "1", "score": score({"lookalike_name": 1, "install_script": 1}, MODEL)}
        report = code_scan.accept(self._report([held]), "service", "me")
        self.assertEqual(report["accepted"]["findings_sha256"],
                         code_scan._sha256_json(code_scan.review_items(report)))

    def test_reports_before_scores_review_every_finding(self) -> None:
        signal = {"code": "B_CODE_PROCESS_EXECUTION", "path": "y.js", "line": 1, "message": "m"}
        legacy = {"findings": [signal]}
        self.assertEqual(code_scan.review_items(legacy), [signal])

    def test_unreadable_code_file_is_a_gap(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "a.js"
            target.write_text("x", encoding="utf-8")
            from unittest import mock

            real_open = Path.open

            def blocked(self, *args, **kwargs):
                if self == target.resolve():
                    raise OSError(22, "Invalid argument")
                return real_open(self, *args, **kwargs)

            with mock.patch.object(Path, "open", blocked):
                body = code_scan._parse({"findings": []}, {"version": "1", "results": [], "errors": [],
                                                           "paths": {"scanned": [str(target)]}},
                                        [Path(folder)], Path(folder))
        self.assertEqual([f["code"] for f in body["findings"]], [code_scan.INCOMPLETE])
        self.assertIn("antivirus", body["findings"][0]["message"])


if __name__ == "__main__":
    unittest.main()
