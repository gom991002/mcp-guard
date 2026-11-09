"""Korean evaluation set v2 and the cross-validated threshold choice (no model needed)."""

import json
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "mvp" / "11-b-classifier"))

from b_classifier.cv import choose_threshold, cross_validate, wilson  # noqa: E402
from b_classifier.evaluate import cv_report, load_samples  # noqa: E402

DATASET = ROOT / "mvp" / "11-b-classifier" / "datasets" / "ko_eval_v2.jsonl"


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.rows = load_samples(DATASET)

    def test_size_balance_and_review_state(self):
        self.assertEqual(Counter(r["label"] for r in self.rows), {"attack": 150, "benign": 150})
        self.assertEqual({r["lang"] for r in self.rows}, {"ko"})
        self.assertEqual({r["review"] for r in self.rows}, {"pending"})  # not yet checked by a person
        self.assertEqual(len({r["text"] for r in self.rows}), 300)

    def test_an_attack_sentence_never_spans_folds(self):
        folds = {}
        for row in self.rows:
            folds.setdefault(row["group"], set()).add(row["fold"])
        self.assertTrue(all(len(f) == 1 for f in folds.values()))
        self.assertEqual(Counter((r["label"], r["fold"]) for r in self.rows),
                         {(label, fold): 30 for label in ("attack", "benign") for fold in range(5)})

    def test_the_file_matches_its_generator(self):
        sys.path.insert(0, str(DATASET.parent))
        from make_ko_eval_v2 import build

        self.assertEqual(build(), self.rows)


class ThresholdTests(unittest.TestCase):
    def test_the_cap_is_kept_and_attacks_are_caught_as_far_as_it_allows(self):
        benign = [0.01 * i for i in range(100)]  # 0.00 .. 0.99
        threshold = choose_threshold([0.5, 0.97, 0.995], benign, 0.02)
        self.assertEqual(sum(b >= threshold for b in benign), 2)
        self.assertGreater(threshold, 0.97)
        self.assertEqual(sum(a >= threshold for a in (0.5, 0.97, 0.995)), 1)

    def test_out_of_fold_thresholds(self):
        rows = [{"fold": i % 5, "label": "attack", "kind": "k", "text": "a", "s": 0.9} for i in range(10)] + \
               [{"fold": i % 5, "label": "benign", "kind": "b", "text": "b", "s": 0.1} for i in range(100)]
        result = cross_validate(rows, "s")
        self.assertEqual((result["detection"]["rate"], result["false_positive"]["rate"]), (1.0, 0.0))
        self.assertEqual(len(result["thresholds"]), 5)

    def test_wilson_interval(self):
        low, high = wilson(0, 150)
        self.assertEqual(low, 0.0)
        self.assertLess(high, 0.03)

    def test_rules_only_report_runs_without_a_model(self):
        report = cv_report(load_samples(DATASET), None)
        self.assertEqual(set(report["results"]), {"rules"})
        self.assertEqual(report["results"]["rules"]["detection"]["total"], 150)


if __name__ == "__main__":
    unittest.main()
