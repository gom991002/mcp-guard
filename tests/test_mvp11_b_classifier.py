import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mvp" / "11-b-classifier"))

from b_classifier.evaluate import evaluate, load_samples  # noqa: E402
from b_classifier.prompt_guard import _injection_index  # noqa: E402

DATASET = ROOT / "mvp" / "11-b-classifier" / "datasets" / "eval_ko_en.jsonl"


class EvaluationHarnessTests(unittest.TestCase):
    def test_unknown_label_is_rejected_instead_of_assuming_class_one(self) -> None:
        self.assertEqual(_injection_index({0: "SAFE", 1: "INJECTION"}), 1)
        with self.assertRaises(ValueError):
            _injection_index({0: "SAFE", 1: "OTHER"})
    def test_dataset_has_both_languages_and_labels(self) -> None:
        samples = load_samples(DATASET)
        pairs = {(s["lang"], s["label"]) for s in samples}

        self.assertEqual(pairs, {("ko", "attack"), ("ko", "benign"), ("en", "attack"), ("en", "benign")})
        self.assertTrue(all(s["text"].strip() and s["kind"] for s in samples))

    def test_rates_are_computed_per_language(self) -> None:
        samples = [
            {"lang": "ko", "label": "attack", "kind": "a", "text": "무시하고"},
            {"lang": "ko", "label": "attack", "kind": "b", "text": "조용히"},
            {"lang": "ko", "label": "benign", "kind": "c", "text": "무시하고 기본값"},
            {"lang": "en", "label": "benign", "kind": "d", "text": "hello"},
        ]
        report = evaluate(lambda text: 0.9 if "무시" in text else 0.1, samples, threshold=0.5)

        self.assertEqual(report["by_language"]["ko"]["detection_rate"], 0.5)
        self.assertEqual(report["by_language"]["ko"]["false_positive_rate"], 1.0)
        self.assertEqual(report["by_language"]["ko"]["missed"], ["b"])
        self.assertEqual(report["by_language"]["en"]["detection_rate"], None)
        self.assertEqual(report["by_language"]["all"]["false_positive_rate"], 0.5)


@unittest.skipUnless(os.environ.get("MCP_GUARD_RUN_PROMPT_GUARD"),
                     "set MCP_GUARD_RUN_PROMPT_GUARD=1 with transformers, torch and Hugging Face access")
class PromptGuardModelTests(unittest.TestCase):
    def test_real_model_scores_the_dataset(self) -> None:
        from b_classifier.prompt_guard import PromptGuardClassifier

        classifier = PromptGuardClassifier()
        report = evaluate(classifier.score, load_samples(DATASET))
        print(json.dumps(report["by_language"], ensure_ascii=False, indent=2))

        self.assertTrue(classifier.revision)


if __name__ == "__main__":
    unittest.main()
