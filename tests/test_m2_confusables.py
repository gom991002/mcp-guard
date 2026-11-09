import unittest

from mcp_guard.confusables import confusable_match, skeleton, tool_name_violations
from mcp_guard.models import RuleAction, ToolRegistration, Verdict
from mcp_guard.policy import evaluate_registration


def _register(tool_name: str, namespace: str = "company"):
    return evaluate_registration(
        ToolRegistration(
            server_name="helper",
            namespace=namespace,
            tool_name=tool_name,
            description="Search.",
            source="registry",
            schema_hash="sha256:example",
        )
    )


def _codes(decision) -> set[str]:
    return {finding.code for finding in decision.findings}


class SkeletonTests(unittest.TestCase):
    def test_cross_script_lookalikes_share_a_skeleton(self) -> None:
        # Cyrillic "е" (U+0435) and "ѕ" (U+0455) map to Latin "e" and "s".
        self.assertEqual(skeleton("github.ѕеarch"), skeleton("github.search"))

    def test_ascii_lookalikes_share_a_skeleton(self) -> None:
        # confusables.txt maps "I" and "1" to "l", and "m" to "rn".
        self.assertEqual(skeleton("fiIe"), skeleton("file"))
        self.assertEqual(skeleton("fi1e"), skeleton("file"))
        self.assertEqual(skeleton("rnail"), skeleton("mail"))

    def test_default_ignorables_are_removed(self) -> None:
        self.assertEqual(skeleton("github​.search"), skeleton("github.search"))

    def test_different_names_keep_different_skeletons(self) -> None:
        self.assertNotEqual(skeleton("github.search"), skeleton("gitlab.search"))

    def test_confusable_match_ignores_identical_names(self) -> None:
        self.assertIsNone(confusable_match("github.search", {"github.search"}))
        self.assertEqual(
            confusable_match("GitHub.Search", {"github.search"}), "github.search"
        )


class ToolNameViolationTests(unittest.TestCase):
    def test_mcp_recommended_names_pass(self) -> None:
        for name in ("getUser", "DATA_EXPORT_v2", "admin.tools.list"):
            with self.subTest(name=name):
                self.assertEqual(tool_name_violations(name), ())

    def test_reports_each_disallowed_character_once(self) -> None:
        self.assertEqual(tool_name_violations("a b cѕ"), ("U+0020", "U+0455"))

    def test_reports_length_over_128(self) -> None:
        self.assertEqual(tool_name_violations("a" * 129), ("length 129",))


class M2ConfusableRegistrationTests(unittest.TestCase):
    def test_blocks_cross_script_lookalike_even_from_trusted_namespace(self) -> None:
        decision = _register("github.ѕearch", namespace="company")

        self.assertEqual(decision.verdict, Verdict.BLOCK)
        finding = next(
            f for f in decision.findings if f.code == "M2_CONFUSABLE_PROTECTED_NAME"
        )
        self.assertEqual(finding.marker, "M2")
        self.assertEqual(finding.stage, "2-registration")
        self.assertEqual(finding.action, RuleAction.BLOCK)
        self.assertEqual(finding.evidence, "github.search")
        self.assertIn("M2_NONSTANDARD_TOOL_NAME", _codes(decision))

    def test_blocks_ascii_lookalike(self) -> None:
        decision = _register("fiIesystem.read_fiIe")

        self.assertEqual(decision.verdict, Verdict.BLOCK)
        self.assertEqual(_codes(decision), {"M2_CONFUSABLE_PROTECTED_NAME"})

    def test_blocks_case_variant(self) -> None:
        decision = _register("Slack.Send_Message")

        self.assertIn("M2_CONFUSABLE_PROTECTED_NAME", _codes(decision))

    def test_blocks_hidden_zero_width_character(self) -> None:
        decision = _register("github​.search")

        self.assertIn("M2_CONFUSABLE_PROTECTED_NAME", _codes(decision))

    def test_exact_protected_name_from_trusted_namespace_is_allowed(self) -> None:
        decision = _register("github.search", namespace="company")

        self.assertEqual(decision.verdict, Verdict.ALLOW)

    def test_unrelated_ascii_name_is_allowed(self) -> None:
        self.assertEqual(_register("company.lookup").verdict, Verdict.ALLOW)

    def test_non_ascii_name_without_lookalike_goes_to_review(self) -> None:
        decision = _register("회사.검색")

        self.assertEqual(decision.verdict, Verdict.REVIEW)
        self.assertEqual(_codes(decision), {"M2_NONSTANDARD_TOOL_NAME"})

    def test_empty_name_is_not_reported_twice(self) -> None:
        decision = _register(" ")

        self.assertIn("M2_EMPTY_TOOL_NAME", _codes(decision))
        self.assertNotIn("M2_NONSTANDARD_TOOL_NAME", _codes(decision))


if __name__ == "__main__":
    unittest.main()
