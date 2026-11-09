from __future__ import annotations

from dataclasses import dataclass
from re import Pattern

from mcp_guard.text_rules import TEXT_RULES

from .common import Match, Rule, RuleAction, RuleFamily, Severity


@dataclass(frozen=True)
class TextRule:
    rule: Rule
    patterns: tuple[Pattern[str], ...]

    def scan(self, text: str, field_name: str) -> Match | None:
        for pattern in self.patterns:
            match = pattern.search(text)
            if match:
                return Match(
                    rule=self.rule,
                    message=f"Suspicious text found in {field_name}.",
                    evidence=match.group(0),
                    metadata={"field": field_name},
                )
        return None


# B signals: "설명문 YARA · LLM" (stage 2) and "분류기 + LLM" (stage 3) in the
# drawings. They raise risk only. The definitions live in the engine of record
# (src/mcp_guard/text_rules.py, D6-39) and are wrapped here as YARA-style rules,
# so the draft and the engine cannot drift. Every rule scans every field here;
# the engine applies only the stage 2 rules to descriptions.
YARA_TEXT_RULES: tuple[TextRule, ...] = tuple(
    TextRule(
        rule=Rule(
            rule_id=spec.rule_id,
            family=RuleFamily.YARA_TEXT,
            title=spec.title,
            stage=spec.stage,
            marker="B",
            severity=Severity.WARNING,
            default_action=RuleAction.SIGNAL,
            description=spec.description,
            tags=spec.tags,
        ),
        patterns=spec.compiled,
    )
    for spec in TEXT_RULES
)


def scan_text(text: str, field_name: str = "text") -> list[Match]:
    matches: list[Match] = []
    for text_rule in YARA_TEXT_RULES:
        match = text_rule.scan(text, field_name)
        if match:
            matches.append(match)
    return matches
