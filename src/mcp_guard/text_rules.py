"""B text rules (YARA-style) for tool descriptions and responses (D6-39).

The rule definitions live here, in the engine of record; the YARA-style draft
in mvp/01-policy-engine-cleanup/rule_sets builds its Rule objects from them, so
the two cannot drift. Every rule is a B signal: it raises a verdict to review
and never blocks.

Description rules (stage 2) look for text written to steer the model rather
than describe the tool: overriding instructions, collecting secrets, and hidden
or cross-tool instructions (the tool-poisoning pattern published by Invariant
Labs in April 2025: <IMPORTANT> blocks, "do not tell the user", "before using
tool X, first ..."). The response rule (stage 3) is not applied to descriptions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from re import Pattern


@dataclass(frozen=True)
class TextRuleSpec:
    rule_id: str
    stage: str
    title: str
    description: str
    tags: tuple[str, ...]
    patterns: tuple[str, ...]

    @property
    def compiled(self) -> tuple[Pattern[str], ...]:
        return _compile(self.patterns)


@lru_cache(maxsize=64)
def _compile(patterns: tuple[str, ...]) -> tuple[Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


PROMPT_OVERRIDE = TextRuleSpec(
    "B_DESCRIPTION_PROMPT_OVERRIDE", "2-registration", "Prompt override phrase",
    "Detects phrases that try to override model or guard policy.",
    ("prompt-injection", "tool-description"),
    # Fixed 2026-11-03 after the evaluation (post-hoc, reported separately):
    # "ignore the previous instructions" and synonyms were missed.
    (r"\bignore\s+((all|any|the|your|of)\s+)*(previous|prior|above|earlier|preceding)\s+"
     r"(instructions|prompts|rules|directions)\b",
     r"\bdisable\s+(the\s+)?guard\b",
     r"\bbypass\s+(security|approval|policy)\b"),
)
SECRET_HARVESTING = TextRuleSpec(
    "B_DESCRIPTION_SECRET_HARVESTING", "2-registration", "Secret harvesting phrase",
    "Detects text that asks the model to collect secrets or credential files.",
    ("secret", "credential", "tool-description"),
    # A secret word alone (e.g. "reset a password") is not enough; it needs a
    # collecting verb nearby, to keep approval load down.
    (r"\b(read|send|include|attach|forward|upload|collect|copy|paste)\b"
     r"[^.\n]{0,40}"
     r"\b(api[_ -]?keys?|access[_ -]?tokens?|passwords?|secrets?|credentials?)\b",
     r"(?<![\w.])\.env\b|\b(ssh[_ -]?key|private[_ -]?key|id_rsa)\b|~/\.(ssh|aws)\b",
     r"\bread\s+(credentials|secrets|environment\s+variables)\b"),
)
# Fixed on 2026-11-03 from the published tool-poisoning pattern, before the
# evaluation data was examined (mvp/11-b-classifier/b_text).
HIDDEN_INSTRUCTION = TextRuleSpec(
    "B_DESCRIPTION_HIDDEN_INSTRUCTION", "2-registration", "Hidden or cross-tool instruction",
    "Detects instructions hidden from the user or aimed at how the model uses other tools.",
    ("prompt-injection", "tool-poisoning", "tool-description"),
    (r"<\s*/?\s*(important|system|instructions?|secret|hidden)\s*>",
     r"\bdo\s+not\s+(tell|mention|inform|reveal|notify|show)\s+(this\s+to\s+)?(the\s+)?user\b",
     r"\b(the\s+)?user\s+(must|should)\s+not\s+(know|see|notice|be\s+told)\b",
     r"\bbefore\s+(using|calling|invoking|running)\s+(this|any|the|every)\b[^.\n]{0,40}\b(tool|function)\b",
     r"\b(instead\s+of|rather\s+than)\s+(using|calling)\s+(the\s+)?\S{1,60}\s+(tool|function)\b"),
)
RESPONSE_EXFIL = TextRuleSpec(
    "B_RESPONSE_EXFIL_TEXT", "3-response", "External exfiltration phrase",
    "Detects text that suggests sending data to an external target.",
    ("exfiltration", "response-contamination"),
    (r"\bsend\s+(it|data|content|secrets?)\s+to\s+https?://",
     r"\b(upload|post|forward)\s+.*\b(webhook|external\s+url)\b",
     r"\badd\s+(bcc|cc)\b"),
)

TEXT_RULES: tuple[TextRuleSpec, ...] = (PROMPT_OVERRIDE, SECRET_HARVESTING, HIDDEN_INSTRUCTION,
                                        RESPONSE_EXFIL)
DESCRIPTION_RULES = tuple(r for r in TEXT_RULES if r.stage == "2-registration")


@dataclass(frozen=True)
class TextHit:
    rule_id: str
    evidence: str
    start: int
    end: int


RESPONSE_RULES = tuple(r for r in TEXT_RULES if r.stage == "3-response")


def response_text(result: object) -> str:
    """The text parts of an MCP tools/call result."""
    content = result.get("content") if isinstance(result, dict) else None
    return "\n".join(part["text"] for part in content
                     if isinstance(part, dict) and isinstance(part.get("text"), str)) \
        if isinstance(content, list) else ""


def scan(text: str, rules: tuple[TextRuleSpec, ...] = DESCRIPTION_RULES) -> list[TextHit]:
    """The first match of each rule, in rule order."""
    hits = []
    for rule in rules:
        for pattern in rule.compiled:
            match = pattern.search(text)
            if match:
                hits.append(TextHit(rule.rule_id, match.group(0), match.start(), match.end()))
                break
    return hits
