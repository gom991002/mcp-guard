"""Stage 2 B: structural signals in a tool description (design discussion, 2026-11-04).

Word rules (text_rules.py) look for fixed phrases. Poisoned descriptions in
MCPTox mostly read like ordinary usage notes, so these signals look at what a
description does to *other* tools instead:

* B_DESCRIPTION_CROSS_TOOL_DIRECTIVE: names another tool of the same server
  next to an order about when or how to call it ("before using X you MUST
  first call Y").
* B_DESCRIPTION_ARGUMENT_TAMPERING: tells the model to change the input of a
  call ("modify the 'path' argument", "replace query with ...").
* B_DESCRIPTION_PRIORITY_CLAIM: claims to outrank the user or the system.

They are B signals: they can raise a decision to review and never block. The
patterns were written from the development half of MCPTox and the Docker
catalog only (mvp/11-b-classifier/b_text/eval_structure.py); the other half is the test.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_DIRECTIVE = re.compile(
    r"\b(must|should|always|never|required|requires|first|prior\s+to|automatically|whenever|mandatory|"
    r"need\s+to|have\s+to)\b", re.IGNORECASE)
# The other tool is the one being called ("you MUST first call 'move_file'")...
_CALLED = re.compile(r"\b(call|use|using|calling|invoke|invoking|execute|executing|run|running|trigger)\b",
                     re.IGNORECASE)
# ...not a tool this one is preferred to ("use this instead of 'execute_command'", deprecated notes).
_PREFERRED_TO = re.compile(r"(instead\s+of|rather\s+than|not|prefer\w*|over|deprecated|replaced\s+by|"
                           r"in\s+favou?r\s+of|rely\s+on)\W{0,4}\S{0,12}\W{0,3}$", re.IGNORECASE)
_TAMPER = re.compile(
    r"\b(modify|replace|change|set|override|redirect|rewrite|substitute|swap|append|prepend|"
    r"alter|force)\b[^.\n]{0,60}?\b(argument|arguments|parameter|parameters|param|field|value|"
    r"query|path|recipient|recipients|address|amount|url|destination)\b", re.IGNORECASE)
_CALL_CONTEXT = re.compile(r"\b(when|whenever|each\s+time|every\s+time)\s+(using|calling|invoking|you\s+(use|call))\b",
                           re.IGNORECASE)
_PRIORITY = re.compile(
    r"\bpriority\b[^.\n]{0,30}\b(higher|over|above|than)\b[^.\n]{0,30}\b(user|query|request|instruction|system)|"
    r"\b(takes?|has)\s+precedence\s+over\b|"
    r"\b(overrides?|supersedes?)\s+(the\s+|any\s+|all\s+)?(user|system|other)\b", re.IGNORECASE)
_WINDOW = 80


@dataclass(frozen=True)
class StructureHit:
    rule_id: str
    evidence: str


def description_signals(description: str, own_name: str = "", sibling_names: Iterable[str] = ()) -> list[StructureHit]:
    """Structural B signals of one tool description; ``sibling_names`` are the server's other tools."""
    hits: list[StructureHit] = []
    others = sorted({n for n in sibling_names if n and n != own_name and _distinctive(n)}, key=len, reverse=True)
    mentioned = []
    for name in others:
        for match in re.finditer(rf"(?<![\w-]){re.escape(name)}(?![\w-])", description):
            mentioned.append(match)
    for match in mentioned:
        before = description[max(0, match.start() - 30):match.start()]
        if _PREFERRED_TO.search(before) or not _CALLED.search(before[-25:]):
            continue
        window = description[max(0, match.start() - _WINDOW):match.end() + _WINDOW]
        if _DIRECTIVE.search(window):
            hits.append(StructureHit("B_DESCRIPTION_CROSS_TOOL_DIRECTIVE", window.strip()[:200]))
            break
    tamper = _TAMPER.search(description)
    if tamper and (mentioned or _CALL_CONTEXT.search(description)):
        hits.append(StructureHit("B_DESCRIPTION_ARGUMENT_TAMPERING", tamper.group(0)[:200]))
    priority = _PRIORITY.search(description)
    if priority:
        hits.append(StructureHit("B_DESCRIPTION_PRIORITY_CLAIM", priority.group(0)[:200]))
    return hits


def _distinctive(name: str) -> bool:
    """A tool name unlikely to be an ordinary word: has _ - . or a digit, or mixed case, or 12+ letters."""
    return bool(re.search(r"[_\-.\d]", name)) or (name != name.lower() and name != name.upper()) or len(name) >= 12
