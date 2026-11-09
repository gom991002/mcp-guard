"""Confusable-name detection for M2 (Unicode UTS #39 section 4).

Data: Unicode 18.0.0 ``confusables.txt`` in ``data/`` under the Unicode
License V3 (``data/UNICODE-LICENSE.txt``). Skeletons are a comparison key only;
UTS #39 says they are not a normalized form to store or display.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

_CONFUSABLES_PATH = Path(__file__).resolve().parent / "data" / "confusables.txt"

# Default_Ignorable_Code_Point from DerivedCoreProperties-18.0.0.txt, adjacent
# ranges merged. Removed before mapping, as internalSkeleton requires.
_DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

# MCP 2026-07-28 "Tool Names" (SHOULD): 1-128 characters, ASCII letters,
# digits, "_", "-", ".".
_MCP_TOOL_NAME_CHARS = re.compile(r"[A-Za-z0-9_.-]")
MCP_TOOL_NAME_MAX_LENGTH = 128


@lru_cache(maxsize=4096)
def skeleton(text: str) -> str:
    """UTS #39 internalSkeleton: NFD, drop default ignorables, map prototypes, NFD.

    The bidi step of bidiSkeleton is not applied; names with right-to-left
    characters already fail ``tool_name_violations``.
    """
    prototypes = _prototypes()
    mapped = "".join(
        prototypes.get(char, char)
        for char in unicodedata.normalize("NFD", text)
        if not _is_default_ignorable(char)
    )
    return unicodedata.normalize("NFD", mapped)


def confusable_match(name: str, candidates: Iterable[str]) -> str | None:
    """Return the first candidate that differs from ``name`` but looks the same."""
    for candidate in sorted(candidates):
        if candidate != name and _looks_alike(name, candidate):
            return candidate
    return None


# Beyond UTS #39 (D6-38) -----------------------------------------------------------
# UTS #39 finds characters that look the same. Tool names copied to impersonate
# another tool also change in ways a reader or a model skims over: separators
# and case (read_file / readFile), word order (file_read), one typo. These forms
# come from the typosquatting literature (TypoSmart's classes) and were chosen
# by evaluation on 755 real tool names (mvp/04-tools-list-relay/m2_names).

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def name_tokens(name: str) -> tuple[str, ...]:
    """Words of a tool name, lowercase: snake, kebab, dot and camel case split."""
    spaced = _CAMEL.sub("_", name)
    return tuple(t for t in re.split(r"[_.\-\s]+", spaced.lower()) if t)


def lookalike_name(name: str, candidates: Iterable[str], *, separators: bool = True,
                   reorder: bool = True, edit: str = "guarded") -> tuple[str, str] | None:
    """(candidate, how) for the first candidate ``name`` imitates, or None.

    ``how``: "skeleton" (UTS #39), "separators" (same words, other separators or
    case), "reordered" (same words, other order), "edit" (one insertion,
    deletion, swap or substitution). Identical names are not lookalikes: two
    servers may each have a ``search`` tool, and clients tell them apart by
    server (MCP 2026-07-28, Tool Names). ``edit``: "guarded" (5+ characters, 7+
    for a substitution), "any", or "off".
    """
    words = name_tokens(name)
    squashed = "".join(words)
    for candidate in sorted(set(candidates)):
        if candidate == name:
            continue
        if _looks_alike(name, candidate):
            return candidate, "skeleton"
        other = name_tokens(candidate)
        if separators and (other == words or skeleton("_".join(other)) == skeleton("_".join(words))):
            return candidate, "separators"
        if reorder and len(words) > 1 and sorted(other) == sorted(words):
            return candidate, "reordered"
        if edit != "off":
            target = "".join(other)
            if target != squashed and abs(len(target) - len(squashed)) <= 1 and _osa(squashed, target) == 1:
                substitution = len(target) == len(squashed) and not _swapped(squashed, target)
                minimum = 0 if edit == "any" else (7 if substitution else 5)
                if len(target) >= minimum:
                    return candidate, "edit"
    return None


def affix_extension_of(name: str, candidates: Iterable[str]) -> str | None:
    """The candidate ``name`` extends by one word, for approvers (D6-38 follow-up).

    ``my_get_device`` or ``get_device_pro`` extends ``get_device``. Only
    candidates of two or more words count: one-word names (``search``) are
    extended by many legitimate tools. Measured on 755 real tool names: 1.72%
    of benign tools match, so this is shown to the person approving a tool and
    is not a review signal; two extra words are not caught.
    """
    words = name_tokens(name)
    for candidate in sorted(set(candidates)):
        base = name_tokens(candidate)
        if candidate != name and len(base) >= 2 and len(words) == len(base) + 1 and \
                (words[1:] == base or words[:-1] == base):
            return candidate
    return None


def _swapped(left: str, right: str) -> bool:
    differ = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
    return (len(differ) == 2 and differ[1] == differ[0] + 1
            and left[differ[0]] == right[differ[1]] and left[differ[1]] == right[differ[0]])


def _osa(left: str, right: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    rows = [list(range(len(right) + 1))]
    for i, a in enumerate(left, 1):
        row = [i]
        for j, b in enumerate(right, 1):
            row.append(min(rows[-1][j] + 1, row[j - 1] + 1, rows[-1][j - 1] + (a != b)))
            if i > 1 and j > 1 and a == right[j - 2] and left[i - 2] == b:
                row[j] = min(row[j], rows[-2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def tool_name_violations(name: str) -> tuple[str, ...]:
    """List what keeps ``name`` outside the MCP tool name recommendation."""
    violations = [
        f"U+{ord(char):04X}"
        for char in dict.fromkeys(name)
        if not _MCP_TOOL_NAME_CHARS.fullmatch(char)
    ]
    if len(name) > MCP_TOOL_NAME_MAX_LENGTH:
        violations.append(f"length {len(name)}")
    return tuple(violations)


def _looks_alike(left: str, right: str) -> bool:
    # Case variants also count: the model picks tools by reading names, so
    # "GitHub.search" can pass for "github.search" (design discussion).
    return (
        skeleton(left) == skeleton(right)
        or skeleton(left.casefold()) == skeleton(right.casefold())
    )


def _is_default_ignorable(char: str) -> bool:
    code_point = ord(char)
    return any(start <= code_point <= end for start, end in _DEFAULT_IGNORABLE_RANGES)


@lru_cache(maxsize=1)
def _prototypes() -> dict[str, str]:
    table: dict[str, str] = {}
    for line in _CONFUSABLES_PATH.read_text(encoding="utf-8-sig").splitlines():
        data = line.split("#", 1)[0].strip()
        if not data:
            continue
        source, target, *_ = (field.strip() for field in data.split(";"))
        table[chr(int(source, 16))] = "".join(chr(int(cp, 16)) for cp in target.split())
    return table
