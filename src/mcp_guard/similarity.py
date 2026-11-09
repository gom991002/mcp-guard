"""Code fingerprints and a known-malware index (stage 1 B, D6-36).

Malware is often republished with small changes: a new package name, another
command-and-control address, renamed variables. A fingerprint keeps the shape
of the code and drops what such campaigns change most:

* comments and whitespace are removed;
* string and number literals become placeholders (addresses, keys, payloads);
* the rest (identifiers, keywords, operators) becomes a token sequence, cut
  into overlapping 5-token shingles.

A MinHash signature of the shingles estimates how much two files share
(Jaccard similarity); LSH bands find candidates without comparing every file.
The index stores signatures only, never code.

A match is review evidence only; it does not raise review or block by itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

SHINGLE = 5
PERMUTATIONS = 64
BANDS = 16  # 16 bands x 4 rows: candidates from about Jaccard 0.5 up
ROWS = PERMUTATIONS // BANDS
MIN_TOKENS = 40  # shorter files share boilerplate by chance
MAX_FILE_BYTES = 256_000  # payloads are small; large bundles are skipped
MATCH_JACCARD = 0.8
INDEX_PATH = Path(__file__).resolve().parent / "data" / "known_malware_index.json"

_PRIME = (1 << 61) - 1
_MASK = (1 << 64) - 1
_TOKEN = re.compile(r"""
    (?P<comment>//[^\n]*|/\*.*?\*/|\#[^\n]*)
  | (?P<string>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)
  | (?P<number>\b\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?\b|\b0[xX][0-9a-fA-F]+\b)
  | (?P<word>[A-Za-z_$][\w$]*)
  | (?P<op>[^\sA-Za-z0-9_$])
""", re.VERBOSE | re.DOTALL)


def _coefficients() -> list[tuple[int, int]]:
    # Fixed, reproducible hash family: the index and the scan must agree.
    result = []
    for i in range(PERMUTATIONS):
        digest = hashlib.sha256(f"mcp-guard-minhash-{i}".encode()).digest()
        a = int.from_bytes(digest[:8], "big") % (_PRIME - 1) + 1
        b = int.from_bytes(digest[8:16], "big") % _PRIME
        result.append((a, b))
    return result


_COEFFICIENTS = _coefficients()


def tokens(source: str) -> list[str]:
    out = []
    for match in _TOKEN.finditer(source):
        kind = match.lastgroup
        if kind == "comment":
            continue
        out.append("S" if kind == "string" else "N" if kind == "number" else match.group())
    return out


def signature(source: str) -> tuple[int, ...] | None:
    """MinHash signature, or None for a file too short to compare."""
    words = tokens(source)
    if len(words) < MIN_TOKENS:
        return None
    shingles = {hashlib.blake2b("\x1f".join(words[i:i + SHINGLE]).encode(), digest_size=8).digest()
                for i in range(len(words) - SHINGLE + 1)}
    values = [int.from_bytes(s, "big") for s in shingles]
    return tuple(min((a * v + b) % _PRIME for v in values) & _MASK for a, b in _COEFFICIENTS)


def file_signature(path: Path) -> tuple[int, ...] | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return signature(path.read_bytes().decode("utf-8", "replace"))
    except OSError:
        return None


def jaccard(left: tuple[int, ...], right: tuple[int, ...]) -> float:
    return sum(a == b for a, b in zip(left, right)) / PERMUTATIONS


def bands(sig: tuple[int, ...]) -> list[str]:
    return [hashlib.blake2b(repr((i, sig[i * ROWS:(i + 1) * ROWS])).encode(), digest_size=8).hexdigest()
            for i in range(BANDS)]


def encode(sig: tuple[int, ...]) -> str:
    return "".join(f"{v:016x}" for v in sig)


def decode(text: str) -> tuple[int, ...]:
    return tuple(int(text[i:i + 16], 16) for i in range(0, len(text), 16))


@dataclass(frozen=True)
class Match:
    label: str  # "package@version path" of the known file
    jaccard: float


class Index:
    """Signatures of known files with an LSH lookup."""

    def __init__(self, entries: Iterable[tuple[str, tuple[int, ...]]] = ()) -> None:
        self.labels: list[str] = []
        self.signatures: list[tuple[int, ...]] = []
        self.buckets: dict[str, list[int]] = {}
        for label, sig in entries:
            self.add(label, sig)

    def add(self, label: str, sig: tuple[int, ...]) -> None:
        position = len(self.labels)
        self.labels.append(label)
        self.signatures.append(sig)
        for key in bands(sig):
            self.buckets.setdefault(key, []).append(position)

    def best(self, sig: tuple[int, ...], threshold: float = MATCH_JACCARD) -> Match | None:
        candidates = {i for key in bands(sig) for i in self.buckets.get(key, ())}
        scored = [(jaccard(sig, self.signatures[i]), i) for i in candidates]
        scored = [(j, i) for j, i in scored if j >= threshold]
        if not scored:
            return None
        j, i = max(scored)
        return Match(self.labels[i], round(j, 4))

    def to_json(self, meta: dict[str, Any]) -> dict[str, Any]:
        return {**meta, "shingle": SHINGLE, "permutations": PERMUTATIONS, "bands": BANDS,
                "min_tokens": MIN_TOKENS, "match_jaccard": MATCH_JACCARD,
                "entries": [[label, encode(sig)] for label, sig in zip(self.labels, self.signatures)]}


@lru_cache(maxsize=2)
def load_index(path: str = str(INDEX_PATH)) -> Index | None:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if payload.get("permutations") != PERMUTATIONS or payload.get("shingle") != SHINGLE:
        return None  # made with other parameters: signatures are not comparable
    return Index((label, decode(sig)) for label, sig in payload.get("entries", []))
