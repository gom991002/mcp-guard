"""Pinned external fingerprint snapshots for the stage 1 advisory scan.

Only an explicitly pinned SHA-256 is trusted. Downloads happen on demand,
never during an MCP call or when loading a scan report.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from . import similarity

MAX_FEED_BYTES = 2_000_000


def validate_snapshot(raw: bytes) -> None:
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError("similarity feed exceeds size limit")
    try:
        payload = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise ValueError("similarity feed is not JSON") from error
    if not isinstance(payload, dict) or any(payload.get(key) != value for key, value in (
            ("model", "known-malware-similarity"), ("shingle", similarity.SHINGLE),
            ("permutations", similarity.PERMUTATIONS), ("bands", similarity.BANDS),
            ("min_tokens", similarity.MIN_TOKENS))):
        raise ValueError("similarity feed uses incompatible fingerprint parameters")
    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) > 5000:
        raise ValueError("similarity feed has invalid entry count")
    for entry in entries:
        if (not isinstance(entry, list) or len(entry) != 2 or
                not isinstance(entry[0], str) or not 0 < len(entry[0]) <= 500 or
                not isinstance(entry[1], str) or
                len(entry[1]) != similarity.PERMUTATIONS * 16 or
                any(char not in "0123456789abcdef" for char in entry[1])):
            raise ValueError("similarity feed has an invalid fingerprint")


def checked_snapshot(path: str | Path, expected_sha256: str, *,
                     validate_schema: bool = True) -> bytes:
    try:
        with Path(path).open("rb") as source:
            raw = source.read(MAX_FEED_BYTES + 1)
    except OSError as error:
        raise ValueError(f"similarity feed unavailable: {error}") from error
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("similarity feed SHA-256 differs from manifest pin")
    if validate_schema:
        validate_snapshot(raw)
    return raw


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("similarity feed redirects are not allowed")


def refresh(url: str, expected_sha256: str, destination: str | Path) -> dict[str, str]:
    parsed = urlparse(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.fragment or parsed.query):
        raise ValueError("similarity feed URL must be an HTTPS address without credentials or query")
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "mcp-guard-similarity-feed/0.1"})
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=20) as response:
        raw = response.read(MAX_FEED_BYTES + 1)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("downloaded similarity feed SHA-256 differs from manifest pin")
    validate_snapshot(raw)
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    # A failed download/validation leaves the previous snapshot intact.
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".similarity-", suffix=".tmp",
                                         delete=False) as stream:
            temp_name = stream.name
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, target)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    similarity.load_index.cache_clear()
    return {"sha256": expected_sha256, "path": str(target), "source": url}
