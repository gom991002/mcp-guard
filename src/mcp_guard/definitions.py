"""Stable hashes for observed MCP tool schemas."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def schema_hash(input_schema: dict[str, Any]) -> str:
    encoded = json.dumps(
        input_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
