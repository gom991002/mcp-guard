"""One-use local M4 approvals for calls held by the stdio wrapper."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

LIFETIME = 600


class LocalValueApprovals:
    def __init__(self, folder: str | Path) -> None:
        self.root = Path(folder) / "m4-value-approvals"

    def _id(self, server: str, tool: str, arguments: dict[str, Any]) -> str:
        raw = json.dumps([server, tool, arguments], sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def request(self, server: str, tool: str, arguments: dict[str, Any], codes: list[str]) -> str:
        ident = self._id(server, tool, arguments)
        path = self.root / "pending" / f"{ident}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {"server": server, "tool": tool, "arguments": arguments, "codes": codes,
                "created": time.time()}
        try:
            with path.open("x", encoding="utf-8") as out:
                json.dump(body, out, ensure_ascii=False)
        except FileExistsError:
            pass
        return ident

    def consume(self, server: str, tool: str, arguments: dict[str, Any]) -> bool:
        ident = self._id(server, tool, arguments)
        source = self.root / "approved" / f"{ident}.json"
        spent = self.root / "spent" / f"{ident}.json"
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            if time.time() - data["created"] > LIFETIME:
                source.unlink(missing_ok=True)
                return False
            spent.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, spent)
            spent.unlink(missing_ok=True)
            return True
        except (FileNotFoundError, ValueError, KeyError, OSError):
            return False

    def pending(self) -> list[tuple[str, dict[str, Any]]]:
        folder = self.root / "pending"
        if not folder.exists():
            return []
        out = []
        for path in folder.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if time.time() - data["created"] <= LIFETIME:
                    out.append((path.stem, data))
                else:
                    path.unlink(missing_ok=True)
            except (ValueError, KeyError, OSError):
                continue
        return out

    def approve(self, ident: str) -> bool:
        if len(ident) != 64 or any(c not in "0123456789abcdef" for c in ident):
            return False
        source = self.root / "pending" / f"{ident}.json"
        target = self.root / "approved" / f"{ident}.json"
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            if time.time() - data["created"] > LIFETIME:
                return False
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            return True
        except (FileNotFoundError, ValueError, KeyError, OSError):
            return False
