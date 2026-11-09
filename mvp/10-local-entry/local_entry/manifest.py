"""The user's per-server guard choice (yes/no), the source for L1, L3, and L4.

{
  "policy": "C:/mcp-guard/configs/policy.json",
  "approvals": "C:/mcp-guard/local-approvals.json",
  "pending": "C:/mcp-guard/pending.json",
  "allow_user_approval": false,
  "user_approvals": "C:/Users/me/.mcp-guard/user-approvals.json",
  "gateway_url": "https://mcp.example.com/mcp",
  "audit_log": "C:/mcp-guard/audit.jsonl",
  "taint_exceptions": [],
  "code_scan": {"enabled": true, "semgrep": "C:/mcp-guard/.venv/Scripts/semgrep.exe",
                "guarddog": {"enabled": true}},
  "review_assist": {"enabled": false, "base_url": "http://127.0.0.1:11434/v1", "model": "", "api_key_env": ""},
  "description_check": {"enabled": false, "base_url": "http://127.0.0.1:11434/v1", "model": "", "api_key_env": ""},
  "servers": {
    "files":  {"guard": true,  "namespace": "company", "command": "npx", "args": ["-y", "pkg"]},
    "notes":  {"guard": false, "command": "node", "args": ["notes.js"]},
    "github": {"guard": true,  "url": "https://api.githubcopilot.com/mcp/"}
  }
}

Configuration is non-exclusive (decision): users may add any other server;
only the guarded entries are wrapped, re-wrapped, and re-judged.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_guard.audit import AuditRecorder, JsonlAuditSink, decision_model, local_user

# Claude Code requires managed server names of letters, digits, "-" and "_".
_SERVER_NAME = re.compile(r"[A-Za-z0-9_-]+")
GATEWAY_SERVER_NAME = "mcp-guard"
# Tool results that bring third-party content into a session (M4 taint sources).
DEFAULT_TAINT_SOURCES = ("mcp__.*", "WebFetch", "WebSearch")
# Built-in Claude Code tools that can send data out; judged in tainted sessions (D6-07).
DEFAULT_GUARDED_BUILTINS = ("Bash", "PowerShell", "WebFetch")


@dataclass(frozen=True)
class GuardManifest:
    path: Path
    policy: str
    approvals: str
    pending: str
    user_approvals: str
    allow_user_approval: bool
    gateway_url: str
    python: str
    state_dir: str
    taint_sources: tuple[str, ...]
    guarded_builtins: tuple[str, ...]
    taint_exceptions: frozenset[str]
    servers: dict[str, dict[str, Any]]
    audit_log: str = ""
    # Stage 1 B code scan (D6-30): {"enabled": bool, "semgrep": path, "reports": dir, "timeout": s}
    code_scan: dict[str, Any] = field(default_factory=dict)
    # D6-36: advisory LLM summary for held items. {"enabled", "base_url", "model",
    # "api_key_env", "timeout"}; any OpenAI-compatible endpoint, local or remote.
    review_assist: dict[str, Any] = field(default_factory=dict)
    # D6-44: optional B description LLM check, same shape as review_assist.
    description_check: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_path(cls, path: str | Path) -> "GuardManifest":
        manifest_path = Path(path).resolve()
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        servers = payload.get("servers")
        if not isinstance(servers, dict):
            raise ValueError("manifest must contain a 'servers' object")
        for name, entry in servers.items():
            _validate(name, entry)
        approvals = str(payload["approvals"])
        allow_user = payload.get("allow_user_approval", False)
        if not isinstance(allow_user, bool):
            raise ValueError("allow_user_approval must be true or false")
        user_approvals = str(payload.get("user_approvals", ""))
        if allow_user and not user_approvals:
            raise ValueError("allow_user_approval needs a user_approvals path")
        for key in ("taint_sources", "guarded_builtins", "taint_exceptions"):
            value = payload.get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                raise ValueError(f"{key} must be a list of non-empty strings")
        for pattern in payload.get("taint_sources", []):
            re.compile(pattern)
        code_scan = payload.get("code_scan", {})
        if (not isinstance(code_scan, dict) or
                not isinstance(code_scan.get("enabled", True), bool) or
                not all(isinstance(code_scan.get(k, ""), str) for k in ("semgrep", "reports")) or
                not isinstance(code_scan.get("timeout", 600), int) or
                isinstance(code_scan.get("timeout"), bool)):
            raise ValueError("code_scan needs enabled (bool), semgrep and reports (str), timeout (int)")
        assist = payload.get("review_assist", {})
        if not isinstance(assist, dict) or not isinstance(assist.get("enabled", False), bool) or \
                not all(isinstance(assist.get(k, ""), str) for k in ("base_url", "model", "api_key_env")):
            raise ValueError("review_assist needs enabled (bool), base_url, model, api_key_env (str)")
        check = payload.get("description_check", {})
        if not isinstance(check, dict) or not isinstance(check.get("enabled", False), bool) or                 not all(isinstance(check.get(k, ""), str) for k in ("base_url", "model", "api_key_env")):
            raise ValueError("description_check needs enabled (bool), base_url, model, api_key_env (str)")
        guarddog = code_scan.get("guarddog", {})
        if not isinstance(guarddog, dict) or not isinstance(guarddog.get("enabled", False), bool) or \
                not isinstance(guarddog.get("command", []), list) or \
                not all(isinstance(part, str) for part in guarddog.get("command", [])):
            raise ValueError("code_scan.guarddog needs enabled (bool) and command (list of str)")
        feed = code_scan.get("similarity_feed", {})
        if not isinstance(feed, dict):
            raise ValueError("code_scan.similarity_feed must be an object")
        if feed:
            from urllib.parse import urlparse

            url = feed.get("url")
            digest = feed.get("sha256")
            path = feed.get("path")
            parsed = urlparse(url) if isinstance(url, str) else None
            if (not isinstance(path, str) or not path or
                    not isinstance(digest, str) or len(digest) != 64 or
                    any(ch not in "0123456789abcdef" for ch in digest) or
                    parsed is None or parsed.scheme != "https" or not parsed.hostname or
                    parsed.username or parsed.password or parsed.fragment or parsed.query):
                raise ValueError("code_scan.similarity_feed needs path, HTTPS url, and SHA-256 pin")
        code_scan = {"enabled": code_scan.get("enabled", True),  # on by default (D6-30)
                     # D6-37: GuardDog per package; command defaults to its Docker image.
                     # D6-47: on by default; set enabled false where Docker is not available.
                     "guarddog": {"enabled": guarddog.get("enabled", True),
                                  "command": guarddog.get("command", []),
                                  "workers": guarddog.get("workers", 4)},
                     "semgrep": code_scan.get("semgrep", ""),
                     "similarity_feed": feed,
                     "reports": code_scan.get("reports") or str(manifest_path.with_name("code-scans")),
                     "timeout": code_scan.get("timeout", 600)}
        return cls(
            path=manifest_path,
            policy=str(payload["policy"]),
            approvals=approvals,
            pending=str(payload.get("pending") or Path(approvals).with_name("pending.json")),
            user_approvals=user_approvals,
            allow_user_approval=allow_user,
            gateway_url=str(payload.get("gateway_url", "")),
            python=str(payload.get("python") or sys.executable),
            state_dir=str(payload.get("state_dir") or manifest_path.with_name("sessions")),
            taint_sources=tuple(payload.get("taint_sources") or DEFAULT_TAINT_SOURCES),
            guarded_builtins=tuple(payload.get("guarded_builtins") or DEFAULT_GUARDED_BUILTINS),
            taint_exceptions=frozenset(payload.get("taint_exceptions", [])),
            servers=servers,
            audit_log=str(payload.get("audit_log", "")),
            code_scan=code_scan,
            review_assist={"enabled": assist.get("enabled", False), "base_url": assist.get("base_url", ""),
                           "model": assist.get("model", ""), "api_key_env": assist.get("api_key_env", ""),
                           "timeout": assist.get("timeout", 60)},
            description_check={"enabled": check.get("enabled", False), "base_url": check.get("base_url", ""),
                               "model": check.get("model", ""), "api_key_env": check.get("api_key_env", ""),
                               "timeout": check.get("timeout", 120)},
        )

    def b_scored_elsewhere(self) -> frozenset[str]:
        """Lock signals the code scan's B score weighs when the scan is on (D6-35)."""
        if not self.code_scan.get("enabled"):
            return frozenset()
        from mcp_guard.dependencies import SCORED_BY_CODE_SCAN

        return SCORED_BY_CODE_SCAN

    def guarded_local(self) -> dict[str, dict[str, Any]]:
        return {n: e for n, e in self.servers.items() if e["guard"] and "command" in e}

    def audit_recorder(self, client: str = "") -> AuditRecorder:
        if not self.audit_log:
            return AuditRecorder()
        return local_recorder(self.audit_log, client, local_decision_model({
            "manifest": self.path, "policy": self.policy, "approvals": self.approvals,
            "user_approvals": self.user_approvals if self.allow_user_approval else None,
        }))


def local_decision_model(files: dict[str, Any]) -> dict[str, Any]:
    """Core engine and local entry code, plus the configuration files that decide."""
    return decision_model(files=files, sources={"local_entry": Path(__file__).resolve().parent})


# D6-24: audit logs are kept six months; local logs stay on the machine (D6-24).
AUDIT_RETENTION_DAYS = 180


def local_recorder(path: str, client: str = "", model: dict[str, Any] | None = None,
                   session_id: str = "") -> AuditRecorder:
    """M1 recorder for the local path; no path means auditing is off."""
    if not path:
        return AuditRecorder()
    return AuditRecorder(JsonlAuditSink(path, retention_days=AUDIT_RETENTION_DAYS), path="local",
                         user=local_user(), client=client, decision_model=model or {},
                         session_id=session_id)


def _validate(name: str, entry: Any) -> None:
    if not _SERVER_NAME.fullmatch(name) or name == GATEWAY_SERVER_NAME:
        raise ValueError(f"invalid or reserved server name: {name!r}")
    if not isinstance(entry, dict) or not isinstance(entry.get("guard"), bool):
        raise ValueError(f"server {name!r} needs a boolean 'guard' choice")
    if ("command" in entry) == ("url" in entry):
        raise ValueError(f"server {name!r} needs exactly one of 'command' or 'url'")
    if "command" in entry:
        if not isinstance(entry["command"], str) or not all(
            isinstance(arg, str) for arg in entry.get("args", [])
        ):
            raise ValueError(f"server {name!r} command and args must be strings")
        if entry["guard"] and not isinstance(entry.get("namespace"), str):
            raise ValueError(f"guarded server {name!r} needs a namespace")
        if "sandbox" in entry:  # OS isolation (local_entry/sandbox.py)
            from .sandbox import validate as validate_sandbox

            if not entry["guard"]:
                raise ValueError(f"server {name!r}: sandbox runs through the guard wrapper; set guard true")
            try:
                validate_sandbox(entry["sandbox"])
            except ValueError as error:
                raise ValueError(f"server {name!r}: {error}") from error
