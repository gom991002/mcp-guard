"""Reviewed tool definitions of local (stdio) servers and the core check on them.

File format, also used for the wrapper's pending-review output:

{"servers": {"files": {"namespace": "company", "tools": [
    {"name": "read_file", "description": "...", "schema_hash": "sha256:..."}]}}}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_guard.confusables import affix_extension_of
from mcp_guard.definitions import schema_hash
from mcp_guard.models import GuardDecision, ToolRegistration
from mcp_guard.policy import evaluate_live_registration
from mcp_guard.registry import GuardRegistry


@dataclass(frozen=True)
class LocalApprovals:
    servers: dict[str, dict[str, Any]]

    @classmethod
    def from_path(cls, path: str | Path) -> "LocalApprovals":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        servers = payload.get("servers")
        if not isinstance(servers, dict):
            raise ValueError("approvals file must contain a 'servers' object")
        return cls(servers)

    def merged_with_user(self, user: "LocalApprovals") -> "LocalApprovals":
        """Add tools a user approved; the service's (admin) entries always win."""
        servers = {name: dict(entry) for name, entry in self.servers.items()}
        for name, entry in user.servers.items():
            if not isinstance(entry, dict):
                continue
            base = servers.setdefault(name, {"namespace": entry.get("namespace"), "tools": []})
            if base.get("namespace") != entry.get("namespace"):
                continue  # a user cannot re-bind a server to another namespace
            known = {t.get("name") for t in base.get("tools", []) if isinstance(t, dict)}
            base["tools"] = [*base.get("tools", []),
                             *(_user_entry(t) for t in entry.get("tools", [])
                               if isinstance(t, dict) and t.get("name") not in known)]
        return LocalApprovals(servers)

    def tool_names(self, server_name: str) -> frozenset[str]:
        server = self.servers.get(server_name, {})
        return frozenset(t.get("name") for t in server.get("tools", []) if isinstance(t, dict))

    def approved(self, server_name: str, namespace: str, tool_name: str) -> ToolRegistration | None:
        server = self.servers.get(server_name)
        if not isinstance(server, dict) or server.get("namespace") != namespace:
            return None
        for tool in server.get("tools", []):
            if isinstance(tool, dict) and tool.get("name") == tool_name:
                return ToolRegistration(
                    server_name=server_name,
                    namespace=namespace,
                    tool_name=tool_name,
                    description=str(tool.get("description", "")),
                    source="local",
                    schema_hash=tool.get("schema_hash"),
                )
        return None


def observed_registration(server_name: str, namespace: str, tool: dict[str, Any]) -> ToolRegistration:
    name = tool.get("name")
    description = tool.get("description", "")
    input_schema = tool.get("inputSchema")
    if not isinstance(name, str) or not isinstance(description, str) or not isinstance(input_schema, dict):
        raise ValueError("tool definition is malformed")
    return ToolRegistration(
        server_name=server_name,
        namespace=namespace,
        tool_name=name,
        description=description,
        source="local",
        schema_hash=schema_hash(input_schema),
    )


def _user_entry(tool: dict[str, Any]) -> dict[str, Any]:
    """A user may mark a tool as sending data out, never the reverse, and may not
    supply the replacement text the model sees (D6-42, D6-43)."""
    entry = {k: v for k, v in tool.items() if k != "replacement"}
    if entry.get("external_send") is not True:
        entry.pop("external_send", None)
    return entry


def approval_entry(approvals: LocalApprovals, server_name: str, tool_name: str) -> dict[str, Any] | None:
    for tool in approvals.servers.get(server_name, {}).get("tools", []):
        if isinstance(tool, dict) and tool.get("name") == tool_name:
            return tool
    return None


def inspect_tool(
    server_name: str,
    namespace: str,
    tool: dict[str, Any],
    approvals: LocalApprovals,
    registry: GuardRegistry,
    description_reviewer: Any | None = None,
) -> tuple[ToolRegistration, GuardDecision]:
    """Same 2단계 check the remote gateway runs on live lists."""
    observed = observed_registration(server_name, namespace, tool)
    approved = approvals.approved(server_name, namespace, observed.tool_name)
    # D6-38: compare with every server's approved tools, not only this one's.
    catalog = {(name, t["name"]) for name, entry in approvals.servers.items()
               for t in entry.get("tools", []) if isinstance(t, dict) and isinstance(t.get("name"), str)}
    return observed, evaluate_live_registration(observed, approved, registry, catalog=catalog,
                                                description_reviewer=description_reviewer)


def write_pending(path: str | Path, server_name: str, namespace: str,
                  tools: list[ToolRegistration], approvals: LocalApprovals | None = None,
                  hints: dict[str, str] | None = None, notes: dict[str, dict[str, Any]] | None = None) -> None:
    """Record unapproved definitions for an administrator to review.

    With ``approvals``, a name that extends another server's approved tool by
    one word (``my_get_device``) carries an ``extends`` note for the approver
    (D6-38 follow-up); it does not change any verdict.
    """
    target = Path(path)
    payload: dict[str, Any] = {"servers": {}}
    if target.exists():
        payload = json.loads(target.read_text(encoding="utf-8"))
    owners: dict[str, str] = {}
    for other, entry in (approvals.servers.items() if approvals else ()):
        if other != server_name:
            for tool in entry.get("tools", []):
                if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                    owners.setdefault(tool["name"], other)
    records = []
    for t in tools:
        record: dict[str, Any] = {"name": t.tool_name, "description": t.description,
                                  "schema_hash": t.schema_hash}
        base = affix_extension_of(t.tool_name, owners) if owners else None
        if base:
            record["extends"] = {"tool": base, "server": owners[base]}
        if (hints or {}).get(t.tool_name):  # D6-42: shown to the approver, kept after approval
            record["sends_data_hint"] = hints[t.tool_name]
        record.update((notes or {}).get(t.tool_name, {}))  # D6-45: input schema, classification
        records.append(record)
    payload.setdefault("servers", {})[server_name] = {"namespace": namespace, "tools": records}
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, target)


def load_approvals(admin_path: str | Path, user_path: str | Path | None) -> LocalApprovals:
    """Service approvals, plus the user's own when the manifest allows it."""
    approvals = LocalApprovals.from_path(admin_path)
    if user_path and Path(user_path).exists():
        approvals = approvals.merged_with_user(LocalApprovals.from_path(user_path))
    return approvals


def approve_pending(pending_path: str | Path, target_path: str | Path, server_name: str,
                    tool_names: list[str] | None = None, external_send: bool | None = None) -> list[str]:
    """Move reviewed definitions from the pending file into an approvals file."""
    pending = _read(pending_path)
    entry = pending.get("servers", {}).get(server_name)
    if not isinstance(entry, dict):
        raise ValueError(f"no pending definitions for {server_name}")
    chosen = [t for t in entry.get("tools", [])
              if tool_names is None or t.get("name") in tool_names]
    if tool_names is not None and len(chosen) != len(set(tool_names)):
        raise ValueError("some requested tools are not pending")
    target = _read(target_path) if Path(target_path).exists() else {"servers": {}}
    server = target.setdefault("servers", {}).setdefault(
        server_name, {"namespace": entry["namespace"], "tools": []})
    if server.get("namespace") != entry["namespace"]:
        raise ValueError("pending namespace differs from the approved one")
    names = {t["name"] for t in chosen}
    if external_send is not None:  # D6-42: the approver's mark decides
        chosen = [{**t, "external_send": external_send} for t in chosen]
    server["tools"] = [t for t in server.get("tools", []) if t.get("name") not in names] + chosen
    entry["tools"] = [t for t in entry.get("tools", []) if t.get("name") not in names]
    _write(target_path, target)
    _write(pending_path, pending)
    return sorted(names)


def revoke_user_approval(user_path: str | Path, server_name: str, tool_name: str) -> dict[str, Any]:
    """Remove a tool from the user's approvals (D6-45: the administrator's check)."""
    payload = _read(user_path)
    entry = payload.get("servers", {}).get(server_name, {})
    kept = [t for t in entry.get("tools", []) if t.get("name") != tool_name]
    removed = [t for t in entry.get("tools", []) if t.get("name") == tool_name]
    if not removed:
        raise ValueError(f"{server_name}:{tool_name} is not in the user's approvals")
    entry["tools"] = kept
    _write(user_path, payload)
    return removed[0]


def _read(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, target)
