"""M4 stage 4 checks on destinations in tool-call arguments.

The administrator owns the boundary. A configured policy is checked on every
call, regardless of session taint. Findings request approval; callers decide
how to obtain it and must never send a flagged call before approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


_AUTO = {
    "recipient": {"to", "cc", "recipient", "recipients", "email", "email_address"},
    "bcc": {"bcc", "blind_copy", "blind_copy_recipients"},
    "url": {"url", "webhook", "webhook_url", "endpoint", "destination_url"},
    "visibility": {"visibility", "access", "sharing", "share_mode", "public", "is_public"},
}
_PUBLIC = {"public", "anyone", "anyone_with_link", "anyonewithlink", "world", "open"}


@dataclass(frozen=True)
class ValueFinding:
    code: str
    path: str
    detail: str
    marker: str = "M4"
    stage: str = "4-containment"

    def to_dict(self) -> dict[str, str]:
        return vars(self).copy()


@dataclass(frozen=True)
class ValuePolicy:
    internal_domains: frozenset[str]
    allowed_url_hosts: frozenset[str]
    fields: dict[str, dict[str, tuple[str, ...]]]

    @classmethod
    def from_dict(cls, data: Any) -> "ValuePolicy | None":
        if data is None:
            return None
        if not isinstance(data, dict):
            raise ValueError("m4_value_policy must be an object")
        def domains(key: str) -> frozenset[str]:
            value = data.get(key, [])
            if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
                raise ValueError(f"m4_value_policy.{key} must be a list of names")
            return frozenset(v.strip().lower().rstrip(".") for v in value)
        fields = data.get("tool_fields", {})
        if not isinstance(fields, dict):
            raise ValueError("m4_value_policy.tool_fields must be an object")
        checked = {}
        for tool, kinds in fields.items():
            if not isinstance(tool, str) or ":" not in tool or not isinstance(kinds, dict):
                raise ValueError("m4_value_policy.tool_fields needs server:tool objects")
            if any(k not in _AUTO or not isinstance(v, list) or
                   any(not isinstance(p, str) or not p for p in v) for k, v in kinds.items()):
                raise ValueError("m4_value_policy tool fields need recipient/bcc/url/visibility paths")
            checked[tool] = {k: tuple(v) for k, v in kinds.items()}
        return cls(domains("internal_domains"), domains("allowed_url_hosts"), checked)


def inspect_values(policy: ValuePolicy | None, server: str, tool: str,
                   arguments: dict[str, Any]) -> tuple[ValueFinding, ...]:
    if policy is None:
        return ()
    values: list[tuple[str, str, Any]] = []
    def walk(node: Any, path: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                at = f"{path}.{key}" if path else key
                normalized = key.lower().replace("-", "_")
                for kind, names in _AUTO.items():
                    if normalized in names:
                        values.append((kind, at, value))
                walk(value, at)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}.{index}")
    walk(arguments)
    for kind, paths in policy.fields.get(f"{server}:{tool}", {}).items():
        for path in paths:
            node: Any = arguments
            try:
                for part in path.split("."):
                    node = node[int(part)] if isinstance(node, list) else node[part]
            except (KeyError, IndexError, TypeError, ValueError):
                values.append((kind, path, None))
            else:
                values.append((kind, path, node))
    findings: list[ValueFinding] = []
    seen = set()
    for kind, path, value in values:
        key = (kind, path)
        if key in seen:
            continue
        seen.add(key)
        if kind == "bcc" and value not in (None, "", []):
            findings.append(ValueFinding("M4_BCC_RECIPIENT", path, "blind copy recipient is present"))
        elif kind == "visibility" and (value is True or isinstance(value, str) and value.strip().lower().replace(" ", "_") in _PUBLIC):
            findings.append(ValueFinding("M4_PUBLIC_DESTINATION", path, "destination is public"))
        elif kind in ("recipient", "url"):
            items = value if isinstance(value, list) else [value]
            for item in items:
                if not isinstance(item, str) or not item.strip():
                    findings.append(ValueFinding("M4_DESTINATION_UNVERIFIABLE", path, "destination is missing or malformed"))
                    continue
                if kind == "recipient":
                    address = item.strip().rsplit("<", 1)[-1].rstrip("> ")
                    domain = address.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in address else ""
                    if not domain or "." not in domain:
                        findings.append(ValueFinding("M4_DESTINATION_UNVERIFIABLE", path, "recipient is malformed"))
                    elif domain not in policy.internal_domains:
                        findings.append(ValueFinding("M4_EXTERNAL_RECIPIENT", path, "recipient is outside internal domains"))
                else:
                    try:
                        parsed = urlsplit(item.strip())
                        host = (parsed.hostname or "").lower().rstrip(".")
                    except ValueError:
                        findings.append(ValueFinding("M4_DESTINATION_UNVERIFIABLE", path, "URL is malformed"))
                        continue
                    if parsed.scheme not in ("https", "http") or not host or parsed.username or parsed.password:
                        findings.append(ValueFinding("M4_DESTINATION_UNVERIFIABLE", path, "URL is malformed"))
                    elif host not in policy.allowed_url_hosts:
                        findings.append(ValueFinding("M4_UNAPPROVED_URL", path, "URL host is not allowed"))
    return tuple(findings)
