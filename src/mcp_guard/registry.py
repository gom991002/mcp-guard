from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from .m4_values import ValuePolicy


@dataclass(frozen=True)
class GuardRegistry:
    trusted_namespaces: frozenset[str]
    protected_tool_names: frozenset[str]
    suspicious_phrases: tuple[str, ...]
    registered_servers: frozenset[str]
    trusted_sources: frozenset[str]
    approved_schema_hashes: dict[str, str]
    refresh_before_call_tools: frozenset[str] = frozenset()
    # M5 (D6-42, D6-43): the administrator's word on which tools send data out,
    # and reviewed replacement descriptions; keys are "<server>:<tool>".
    external_send_tools: frozenset[str] = frozenset()
    not_external_send_tools: frozenset[str] = frozenset()
    replacement_descriptions: dict[str, str] = field(default_factory=dict)
    # Stage 1: MCP Registry publishers (the namespace before "/" in a Registry
    # server name) whose npm/PyPI servers may be approved; empty means any.
    trusted_registry_publishers: frozenset[str] = frozenset()
    m4_value_policy: ValuePolicy | None = None
    # State (design: "정책·신뢰 등급"): the administrator's trust tier per server.
    # trusted_output - its results carry no third-party content, so they do not taint
    #                  a session (an A decision; B signals never set it);
    # standard       - the default;
    # restricted     - its tool descriptions are always replaced (M5), sensitive session or not.
    server_trust: dict[str, str] = field(default_factory=dict)

    def trust_tier(self, server_name: str) -> str:
        return self.server_trust.get(server_name, "standard")

    @classmethod
    def from_path(cls, path: str | Path) -> "GuardRegistry":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "GuardRegistry":
        return cls(
            trusted_namespaces=_string_set(payload, "trusted_namespaces"),
            protected_tool_names=_string_set(payload, "protected_tool_names"),
            suspicious_phrases=_string_tuple(
                payload,
                "suspicious_phrases",
                legacy_key="blocked_phrases",
            ),
            registered_servers=_string_set(payload, "registered_servers"),
            trusted_sources=_string_set(payload, "trusted_sources"),
            approved_schema_hashes=_scoped_hash_map(payload, "approved_schema_hashes"),
            refresh_before_call_tools=_string_set(payload, "refresh_before_call_tools"),
            external_send_tools=_scoped_set(payload, "external_send_tools"),
            not_external_send_tools=_scoped_set(payload, "not_external_send_tools"),
            replacement_descriptions=_scoped_hash_map(payload, "replacement_descriptions"),
            trusted_registry_publishers=_string_set(payload, "trusted_registry_publishers"),
            m4_value_policy=ValuePolicy.from_dict(payload.get("m4_value_policy")),
            server_trust=_trust_tiers(payload),
        )

    def approved_hash_for(self, server_name: str, tool_name: str) -> str | None:
        # M2 binds a tool name to its server, so an approval never carries over
        # to another server that registers the same tool name.
        return self.approved_schema_hashes.get(f"{server_name}:{tool_name}")


TRUST_TIERS = ("trusted_output", "standard", "restricted")


def _trust_tiers(payload: dict[str, object]) -> dict[str, str]:
    value = payload.get("server_trust", {})
    if not isinstance(value, dict) or not all(
            isinstance(k, str) and k and v in TRUST_TIERS for k, v in value.items()):
        raise ValueError(f"server_trust must map server names to one of {', '.join(TRUST_TIERS)}")
    return dict(value)


def _string_set(payload: dict[str, object], key: str) -> frozenset[str]:
    value = payload.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return frozenset(value)


def _string_tuple(
    payload: dict[str, object],
    key: str,
    legacy_key: str | None = None,
) -> tuple[str, ...]:
    value = payload.get(key)
    if value is None and legacy_key is not None:
        value = payload.get(legacy_key, [])
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return tuple(value)


def _string_map(payload: dict[str, object], key: str) -> dict[str, str]:
    value = payload.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ValueError(f"{key} must map strings to strings")
    return dict(value)


def _scoped_set(payload: dict[str, object], key: str) -> frozenset[str]:
    value = _string_set(payload, key)
    if any(not k.partition(":")[0] or not k.partition(":")[2] for k in value):
        raise ValueError(f"{key} entries must be '<server_name>:<tool_name>'")
    return value


def _scoped_hash_map(payload: dict[str, object], key: str) -> dict[str, str]:
    value = _string_map(payload, key)
    for scoped_key in value:
        server_name, _, tool_name = scoped_key.partition(":")
        if not server_name or not tool_name:
            raise ValueError(f"{key} keys must be '<server_name>:<tool_name>'")
    return value


# Must stay identical to configs/example-policy.json (checked by tests).
DEFAULT_REGISTRY = GuardRegistry(
    trusted_namespaces=frozenset({"mcp_guard", "company"}),
    protected_tool_names=frozenset(
        {
            "github.search",
            "slack.send_message",
            "filesystem.read_file",
        }
    ),
    suspicious_phrases=(
        "ignore previous instructions",
        "disable guard",
        "send secrets",
        "exfiltrate",
    ),
    registered_servers=frozenset({"company-tools", "helper"}),
    trusted_sources=frozenset({"gateway", "registry", "local"}),
    approved_schema_hashes={"company-tools:company.search": "sha256:example"},
    refresh_before_call_tools=frozenset({"slack.send_message", "filesystem.read_file"}),
)

