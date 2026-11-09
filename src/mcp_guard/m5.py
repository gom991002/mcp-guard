"""M5 (stage 2): session isolation and description replacement (D6-42, D6-43).

A session is sensitive when any tool in it can send data out. In a sensitive
session the model never sees text the server wrote: tool, prompt and resource
descriptions, the server's instructions, and the text inside input schemas
(descriptions, titles, examples, defaults) are replaced. A tool's replacement
is the administrator's reviewed text if there is one, otherwise a line built
from its name and input names only.

Which tools send data out: the administrator decides (A). For a tool the
administrator has not marked, a name or input that looks like sending
(``send_email``, a ``url`` or ``recipient`` input) counts as sending, so an
unclear case gets the stricter treatment; the same hint is shown to the
approver as a note (B, never a verdict). A mark of "sends data out" wins over
"does not".

Isolation is per server: only approved servers' tools are listed (M2, M3),
and policy.evaluate_registration holds a description that names another
server's tool (``M5_DESCRIPTION_NAMES_OTHER_SERVER_TOOL``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .confusables import name_tokens
from .registry import GuardRegistry

SENDING_WORDS = frozenset({
    "send", "post", "upload", "email", "mail", "message", "messages", "publish", "share", "webhook",
    "notify", "forward", "export", "tweet", "reply", "comment", "invite", "submit", "fetch", "request",
    "http", "browse", "navigate", "sms", "chat",
})
SENDING_INPUTS = frozenset({
    "url", "uri", "urls", "link", "endpoint", "webhook", "recipient", "recipients", "cc", "bcc", "email",
    "emails", "channel", "destination", "host", "hostname", "phone",
})
SCHEMA_TEXT_KEYS = frozenset({"description", "title", "examples", "example", "default", "$comment"})
_NAME_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
WITHHELD_INSTRUCTIONS = ("mcp-guard withheld this server's instructions because the session can send "
                         "data out. Use each tool by its name and input schema.")


def likely_external_send(name: str, input_schema: Any) -> str | None:
    """Why ``name`` looks like a tool that sends data out, or None (a hint, not a decision)."""
    words = set(name_tokens(name)) & SENDING_WORDS
    if words:
        return f"name has {', '.join(sorted(words))}"
    for prop in _properties(input_schema):
        tokens = name_tokens(prop)
        if set(tokens) & SENDING_INPUTS or (tokens[:1] == ("to",)):
            return f"input {prop!r}"
    return None


def is_external_send(server: str, name: str, input_schema: Any, registry: GuardRegistry,
                     approval: dict[str, Any] | None = None) -> tuple[bool, str]:
    """(sends data out?, why). The administrator's mark decides; unmarked tools follow the hint."""
    key = f"{server}:{name}"
    if key in registry.external_send_tools or (approval or {}).get("external_send") is True:
        return True, "marked by the administrator"
    if key in registry.not_external_send_tools or (approval or {}).get("external_send") is False:
        return False, "marked by the administrator as not sending data out"
    hint = likely_external_send(name, input_schema) or (approval or {}).get("sends_data_hint")
    return (True, f"not marked; {hint}") if hint else (False, "not marked; nothing looks like sending")


def replacement_description(name: str, input_schema: Any, reviewed: str | None = None) -> str:
    if reviewed:
        return reviewed
    schema = input_schema if isinstance(input_schema, dict) else {}
    required = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
    inputs = []
    for prop, spec in sorted(_properties(schema).items()):
        kind = spec.get("type") if isinstance(spec, dict) and isinstance(spec.get("type"), str) else "value"
        label = prop if _SAFE_NAME.fullmatch(prop) else "(unnamed)"
        inputs.append(f"{label} ({kind}{', required' if prop in required else ''})")
    return f"Tool {name}. Inputs: {', '.join(inputs) if inputs else 'none'}."


def strip_schema_text(value: Any) -> Any:
    """The schema without free text a server could use to instruct the model."""
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if key in SCHEMA_TEXT_KEYS:
                continue
            if key in _NAME_MAPS and isinstance(item, dict):  # keys here are input names, not text
                clean[key] = {name: strip_schema_text(sub) for name, sub in item.items()}
            else:
                clean[key] = strip_schema_text(item)
        return clean
    if isinstance(value, list):
        return [strip_schema_text(v) for v in value]
    return value


def sanitize_tool(tool: dict[str, Any], reviewed: str | None = None) -> dict[str, Any]:
    name = str(tool.get("name", ""))
    schema = tool.get("inputSchema")
    clean = {k: v for k, v in tool.items() if k not in {"description", "title", "annotations", "_meta"}}
    clean["description"] = replacement_description(name, schema, reviewed)
    if isinstance(schema, dict):
        clean["inputSchema"] = strip_schema_text(schema)
    if isinstance(tool.get("outputSchema"), dict):
        clean["outputSchema"] = strip_schema_text(tool["outputSchema"])
    return clean


def sanitize_prompt(prompt: dict[str, Any]) -> dict[str, Any]:
    clean = {k: v for k, v in prompt.items() if k not in {"description", "title", "_meta"}}
    clean["description"] = f"Prompt {prompt.get('name', '')}."
    if isinstance(prompt.get("arguments"), list):
        clean["arguments"] = [{k: v for k, v in a.items() if k in {"name", "required"}}
                              for a in prompt["arguments"] if isinstance(a, dict)]
    return clean


def sanitize_resource(resource: dict[str, Any]) -> dict[str, Any]:
    clean = {k: v for k, v in resource.items() if k not in {"description", "title", "annotations", "_meta"}}
    clean["description"] = f"Resource {resource.get('name', '')}."
    return clean


def names_other_server_tool(server: str, description: str,
                            catalog: Iterable[tuple[str, str]]) -> tuple[str, str] | None:
    """(server, tool) of another server's tool that ``description`` names, or None.

    Only names of two or more words count, and not a name the server itself also
    uses: on 755 real Docker catalog tools this held none (mvp/04-tools-list-relay/m2_names data).
    """
    pairs = list(catalog)
    own = {tool for s, tool in pairs if s == server}
    for other, tool in sorted(pairs):
        if other != server and tool not in own and len(name_tokens(tool)) >= 2 and \
                re.search(rf"(?<![\w.-]){re.escape(tool)}(?![\w-])", description or ""):
            return other, tool
    return None


def _properties(schema: Any) -> dict[str, Any]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}
