from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field

from .common import Match, Rule, RuleAction, RuleFamily, Severity
from mcp_guard.protocol import PROTOCOL_VERSION

# Gateway edge checks for the remote gateway on the cloud path (A-02). Not in
# the drawings; they run before the inspection core sees a message.
# Target: MCP Streamable HTTP, protocol revision 2026-07-28. Clients on
# 2025-11-25 or earlier (GET stream, DELETE session, Mcp-Session-Id) are not
# supported by these rules.

MAX_MCP_BODY_BYTES = 1024 * 1024
_NAMED_METHODS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}
_SUPPORTED_CONTENT_TYPES = {"application/json"}


@dataclass(frozen=True)
class GatewayRequest:
    method: str
    body: bytes
    content_type: str
    path: str = "/mcp"
    headers: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        # HTTP header names are case-insensitive.
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return None


def _rule(rule_id: str, title: str, description: str, tags: tuple[str, ...]) -> Rule:
    return Rule(
        rule_id=rule_id,
        family=RuleFamily.WAF_GATEWAY,
        title=title,
        stage="0-entry",
        marker="A",
        severity=Severity.CRITICAL,
        default_action=RuleAction.BLOCK,
        description=description,
        tags=tags,
    )


METHOD_NOT_ALLOWED_RULE = _rule(
    "S0_GATEWAY_METHOD_NOT_ALLOWED",
    "HTTP method not allowed",
    "Only POST (and CORS preflight OPTIONS) reach the MCP endpoint. "
    "GET and DELETE were removed in 2026-07-28; answer 405.",
    ("gateway", "http"),
)

BODY_TOO_LARGE_RULE = _rule(
    "S0_GATEWAY_BODY_TOO_LARGE",
    "MCP request body too large",
    "Rejects oversized MCP requests before JSON parsing.",
    ("gateway", "dos"),
)

PATH_NOT_ALLOWED_RULE = _rule(
    "S0_GATEWAY_PATH_NOT_ALLOWED",
    "MCP path not allowed",
    "Only the configured /mcp endpoint reaches the gateway core.",
    ("gateway", "http"),
)

UNSUPPORTED_MEDIA_TYPE_RULE = _rule(
    "S0_GATEWAY_UNSUPPORTED_MEDIA_TYPE",
    "Unsupported MCP content type",
    "POST requests must use application/json so the JSON-RPC body and mirrored headers can be compared.",
    ("gateway", "http"),
)

ORIGIN_NOT_ALLOWED_RULE = _rule(
    "S0_GATEWAY_ORIGIN_NOT_ALLOWED",
    "Origin not allowed",
    "A present but unknown Origin header must be rejected with 403 (DNS rebinding).",
    ("gateway", "origin"),
)

INVALID_JSONRPC_RULE = _rule(
    "S0_GATEWAY_INVALID_JSONRPC",
    "Invalid JSON-RPC request",
    "The body must be one JSON-RPC request or notification; no batches, no client responses.",
    ("gateway", "jsonrpc"),
)

HEADER_MISMATCH_RULE = _rule(
    "S0_GATEWAY_HEADER_MISMATCH",
    "Mirrored header missing or mismatched",
    "MCP-Protocol-Version, Mcp-Method, and Mcp-Name must match the body. "
    "A spoofed Mcp-Name would let routing and execution see different tools (M2).",
    ("gateway", "header-mismatch", "related:M2"),
)


def inspect_gateway_request(
    request: GatewayRequest,
    allowed_origins: frozenset[str] = frozenset(),
) -> list[Match]:
    matches: list[Match] = []
    method = request.method.upper()

    if request.path != "/mcp":
        matches.append(
            Match(
                rule=PATH_NOT_ALLOWED_RULE,
                message="Request path is not the MCP gateway endpoint.",
                evidence=request.path,
            )
        )

    if method not in {"POST", "OPTIONS"}:
        matches.append(
            Match(
                rule=METHOD_NOT_ALLOWED_RULE,
                message="Unsupported HTTP method for MCP gateway.",
                evidence=request.method,
            )
        )

    origin = request.header("Origin")
    if origin is not None and origin not in allowed_origins:
        matches.append(
            Match(
                rule=ORIGIN_NOT_ALLOWED_RULE,
                message="Origin header is not on the allow-list.",
                evidence=origin,
            )
        )

    if len(request.body) > MAX_MCP_BODY_BYTES:
        matches.append(
            Match(
                rule=BODY_TOO_LARGE_RULE,
                message="Request body exceeds gateway limit.",
                evidence=str(len(request.body)),
            )
        )
        return matches

    if method == "POST":
        content_type = request.content_type.split(";", 1)[0].strip().lower()
        if content_type not in _SUPPORTED_CONTENT_TYPES:
            matches.append(
                Match(
                    rule=UNSUPPORTED_MEDIA_TYPE_RULE,
                    message="POST requests must use application/json.",
                    evidence=request.content_type,
                )
            )
            return matches
        matches.extend(_inspect_post(request))

    return matches


def _inspect_post(request: GatewayRequest) -> list[Match]:
    try:
        message = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return [_invalid("Request body is not valid UTF-8 JSON.", error.__class__.__name__)]

    if isinstance(message, list):
        return [_invalid("JSON-RPC batches are not allowed; send one message per POST.")]
    if not isinstance(message, dict):
        return [_invalid("JSON-RPC message must be an object.")]
    if message.get("jsonrpc") != "2.0":
        return [_invalid("JSON-RPC version must be 2.0.")]
    if not isinstance(message.get("method"), str):
        return [_invalid("Clients send only requests or notifications, which need a method.")]

    if "id" not in message:
        # Notification: this protocol revision defines no mirrored headers for it.
        return []
    return _inspect_mirrored_headers(request, message)


def _inspect_mirrored_headers(request: GatewayRequest, message: dict[str, object]) -> list[Match]:
    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    meta = params.get("_meta")
    meta = meta if isinstance(meta, dict) else {}

    expected = {
        "MCP-Protocol-Version": meta.get("io.modelcontextprotocol/protocolVersion"),
        "Mcp-Method": message["method"],
    }
    name_field = _NAMED_METHODS.get(str(message["method"]))
    if name_field is not None:
        expected["Mcp-Name"] = params.get(name_field)

    problems: list[Match] = []
    for header_name, body_value in expected.items():
        header_value = request.header(header_name)
        if header_value is None:
            problems.append(_mismatch(f"{header_name} header is missing.", header_name))
            continue
        if header_name == "Mcp-Name":
            header_value = _decode_sentinel(header_value)
        if header_value is None or header_value != body_value:
            problems.append(_mismatch(f"{header_name} header does not match the body.", header_name))
    return problems


def _decode_sentinel(value: str) -> str | None:
    # Non-ASCII names travel as =?base64?...?=; decode before comparing.
    if not (value.startswith("=?base64?") and value.endswith("?=")):
        return value
    try:
        return base64.b64decode(value[len("=?base64?") : -len("?=")], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def _invalid(message: str, evidence: str = "") -> Match:
    return Match(rule=INVALID_JSONRPC_RULE, message=message, evidence=evidence)


def _mismatch(message: str, header_name: str) -> Match:
    return Match(rule=HEADER_MISMATCH_RULE, message=message, evidence=header_name)
