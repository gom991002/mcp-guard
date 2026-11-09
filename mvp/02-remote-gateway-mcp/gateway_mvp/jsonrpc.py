from __future__ import annotations

import json
from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
GUARD_BLOCKED = -32001


def load_single_request(body: bytes) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, error_response(None, PARSE_ERROR, "Parse error")

    if not isinstance(payload, dict):
        return None, error_response(None, INVALID_REQUEST, "JSON-RPC request must be an object")
    if payload.get("jsonrpc") != "2.0":
        return None, error_response(payload.get("id"), INVALID_REQUEST, "jsonrpc must be 2.0")
    if not isinstance(payload.get("method"), str):
        return None, error_response(payload.get("id"), INVALID_REQUEST, "method is required")
    return payload, None


def success_response(request_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def error_response(
    request_id: object,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": error,
    }

