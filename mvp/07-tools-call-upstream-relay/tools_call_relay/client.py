from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable

from gateway_mvp.models import ToolDefinition, UpstreamServer
from mcp_guard.protocol import PROTOCOL_VERSION


class HttpJsonRpcToolCallClient:
    """``header_provider`` adds gateway-held upstream credentials (C3)."""

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        header_provider: Callable[[UpstreamServer], dict[str, str]] | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._header_provider = header_provider
        self._opener = urllib.request.build_opener(_NoRedirect())

    def call_tool(
        self,
        upstream: UpstreamServer,
        tool: ToolDefinition,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if not upstream.url:
            raise ValueError(f"{upstream.name} has no upstream URL")
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool.name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "mcp-guard", "version": "0.1.0",
                    },
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }
        request = urllib.request.Request(
            upstream.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                **(self._header_provider(upstream) if self._header_provider else {}),
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": PROTOCOL_VERSION,
                "Mcp-Method": "tools/call",
                "Mcp-Name": tool.name,
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                if response.headers.get_content_type() == "text/event-stream":
                    body = _read_sse_result(response, 1)
                elif response.headers.get_content_type() == "application/json":
                    raw = response.read(2_000_001)
                    if len(raw) > 2_000_000:
                        raise ValueError("upstream tool result exceeds size limit")
                    body = json.loads(raw.decode("utf-8"))
                else:
                    raise ValueError("upstream tool result has unsupported content type")
        except (urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConnectionError(f"upstream call failed: {error}") from error

        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != 1:
            raise ValueError("upstream response must match the JSON-RPC request")
        if "error" in body:
            raise ValueError(f"upstream returned error: {body['error']}")
        result = body.get("result")
        if not isinstance(result, dict):
            raise ValueError("upstream response missing object result")
        return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("upstream redirected away from its approved URL")


def _read_sse_result(response, request_id: int) -> dict[str, Any]:
    size = 0
    data_lines: list[str] = []
    for raw in response:
        size += len(raw)
        if size > 2_000_000:
            raise ValueError("upstream SSE tool result exceeds size limit")
        line = raw.decode("utf-8").rstrip("\r\n")
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
        elif not line and data_lines:
            body = json.loads("\n".join(data_lines))
            data_lines.clear()
            if isinstance(body, dict) and body.get("id") == request_id:
                return body
    raise ValueError("upstream SSE stream ended without a tool result")

