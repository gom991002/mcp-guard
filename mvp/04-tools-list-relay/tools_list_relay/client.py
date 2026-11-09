from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Callable

from gateway_mvp.models import ToolDefinition, ToolListSnapshot, UpstreamServer
from mcp_guard.definitions import schema_hash
from mcp_guard.protocol import PROTOCOL_VERSION


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("upstream redirected away from its approved URL")


HeaderProvider = Callable[[UpstreamServer], dict[str, str]]


class HttpToolsListClient:
    """Fetch complete modern MCP tool lists.

    ``header_provider`` adds gateway-held upstream credentials (C3); client
    tokens are never forwarded.
    """

    def __init__(
        self, *, timeout_seconds: float = 5.0, max_pages: int = 32,
        max_tools: int = 1000, max_response_bytes: int = 2_000_000,
        header_provider: HeaderProvider | None = None,
    ) -> None:
        self._header_provider = header_provider
        self._timeout = timeout_seconds
        self._max_pages = max_pages
        self._max_tools = max_tools
        self._max_response_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(_NoRedirect())

    def fetch(self, upstream: UpstreamServer) -> ToolListSnapshot:
        if upstream.transport != "streamable_http" or not upstream.url:
            raise ValueError("upstream needs an approved Streamable HTTP URL")
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_names: set[str] = set()
        tools: list[ToolDefinition] = []
        ttl_ms: int | None = None
        scope: str | None = None
        extra_headers = self._header_provider(upstream) if self._header_provider else {}
        for page_number in range(self._max_pages):
            result = self._page(upstream.url, page_number + 1, cursor, extra_headers)
            if result.get("resultType") != "complete" or not isinstance(result.get("tools"), list):
                raise ValueError("upstream tools/list result is incomplete or malformed")
            page_ttl = result.get("ttlMs", 0)
            if isinstance(page_ttl, bool) or not isinstance(page_ttl, int) or page_ttl < 0:
                raise ValueError("upstream tools/list ttlMs is invalid")
            ttl_ms = page_ttl if ttl_ms is None else min(ttl_ms, page_ttl)
            page_scope = result.get("cacheScope", "private")
            if page_scope not in {"public", "private"} or (scope and page_scope != scope):
                raise ValueError("upstream tools/list cacheScope is invalid or inconsistent")
            scope = page_scope
            for item in result["tools"]:
                if not isinstance(item, dict):
                    raise ValueError("upstream tool is not an object")
                name = item.get("name")
                description = item.get("description", "")
                input_schema = item.get("inputSchema")
                if (not isinstance(name, str) or not name or
                        not isinstance(description, str) or not isinstance(input_schema, dict)):
                    raise ValueError("upstream tool definition is invalid")
                if name in seen_names:
                    raise ValueError("upstream returned duplicate tool names")
                seen_names.add(name)
                tools.append(ToolDefinition(
                    server_name=upstream.name, namespace=upstream.namespace,
                    name=name, description=description, input_schema=input_schema,
                    schema_hash=schema_hash(input_schema), source=upstream.source,
                ))
                if len(tools) > self._max_tools:
                    raise ValueError("upstream tool count exceeds limit")
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return ToolListSnapshot(tuple(tools), ttl_ms or 0, scope or "private")
            if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                raise ValueError("upstream tools/list cursor is invalid or repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise ValueError("upstream tools/list exceeded page limit")

    def _page(
        self, url: str, request_id: int, cursor: str | None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict:
        params: dict[str, object] = {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {
                    "name": "mcp-guard", "version": "0.1.0",
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        }
        if cursor is not None:
            params["cursor"] = cursor
        request = urllib.request.Request(
            url, data=json.dumps({
                "jsonrpc": "2.0", "id": request_id,
                "method": "tools/list", "params": params,
            }).encode("utf-8"),
            headers={
                **(extra_headers or {}),
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": PROTOCOL_VERSION,
                "Mcp-Method": "tools/list",
            }, method="POST",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                media_type = response.headers.get_content_type()
                if media_type == "application/json":
                    raw = response.read(self._max_response_bytes + 1)
                    if len(raw) > self._max_response_bytes:
                        raise ValueError("upstream response exceeds size limit")
                    body = json.loads(raw.decode("utf-8"))
                elif media_type == "text/event-stream":
                    body = self._sse_result(response, request_id)
                else:
                    raise ValueError("upstream response has unsupported content type")
        except (urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConnectionError("upstream tools/list request failed") from error
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != request_id:
            raise ValueError("upstream tools/list response ID is invalid")
        if "error" in body:
            raise ValueError("upstream returned a tools/list error")
        result = body.get("result")
        if not isinstance(result, dict):
            raise ValueError("upstream tools/list result is missing")
        return result

    def _sse_result(self, response, request_id: int) -> dict:
        size = 0
        data_lines: list[str] = []
        for raw in response:
            size += len(raw)
            if size > self._max_response_bytes:
                raise ValueError("upstream SSE response exceeds size limit")
            line = raw.decode("utf-8").rstrip("\r\n")
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
            elif not line and data_lines:
                body = json.loads("\n".join(data_lines))
                data_lines.clear()
                if isinstance(body, dict) and body.get("id") == request_id:
                    return body
        raise ValueError("upstream SSE stream ended without a tools/list result")

    def watch_changes(
        self, upstream: UpstreamServer, on_change: Callable[[str], None],
        stop: threading.Event,
    ) -> bool:
        """Listen for modern MCP list changes; TTL refresh remains the fallback."""
        params = {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {
                    "name": "mcp-guard", "version": "0.1.0",
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "notifications": {"toolsListChanged": True},
        }
        request = urllib.request.Request(
            upstream.url, data=json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "method": "subscriptions/listen", "params": params,
            }).encode("utf-8"),
            headers={
                **(self._header_provider(upstream) if self._header_provider else {}),
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": PROTOCOL_VERSION,
                "Mcp-Method": "subscriptions/listen",
            }, method="POST",
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            if response.headers.get_content_type() != "text/event-stream":
                return False
            data_lines: list[str] = []
            size = 0
            for raw in response:
                if stop.is_set():
                    return True
                size += len(raw)
                if size > self._max_response_bytes:
                    raise ValueError("upstream subscription event exceeds size limit")
                line = raw.decode("utf-8").rstrip("\r\n")
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip(" "))
                elif not line:
                    if data_lines:
                        event = json.loads("\n".join(data_lines))
                        data_lines.clear()
                        if (isinstance(event, dict) and
                                event.get("method") == "notifications/tools/list_changed"):
                            on_change(upstream.name)
                    size = 0
        return True

    def run_change_watcher(
        self, upstream: UpstreamServer, on_change: Callable[[str], None],
        stop: threading.Event, on_gap: Callable[[str], None] | None = None,
    ) -> None:
        """Keep a change subscription open, reconnecting after it drops.

        Change events sent while the subscription was down are lost, so every
        reconnect first calls ``on_gap`` (default ``on_change``): a cached list
        is fetched and inspected again instead of waiting for its TTL.
        """
        reconnect = False
        while not stop.is_set():
            if reconnect:
                (on_gap or on_change)(upstream.name)
            reconnect = True
            try:
                if not self.watch_changes(upstream, on_change, stop):
                    return
            except urllib.error.HTTPError as error:
                if 400 <= error.code < 500:
                    return  # Upstream does not support subscriptions; TTL still works.
            except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                pass
            stop.wait(5.0)

