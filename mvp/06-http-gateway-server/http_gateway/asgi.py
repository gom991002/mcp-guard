"""Production ASGI front end for the gateway (served by uvicorn, ``--server asgi``).

The app itself uses only the standard library. Compared with the development
``ThreadingHTTPServer``:

* The IP delay is awaited with ``asyncio.sleep``, so a delayed client holds no
  thread (the development server sleeps in the request thread).
* Blocking work (upstream calls, the secret manager, file writes) runs in the
  default thread pool through ``asyncio.to_thread``.
* At most ``MAX_MCP_BODY_BYTES + 1`` body bytes are read; a larger body reaches
  the gateway's edge rule, which answers 413 and records the rejection.
* ``client`` in the ASGI scope must be the socket peer: run uvicorn with
  ``proxy_headers=False`` so the adapter alone decides which proxies to trust.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from rule_sets.waf_gateway_rules import MAX_MCP_BODY_BYTES

from .adapter import HttpGatewayAdapter
from .models import HttpRequest, HttpResponse

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class GatewayAsgiApp:
    def __init__(self, adapter: HttpGatewayAdapter,
                 on_shutdown: Callable[[], None] | None = None) -> None:
        self._adapter = adapter
        self._on_shutdown = on_shutdown

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
        elif scope["type"] == "http":
            await self._http(scope, receive, send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})  # MCP uses plain HTTP

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                if self._on_shutdown is not None:
                    await asyncio.to_thread(self._on_shutdown)
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _http(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        body = await _read_body(receive, MAX_MCP_BODY_BYTES + 1)
        query = scope.get("query_string", b"").decode("latin-1")
        client = scope.get("client")
        request = HttpRequest(
            method=scope["method"],
            path=scope["path"] + (f"?{query}" if query else ""),
            headers=_headers(scope.get("headers", [])),
            body=body,
            client_ip=client[0] if client else "",
        )
        request, decision, answered = await asyncio.to_thread(self._adapter.admit, request)
        if answered is not None:
            await _send(send, answered)
            return
        if decision is not None and decision.should_delay:
            await asyncio.sleep(decision.delay_seconds)
        response = await asyncio.to_thread(
            self._adapter.handle, request, None, (request, decision))
        await _send(send, response)


async def _read_body(receive: Receive, limit: int) -> bytes:
    chunks, size = [], 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        if size < limit:
            chunks.append(chunk[: limit - size])
        size += len(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _headers(raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in raw:
        key, text = name.decode("latin-1").lower(), value.decode("latin-1")
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
    return headers


async def _send(send: Send, response: HttpResponse) -> None:
    await send({
        "type": "http.response.start",
        "status": response.status_code,
        "headers": [(k.lower().encode("latin-1"), str(v).encode("latin-1"))
                    for k, v in response.headers.items()],
    })
    await send({"type": "http.response.body", "body": response.body or b""})
