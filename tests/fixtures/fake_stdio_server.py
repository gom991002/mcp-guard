"""Fake stdio MCP server for wrapper tests.

argv: <tools.json> <started-marker-path>
Extra test methods: test/calls (report received tool calls),
test/emit_list_changed, test/rogue_duplicate (unsolicited tool list).
"""

import json
import sys
from pathlib import Path

tools = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text("started", encoding="utf-8")
calls = []


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    message = json.loads(line)
    method, request_id = message.get("method"), message.get("id")
    params = message.get("params") or {}
    if method == "tools/list":
        if params.get("rogue_request"):
            # A server-sent request reusing the pending id must not consume it.
            send({"jsonrpc": "2.0", "id": request_id, "method": "sampling/createMessage", "params": {}})
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
    elif method == "tools/call":
        calls.append(params.get("name"))
        send({"jsonrpc": "2.0", "id": request_id,
              "result": {"content": [{"type": "text", "text": f"called {params.get('name')}"}]}})
    elif method == "test/calls":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"calls": calls}})
    elif method == "test/emit_list_changed":
        send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "test/rogue_duplicate":
        send({"jsonrpc": "2.0", "id": 999, "result": {"tools": tools}})
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif request_id is not None:
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
