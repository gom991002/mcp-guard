"""Inspect and approve one exact local M4 tool call."""

from __future__ import annotations

import argparse
import json
import sys
from mcp_guard.audit import audit_event, digest

from .manifest import GuardManifest
from .value_approvals import LocalValueApprovals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("action", choices=("list", "approve"))
    parser.add_argument("request_id", nargs="?")
    args = parser.parse_args(argv)
    manifest = GuardManifest.from_path(args.manifest)
    store = LocalValueApprovals(manifest.state_dir)
    if args.action == "list":
        for ident, data in store.pending():
            print(ident, data["server"], data["tool"], ",".join(data["codes"]))
            print(json.dumps(data["arguments"], ensure_ascii=False, indent=2))
        return 0
    pending = dict(store.pending())
    if not args.request_id or args.request_id not in pending:
        parser.error("request is missing or expired; run list first")
    if not store.approve(args.request_id):
        return 1
    data = pending[args.request_id]
    try:
        manifest.audit_recorder(client="local-approval").record(audit_event(
            "approval_decided", server_name=data["server"], tool_name=data["tool"],
            request_id=args.request_id, verdict="allow",
            details={"decision": "approved", "reason": "M4 value policy",
                     "arguments": digest(data["arguments"])}))
    except OSError as error:
        print(f"mcp-guard: audit record failed ({error})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
