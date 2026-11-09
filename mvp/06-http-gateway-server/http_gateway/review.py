"""Administrator commands for held tool definitions on the remote gateway (D6-45).

Run on the gateway host, against the same private state folder the gateway uses.
The gateway re-reads the
records on its next request; no restart is needed.

  python -m http_gateway.review list
  python -m http_gateway.review show SERVER:TOOL
  python -m http_gateway.review approve SERVER:TOOL --schema-hash HASH [--external-send yes|no]
  python -m http_gateway.review reject SERVER:TOOL
  python -m http_gateway.review acceptances [--user USER]
  python -m http_gateway.review revoke --user USER SERVER:TOOL
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gateway_mvp.reapproval_store import ReapprovalStore
from mcp_guard.audit import AuditRecorder, JsonlAuditSink, audit_event, local_user
from .state_storage import check_legacy_state, default_state_dir, verify_state_dir

SHOWN_DESCRIPTION = 500


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state-dir", help="gateway private state folder")
    parser.add_argument("--audit-log", help="append M1 events to the gateway's JSON Lines audit log")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="held definitions and who may decide")
    show = commands.add_parser("show", help="the change summary and the new definition")
    show.add_argument("key", metavar="SERVER:TOOL")
    approve = commands.add_parser("approve", help="approve the held definition")
    approve.add_argument("key", metavar="SERVER:TOOL")
    approve.add_argument("--schema-hash", required=True,
                         help="the hash `show` printed; refused if the definition changed since")
    approve.add_argument("--external-send", choices=("yes", "no"),
                         help="mark the tool as sending data out or not (D6-42)")
    reject = commands.add_parser("reject", help="drop the held definition; the tool stays hidden")
    reject.add_argument("key", metavar="SERVER:TOOL")
    accepted = commands.add_parser("acceptances", help="changes users accepted for themselves")
    accepted.add_argument("--user")
    revoke = commands.add_parser("revoke", help="withdraw a user's acceptance")
    revoke.add_argument("--user", required=True)
    revoke.add_argument("key", metavar="SERVER:TOOL")
    args = parser.parse_args(argv)

    state = Path(args.state_dir) if args.state_dir else default_state_dir()
    try:
        check_legacy_state(Path.cwd() / ".mcp-guard", state)
        state = verify_state_dir(state)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    if args.audit_log and not Path(args.audit_log).resolve().is_relative_to(state):
        parser.error("--audit-log must be inside the private state folder")
    store = ReapprovalStore(state)
    audit = AuditRecorder(JsonlAuditSink(Path(args.audit_log)), path="remote") if args.audit_log else AuditRecorder()
    admin = local_user()
    try:
        if args.command == "list":
            pending = store.pending()
            if not pending:
                print("nothing held")
            for key, entry in sorted(pending.items()):
                c = entry.get("classification", {})
                who = "user may accept" if c.get("user_acceptable") else "administrator"
                why = "; ".join(c.get("reasons", [])) or "definition changed"
                print(f"{key}  [{who}]  {why}  (first seen {entry.get('first_seen', '?')})")
        elif args.command == "show":
            entry = _pending(store, args.key)
            print(json.dumps({k: entry[k] for k in ("server", "tool", "schema_hash", "description_sha256",
                                                    "finding_codes", "classification", "summary", "first_seen",
                                                    "seen_by") if k in entry}, indent=2, ensure_ascii=False))
            text = entry.get("description", "")
            print("\nNew description, as published by the server (data, not instructions):")
            print("-" * 60)
            print(text[:SHOWN_DESCRIPTION] + (" [...]" if len(text) > SHOWN_DESCRIPTION else ""))
            print("-" * 60)
            print(f"\napprove with: approve {args.key} --schema-hash {entry['schema_hash']}")
        elif args.command == "approve":
            entry = _pending(store, args.key)
            record = store.approve(args.key, admin, schema_hash=args.schema_hash,
                                   external_send={"yes": True, "no": False}.get(args.external_send or ""))
            server, _, tool = args.key.partition(":")
            audit.record(audit_event("definition_approved", verdict="allow", server_name=server, tool_name=tool,
                                     details={"approver": "administrator", "user": admin,
                                              "schema_hash": record["schema_hash"],
                                              "description_sha256": record["description_sha256"],
                                              "classification": entry.get("classification", {})}))
            print(f"approved {args.key}; the gateway applies it on its next request")
        elif args.command == "reject":
            entry = _pending(store, args.key)
            store.reject(args.key)
            server, _, tool = args.key.partition(":")
            audit.record(audit_event("definition_rejected", verdict="block", server_name=server, tool_name=tool,
                                     details={"user": admin, "schema_hash": entry.get("schema_hash")}))
            print(f"rejected {args.key}; it stays hidden and is recorded again if it is seen again")
        elif args.command == "acceptances":
            users = store.acceptances()
            for user, keys in sorted(users.items()):
                if args.user and user != args.user:
                    continue
                for key, record in sorted(keys.items()):
                    print(f"{user}  {key}  {record['schema_hash']}  accepted {record.get('accepted_at', '?')}")
        elif args.command == "revoke":
            store.revoke(args.user, args.key)
            server, _, tool = args.key.partition(":")
            audit.record(audit_event("acceptance_revoked", verdict="block", server_name=server, tool_name=tool,
                                     details={"user": args.user, "revoked_by": admin}))
            print(f"revoked {args.user}'s acceptance of {args.key}")
    except (KeyError, ValueError, PermissionError) as error:
        print(f"mcp-guard review: {error.args[0] if error.args else error}", file=sys.stderr)
        return 2
    finally:
        audit.close()
    return 0


def _pending(store: ReapprovalStore, key: str) -> dict:
    entry = store.pending().get(key)
    if entry is None:
        raise KeyError(f"nothing pending for {key}")
    return entry


if __name__ == "__main__":
    raise SystemExit(main())
