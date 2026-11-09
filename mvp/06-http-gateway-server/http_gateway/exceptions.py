"""Administrator commands for users' exceptions to the tainted-session send block (D6-49).

Run on the gateway host, against the gateway's state folder. Users choose
their own exceptions on /approve, only among the tools allowed here; each call
in a tainted session still waits for the user's approval of its input.

  python -m http_gateway.exceptions list
  python -m http_gateway.exceptions allow SERVER:TOOL
  python -m http_gateway.exceptions disallow SERVER:TOOL
  python -m http_gateway.exceptions revoke --user USER SERVER:TOOL
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gateway_mvp.taint_exceptions import TaintExceptionStore
from mcp_guard.audit import AuditRecorder, JsonlAuditSink, audit_event, local_user
from .state_storage import check_legacy_state, default_state_dir, verify_state_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state-dir", help="gateway private state folder")
    parser.add_argument("--audit-log", help="append M1 events to the gateway's JSON Lines audit log")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="allowed tools and each user's choices")
    for name, text in (("allow", "let users choose this tool as an exception"),
                       ("disallow", "stop the tool counting as anyone's exception")):
        command = commands.add_parser(name, help=text)
        command.add_argument("key", metavar="SERVER:TOOL")
    revoke = commands.add_parser("revoke", help="remove a tool from one user's exceptions")
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
    store = TaintExceptionStore(state)
    audit = AuditRecorder(JsonlAuditSink(Path(args.audit_log)), path="remote") if args.audit_log else AuditRecorder()
    admin = local_user()
    try:
        if args.command == "list":
            allowed, users = store.allowed(), store.designations()
            if not allowed and not users:
                print("no exceptions")
            for key, entry in sorted(allowed.items()):
                print(f"allowed  {key}  (by {entry.get('allowed_by', '?')}, {entry.get('allowed_at', '?')})")
            for user, keys in sorted(users.items()):
                for key in sorted(keys):
                    state = "" if key in allowed else "  [no longer allowed; not in effect]"
                    print(f"user     {user}  {key}{state}")
            return 0
        server, separator, tool = args.key.partition(":")
        if not (server and separator and tool):
            raise ValueError("give the tool as SERVER:TOOL")
        if args.command == "allow":
            store.allow(args.key, admin)
            print(f"users may now choose {args.key} as an exception on /approve")
        elif args.command == "disallow":
            store.disallow(args.key)
            print(f"{args.key} no longer counts as anyone's exception")
        elif args.command == "revoke":
            store.remove(args.user, args.key)
            print(f"removed {args.key} from {args.user}'s exceptions")
        audit.record(audit_event("taint_exception_changed", user=args.user if args.command == "revoke" else "",
                                 server_name=server, tool_name=tool,
                                 details={"action": args.command, "by": "administrator", "administrator": admin}))
    except (KeyError, ValueError, PermissionError) as error:
        print(f"mcp-guard exceptions: {error.args[0] if error.args else error}", file=sys.stderr)
        return 2
    finally:
        audit.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
