from __future__ import annotations

import json
import sys
from pathlib import Path

from .audit import audit_event_for_decision
from .models import ToolRegistration
from .policy import evaluate_registration
from .registry import DEFAULT_REGISTRY, GuardRegistry


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or len(args) not in {1, 3}:
        print(
            "Usage: python -m mcp_guard.server [--policy policy.json] <tool-registration.json>",
            file=sys.stderr,
        )
        return 2

    registry = DEFAULT_REGISTRY
    registration_path = args[0]
    if len(args) == 3:
        if args[0] != "--policy":
            print("Usage error: expected --policy <policy.json>", file=sys.stderr)
            return 2
        registry = GuardRegistry.from_path(args[1])
        registration_path = args[2]

    payload = json.loads(Path(registration_path).read_text(encoding="utf-8"))
    registration = ToolRegistration(
        server_name=payload["server_name"],
        namespace=payload["namespace"],
        tool_name=payload["tool_name"],
        description=payload["description"],
        source=payload["source"],
        schema_hash=payload.get("schema_hash"),
    )
    decision = evaluate_registration(registration, registry=registry)
    result = {
        "decision": decision.to_dict(),
        "audit_event": audit_event_for_decision(registration, decision).to_dict(),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

