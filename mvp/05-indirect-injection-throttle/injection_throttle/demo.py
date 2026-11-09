from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from .throttle import RequestRateThrottle


def main() -> int:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
    throttle = RequestRateThrottle()
    headers = {"User-Agent": "demo-agent/1.0"}
    first_delay = None
    for index in range(70):
        decision = throttle.check("203.0.113.10", headers, now + timedelta(seconds=index * 0.5))
        if decision.should_delay and first_delay is None:
            first_delay = {"request_number": index + 1, **decision.to_dict()}
    print(json.dumps(
        {"first_delayed_request": first_delay, "last_decision": decision.to_dict()},
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
