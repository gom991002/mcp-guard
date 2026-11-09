from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ActivationMode(str, Enum):
    GUARD = "guard"
    DIRECT = "direct"


@dataclass(frozen=True)
class ActivationDecision:
    mode: ActivationMode
    target_url: str
    warning: str = ""


def decide_activation(
    enable_guard: bool,
    gateway_url: str,
    origin_server_url: str,
) -> ActivationDecision:
    if enable_guard:
        if not gateway_url:
            raise ValueError("gateway_url is required when guard is enabled")
        return ActivationDecision(mode=ActivationMode.GUARD, target_url=gateway_url)
    if not origin_server_url:
        raise ValueError("origin_server_url is required when guard is disabled")
    return ActivationDecision(
        mode=ActivationMode.DIRECT,
        target_url=origin_server_url,
        warning="mcp-guard is disabled; direct origin server URLs bypass stage 0 controls",
    )

