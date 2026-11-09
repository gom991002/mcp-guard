"""Start-up confirmation for a gateway whose sessions are not bound to a user.

Without ``--auth oauth`` the gateway takes the session from the client's
``mcp-guard-session-id`` header, so a client can leave a tainted session by
sending a new id and the M4 removal of external-send tools no longer holds.
The gateway therefore refuses to start in that mode unless someone accepts it:
a window when a desktop is available, otherwise a terminal prompt, otherwise
only ``--accept-unbound-sessions``. Accepting changes no decision; it is
recorded (``startup_override``) so the weaker session binding is visible.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

TITLE = "mcp-guard 보안 경고"
WARNING = (
    "로그인 없이 시작할 경우 MCP 잠금이 해제될 수 있습니다.\n"
    "\n"
    "시험용이 아니면 '아니요'를 누르고\n"
    "로그인을 켜서(--auth oauth) 다시 시작하세요."
)
QUESTION = "그래도 로그인 없이 시작할까요?"
REFUSED = ("refusing to relay tool calls with unbound sessions; use --auth oauth "
           "(or --accept-unbound-sessions to accept the weaker M4 session binding)")


def confirm(accepted_by_flag: bool, *,
            window: Callable[[], bool | None] | None = None,
            prompt: Callable[[str], str] = input,
            interactive: Callable[[], bool] = lambda: sys.stdin.isatty(),
            out: Callable[[str], None] = lambda text: print(text, file=sys.stderr)) -> str:
    """How the operator accepted unbound sessions: "flag", "window", "terminal",
    or "" when they did not (refused, closed, or nobody could be asked)."""
    out(f"[{TITLE}]\n{WARNING}")
    if accepted_by_flag:
        return "flag"
    answer = (window or desktop_window)()
    if answer is not None:  # a window was shown; its answer is final
        return "window" if answer else ""
    if not interactive():
        return ""
    try:
        reply = prompt(f"{QUESTION} [y/N]: ")
    except EOFError:
        return ""
    return "terminal" if reply.strip().lower() in ("y", "yes") else ""


def desktop_window() -> bool | None:
    """Yes/no in a native window (Tk, standard library); None when no window can
    be shown: no display, no Tk, or a headless host such as a container."""
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY")
                                                 or os.environ.get("WAYLAND_DISPLAY")):
        return None
    try:
        import tkinter
        from tkinter import messagebox
    except ImportError:
        return None
    try:
        root = tkinter.Tk()
    except tkinter.TclError:
        return None
    try:
        root.withdraw()
        root.attributes("-topmost", True)  # start-up is blocked until it is answered
        return bool(messagebox.askyesno(TITLE, f"{WARNING}\n\n{QUESTION}", icon="warning",
                                        default="no", parent=root))
    finally:
        root.destroy()
