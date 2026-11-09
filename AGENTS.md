# Agent Instructions

## Project Context

This repository is the scaffold for `mcp-guard`, an MCP tool impersonation protection service based on the user's architecture drawings in `Docs/Core_images/` (v2, A-01, A-02).

A-01 and A-02 are the latest reference. When docs, code, or the v2 drawing disagree, unify on A-01 and A-02.

Keep the project aligned with these design anchors:

- Run before MCP connections are trusted.
- Support local proxy and remote gateway paths; both run the same inspection core.
- Preserve the 0-4 stage defense model and the attack types it maps to (0, ①–③, out of scope).
- Track M1-M5 inspection markers and the other module IDs (L1–L4, C1–C3, 2-A5, 3-A4, B) as defined in `Docs/Core_mds/architecture.md`.
- A controls make decisions. B signals only raise risk; they never relax a decision, clear taint, or skip approval. In code, B findings use `RuleAction.SIGNAL` and can raise a verdict to `review`, never to `block`.
- Label every finding and rule with `marker` and `stage`. Code prefix: the drawing ID (`M2_`), `B_` for signals, or `S<stage>_` for A checks without a drawing ID. Never put a client-side ID (L1, C1) on a core check.
- Keep `src/mcp_guard` as the single engine of record; rule drafts under `mvp/` reuse its models and stay parity-tested.
- Do not describe a control as implemented unless code and tests support it.

## Working Rules

- Prefer small, auditable changes.
- Keep documentation and code behavior aligned. When they diverge, record it in `SECURITY.md` under "Known Divergences From Design".
- When docs state something that is not in the drawings, tag its origin the way `Docs/Core_mds/architecture.md` describes.
- Use standard library Python unless a dependency is clearly needed.
- Run `python -m unittest discover -s tests` with `PYTHONPATH=src` (as in CI and `README.md`) before claiming the scaffold passes tests.
- Do not commit generated files such as `__pycache__`, coverage output, or virtual environments.
