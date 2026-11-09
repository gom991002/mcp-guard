"""L1 client config rendering, L3 config watch and rewrap, L4 hook settings, approvals.

Configuration is non-exclusive (decision): nothing stops a user from adding
other servers. Only servers the user chose to guard are wrapped or routed to
the gateway; servers marked ``guard: false`` are written as configured. The
security mechanisms stay: the L2 wrapper, L3 rewrap of guarded entries, and
the L4 hook. The guard yes/no branch uses MVP 8 ``decide_activation``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Any

from decision_controls.activation import ActivationMode, decide_activation
from mcp_guard.audit import AuditFinding, AuditRecorder, audit_event, local_user
from mcp_guard.stage1 import tree_digest, verify_stage1

from .approvals import LocalApprovals, approve_pending, revoke_user_approval
from .manifest import GATEWAY_SERVER_NAME, GuardManifest

_HERE = Path(__file__).resolve().parents[1]
WRAP_LAUNCHER = _HERE / "mcp_guard_wrap.py"
HOOK_LAUNCHER = _HERE / "mcp_guard_hook.py"


def wrapped_entry(manifest: GuardManifest, name: str, entry: dict[str, Any]) -> dict[str, Any]:
    args = [
        str(WRAP_LAUNCHER), "--policy", manifest.policy, "--approvals", manifest.approvals,
        "--record-pending", manifest.pending, "--manifest", str(manifest.path),
    ]
    if manifest.allow_user_approval:
        args += ["--user-approvals", manifest.user_approvals]
    if manifest.audit_log:
        args += ["--audit-log", manifest.audit_log]
    args += ["--server-name", name, "--namespace", entry["namespace"],
             "--", entry["command"], *entry.get("args", [])]
    rendered: dict[str, Any] = {"type": "stdio", "command": manifest.python, "args": args}
    if entry.get("env"):
        rendered["env"] = dict(entry["env"])
    return rendered


def render_claude_code(manifest: GuardManifest) -> dict[str, Any]:
    """Content for a Claude Code .mcp.json (project or user scope, non-exclusive)."""
    servers: dict[str, Any] = {}
    use_gateway = False
    for name, entry in manifest.servers.items():
        if "url" in entry:
            decision = decide_activation(entry["guard"], manifest.gateway_url, entry["url"])
            if decision.mode == ActivationMode.GUARD:
                use_gateway = True
            else:
                servers[name] = {"type": "http", "url": decision.target_url}
        elif entry["guard"]:
            servers[name] = wrapped_entry(manifest, name, entry)
        else:
            servers[name] = {"type": "stdio", "command": entry["command"],
                             "args": list(entry.get("args", []))}
            if entry.get("env"):
                servers[name]["env"] = dict(entry["env"])
    if use_gateway:
        servers[GATEWAY_SERVER_NAME] = {"type": "http", "url": manifest.gateway_url}
    return {"mcpServers": servers}


def render_claude_desktop(manifest: GuardManifest) -> dict[str, Any]:
    """claude_desktop_config.json takes local servers; remote ones become connectors (C1).

    Claude Desktop starts servers from a folder of its own and needs absolute
    paths, so the guard's file paths must be absolute here; otherwise the
    wrapper could not load its policy and every guarded server would fail to start.
    """
    if manifest.guarded_local():
        relative = [f"{name} ({value})" for name, value in _guard_paths(manifest) if not Path(value).is_absolute()]
        if relative:
            raise ValueError("Claude Desktop needs absolute paths in the manifest: " + ", ".join(relative))
    servers = {}
    for name, entry in render_claude_code(manifest)["mcpServers"].items():
        if entry["type"] == "stdio":
            servers[name] = {k: v for k, v in entry.items() if k != "type"}
    return {"mcpServers": servers}


def _guard_paths(manifest: GuardManifest) -> list[tuple[str, str]]:
    paths = [("policy", manifest.policy), ("approvals", manifest.approvals), ("pending", manifest.pending)]
    if manifest.allow_user_approval:
        paths.append(("user_approvals", manifest.user_approvals))
    if manifest.audit_log:
        paths.append(("audit_log", manifest.audit_log))
    return paths


def _trusted_publishers(manifest: GuardManifest) -> frozenset[str]:
    from mcp_guard.registry import GuardRegistry

    return GuardRegistry.from_path(manifest.policy).trusted_registry_publishers


def render_claude_code_settings(manifest: GuardManifest) -> dict[str, Any]:
    """Claude Code settings with the L4 hook only; no server allow-list (non-exclusive)."""
    hook = [{"type": "command",
             "command": f'"{manifest.python}" "{HOOK_LAUNCHER}" --manifest "{manifest.path}"'}]
    judged = "|".join(["mcp__.*", *(re.escape(t) for t in manifest.guarded_builtins)])
    # Exceptions also run PostToolUse so an approved run can be recorded (3-A4).
    sources = "|".join(dict.fromkeys([*manifest.taint_sources,
                                      *(re.escape(t) for t in sorted(manifest.taint_exceptions))]))
    return {"hooks": {
        "PreToolUse": [{"matcher": f"^({judged})$", "hooks": hook}],
        "PostToolUse": [{"matcher": f"^({sources})$", "hooks": hook}],
    }}


def rewrap(manifest: GuardManifest, config_path: Path, flavor: str) -> list[str]:
    """L3: restore guarded entries in a client config; return what changed."""
    render = render_claude_desktop if flavor == "claude-desktop" else render_claude_code
    expected = render(manifest)["mcpServers"]
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    servers = config.setdefault("mcpServers", {})
    changes: list[str] = []
    guarded = manifest.guarded_local()
    for name in guarded:
        if servers.get(name) != expected[name]:
            changes.append(f"{'rewrapped' if name in servers else 'added'} {name}")
            servers[name] = expected[name]
    originals = {
        (entry["command"], tuple(entry.get("args", []))): name for name, entry in guarded.items()
    }
    guarded_urls = {e["url"].rstrip("/") for e in manifest.servers.values() if e["guard"] and "url" in e}
    for name, entry in list(servers.items()):
        if name in guarded or not isinstance(entry, dict):
            continue
        original = originals.get((entry.get("command"), tuple(entry.get("args", []))))
        if original:
            servers[name] = wrapped_entry(manifest, original, guarded[original])
            if flavor == "claude-desktop":
                servers[name].pop("type")
            changes.append(f"rewrapped unguarded copy {name} of {original}")
        elif str(entry.get("url", "")).rstrip("/") in guarded_urls:
            del servers[name]
            changes.append(f"removed direct copy {name} of a guarded remote server")
    if GATEWAY_SERVER_NAME in expected and servers.get(GATEWAY_SERVER_NAME) != expected[GATEWAY_SERVER_NAME]:
        servers[GATEWAY_SERVER_NAME] = expected[GATEWAY_SERVER_NAME]
        changes.append(f"restored {GATEWAY_SERVER_NAME} gateway entry")
    if changes:
        if config_path.exists():
            shutil.copyfile(config_path, config_path.with_suffix(config_path.suffix + ".bak"))
        temporary = config_path.with_suffix(config_path.suffix + ".tmp")
        temporary.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, config_path)
    return changes


def rewrap_and_record(manifest: GuardManifest, config_path: Path, flavor: str,
                      audit: AuditRecorder) -> list[str]:
    """L3 rewrap, recording each change: the log is the only trace of a bypass attempt."""
    changes = rewrap(manifest, config_path, flavor)
    for change in changes:
        audit.record(audit_event("config_rewrapped", client=flavor,
                                 details={"config": str(config_path), "change": change}))
    return changes


def watch(manifest: GuardManifest, config_path: Path, flavor: str,
          interval: float, stop: threading.Event) -> None:
    """Poll the config file and rewrap whenever it changes."""
    audit = manifest.audit_recorder()
    last = None
    while not stop.is_set():
        mtime = config_path.stat().st_mtime_ns if config_path.exists() else None
        if mtime != last:
            for change in rewrap_and_record(manifest, config_path, flavor, audit):
                print(f"mcp-guard L3: {change} in {config_path}", flush=True)
            last = config_path.stat().st_mtime_ns if config_path.exists() else None
        stop.wait(interval)


def approve_and_record(manifest: GuardManifest, server: str, tools: list[str] | None,
                       as_user: bool, external_send: bool | None = None) -> list[str]:
    """Approve pending definitions and record who approved which definition (D6-18)."""
    target = manifest.user_approvals if as_user else manifest.approvals
    names = approve_pending(manifest.pending, target, server, tools, external_send)
    approved = LocalApprovals.from_path(target)
    audit = manifest.audit_recorder()
    namespace = approved.servers.get(server, {}).get("namespace", "")
    for name in names:
        registration = approved.approved(server, namespace, name)
        audit.record(audit_event(
            "definition_approved", verdict="allow", server_name=server, namespace=namespace,
            tool_name=name, details={"approver": "user" if as_user else "service",
                                     "schema_hash": registration.schema_hash if registration else None}))
    return names


def dependency_lock_path(manifest: GuardManifest, server: str) -> Path:
    spec = manifest.guarded_local()[server].get("stage1") or {}
    return Path(spec.get("dependency_lock") or manifest.path.with_name("dependency-locks") /
                f"{server}.json")


def lock_and_record(manifest: GuardManifest, server: str) -> tuple[dict[str, Any], Path]:
    """Stage 1: check every installed dependency and write the lock to pin (D6-31)."""
    from mcp_guard.dependencies import build_dependency_lock

    entry = manifest.guarded_local()[server]
    lock = build_dependency_lock(entry)
    path = dependency_lock_path(manifest, server)
    _write_json(path, lock)
    _record_lock(manifest, server, entry, "dependencies_checked", lock)
    return lock, path


def accept_lock_and_record(manifest: GuardManifest, server: str,
                           as_user: bool) -> tuple[dict[str, Any], Path]:
    from mcp_guard.dependencies import accept_dependency_lock

    entry = manifest.guarded_local()[server]
    path = dependency_lock_path(manifest, server)
    lock = json.loads(path.read_text(encoding="utf-8"))
    lock = accept_dependency_lock(lock, "user" if as_user else "service", local_user())
    _write_json(path, lock)
    _record_lock(manifest, server, entry, "dependencies_reviewed", lock)
    return lock, path


def _record_lock(manifest: GuardManifest, server: str, entry: dict[str, Any], event_type: str,
                 lock: dict[str, Any]) -> None:
    findings = lock["findings"]
    verdicts = {f["verdict"] for f in findings}
    verdict = ("allow" if event_type == "dependencies_reviewed" or not findings else
               "block" if "block" in verdicts else "review")
    unique = sorted({(f["code"], f["marker"]) for f in findings})
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["code"]] = counts.get(finding["code"], 0) + 1
    details: dict[str, Any] = {"packages": len(lock["packages"]), "finding_counts": counts,
                               "findings_sha256": lock["findings_sha256"],
                               "install_tree_sha256": lock["install_tree_sha256"]}
    if lock.get("accepted"):
        details["approver"] = lock["accepted"]["approver"]
    manifest.audit_recorder().record(audit_event(
        event_type, server_name=server, namespace=entry.get("namespace", ""), verdict=verdict,
        finding_codes=tuple(code for code, _ in unique),
        findings=tuple(AuditFinding(code, marker, "1-integration") for code, marker in unique),
        details=details))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def scan_and_record(manifest: GuardManifest, server: str) -> dict[str, Any]:
    """Stage 1 B: Semgrep over the code stage 1 pinned; write and record the report (D6-30)."""
    from . import code_scan

    entry = manifest.guarded_local()[server]
    # scan only code whose hashes match the approval (the publisher list is applied at launch)
    verify_stage1(entry, b_scored_elsewhere=manifest.b_scored_elsewhere())
    settings = manifest.code_scan
    body = code_scan.run_semgrep(code_scan.scan_targets(entry),
                                 code_scan.find_semgrep(settings.get("semgrep", "")),
                                 timeout=settings.get("timeout", code_scan.DEFAULT_TIMEOUT_SECONDS))
    body = code_scan.similar_to_known_malware(
        body, code_scan.scan_targets(entry), entry, settings.get("similarity_feed"))  # D6-36
    guarddog = None
    gd_settings = settings.get("guarddog") or {}
    provider = (entry.get("stage1") or {}).get("provider")
    if gd_settings.get("enabled") and provider in {"npm", "pypi"}:  # D6-37
        guarddog = code_scan.guarddog_packages(entry, gd_settings)
        body["guarddog"] = {"status": guarddog["status"], "image": code_scan.GUARDDOG_IMAGE,
                            "reason": guarddog.get("reason", ""), "failed": guarddog.get("failed", []),
                            "results": guarddog["results"]}
        if guarddog["status"] == "unavailable":
            body["findings"].append({"code": code_scan.GUARDDOG_UNAVAILABLE, "path": "", "line": 0,
                                     "message": guarddog["reason"]})
        for label in guarddog.get("failed", []):
            body["findings"].append({"code": code_scan.GUARDDOG_UNAVAILABLE, "path": "", "line": 0,
                                     "message": f"guarddog failed on {label}"})
    body["packages"] = code_scan.score_packages(entry, body, guarddog)  # D6-35
    report = code_scan.new_report(server, entry, body)
    code_scan.write_report(code_scan.report_path(settings["reports"], server), report)
    held = code_scan.review_codes(report)
    codes = tuple(sorted(set(code_scan.finding_codes(report)) | set(held)))
    manifest.audit_recorder().record(audit_event(
        "code_scanned", server_name=server, namespace=entry.get("namespace", ""),
        verdict="review" if held else "allow", finding_codes=codes,
        findings=tuple(AuditFinding(c, "B", code_scan.STAGE) for c in codes),
        details=code_scan.summary(report)))
    return report


def explain_and_record(manifest: GuardManifest, server: str) -> tuple[dict[str, Any], Path]:
    """Advisory LLM summary of the held packages in the current report (D6-36)."""
    from . import code_scan, review_assist

    settings = manifest.review_assist
    if not settings.get("enabled"):
        raise ValueError("review_assist is not enabled in the manifest")
    error = review_assist.settings_error(settings)
    if error:
        raise ValueError(error)
    entry = manifest.guarded_local()[server]
    path = code_scan.report_path(manifest.code_scan["reports"], server)
    report = code_scan.load_report(path)
    status, reason = code_scan.report_status(report, entry, manifest.code_scan.get("similarity_feed"))
    if status in {"missing", "stale"}:
        raise ValueError(reason)
    held = [p for p in report.get("packages", []) if p["score"]["raise_review"]]
    result = review_assist.explain(report, settings, held)
    out = path.with_suffix(".review.json")
    _write_json(out, result)
    manifest.audit_recorder().record(audit_event(
        "review_assisted", server_name=server, namespace=entry.get("namespace", ""),
        details={"advisory": True, "model": result["model"], "endpoint": result["endpoint"],
                 "items": [{k: item[k] for k in ("package", "assessment", "code_aimed_at_ai_reviewer",
                                                 "prompt_sha256")} for item in result["items"]]}))
    return result, out


def accept_scan_and_record(manifest: GuardManifest, server: str, as_user: bool) -> dict[str, Any]:
    """Accept the findings of a current report; the wrapper then starts the server."""
    from . import code_scan

    entry = manifest.guarded_local()[server]
    path = code_scan.report_path(manifest.code_scan["reports"], server)
    report = code_scan.load_report(path)
    status, reason = code_scan.report_status(report, entry, manifest.code_scan.get("similarity_feed"))
    if status in {"missing", "stale"}:
        raise ValueError(reason)  # accept only findings made over the current code and rules
    report = code_scan.accept(report, "user" if as_user else "service", local_user())
    code_scan.write_report(path, report)
    codes = code_scan.finding_codes(report)
    manifest.audit_recorder().record(audit_event(
        "code_scan_reviewed", verdict="allow", server_name=server,
        namespace=entry.get("namespace", ""), finding_codes=codes,
        findings=tuple(AuditFinding(c, "B", code_scan.STAGE) for c in codes),
        details={**code_scan.summary(report), "approver": report["accepted"]["approver"]}))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mcp-guard client entry configuration")
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render", help="write a client or policy config (L1, C1)")
    render.add_argument("--manifest", required=True)
    render.add_argument("--target", required=True,
                        choices=("claude-code", "claude-desktop", "claude-code-settings"))
    render.add_argument("--output", type=Path)
    fix = commands.add_parser("rewrap", help="restore guarded entries in a config (L3)")
    fix.add_argument("--manifest", required=True)
    fix.add_argument("--config", required=True, type=Path)
    fix.add_argument("--flavor", choices=("claude-code", "claude-desktop"), default="claude-code")
    fix.add_argument("--watch", type=float, metavar="SECONDS")
    allow = commands.add_parser("approve", help="approve pending local tool definitions (L2)")
    allow.add_argument("--manifest", required=True)
    allow.add_argument("--server", required=True)
    allow.add_argument("--tool", action="append", help="tool to approve (repeatable); default all")
    allow.add_argument("--as-user", action="store_true",
                       help="write to the user's approvals (needs allow_user_approval)")
    allow.add_argument("--external-send", choices=("yes", "no"),
                       help="mark the approved tools as sending data out or not (M5, D6-42)")
    take_back = commands.add_parser("revoke", help="remove a tool from the user's approvals (D6-45)")
    take_back.add_argument("--manifest", required=True)
    take_back.add_argument("--server", required=True)
    take_back.add_argument("--tool", required=True)
    show = commands.add_parser("pending", help="list definitions waiting for approval")
    show.add_argument("--manifest", required=True)
    check = commands.add_parser("check-stage1", help="check a guarded local server before connection")
    check.add_argument("--manifest", required=True)
    check.add_argument("--server", required=True)
    deps = commands.add_parser("deps", help="stage 1 dependency lock for an npm or pypi server")
    deps.add_argument("--manifest", required=True)
    deps.add_argument("--server", required=True)
    deps.add_argument("--accept", action="store_true",
                      help="accept the review findings of the current lock")
    deps.add_argument("--as-user", action="store_true",
                      help="accept as the user (needs allow_user_approval)")
    scan = commands.add_parser("scan", help="stage 1 code-behavior scan with Semgrep (B)")
    scan.add_argument("--manifest", required=True)
    scan.add_argument("--server", required=True)
    scan.add_argument("--accept", action="store_true",
                      help="accept the findings of the current report instead of scanning")
    scan.add_argument("--explain", action="store_true",
                      help="advisory LLM summary of held packages (review_assist; changes nothing)")
    scan.add_argument("--as-user", action="store_true",
                      help="accept as the user (needs allow_user_approval)")
    feed_command = commands.add_parser("refresh-similarity", help="download a pinned similarity feed")
    feed_command.add_argument("--manifest", required=True)
    fingerprint = commands.add_parser("fingerprint", help="show SHA-256 for a local file or install tree")
    fingerprint.add_argument("--path", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "fingerprint":
        if args.path.is_symlink():
            parser.error("path must not be a symbolic link")
        path = args.path.resolve()
        if not path.exists():
            parser.error("path must be an existing file or directory")
        if path.is_dir():
            value = tree_digest(path)
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            value = digest.hexdigest()
        else:
            parser.error("path must be an existing file or directory")
        print(value)
        return 0
    manifest = GuardManifest.from_path(args.manifest)
    if args.command == "refresh-similarity":
        from mcp_guard.similarity_feed import refresh

        feed = manifest.code_scan.get("similarity_feed")
        if not feed:
            parser.error("code_scan.similarity_feed is not configured")
        try:
            print(json.dumps(refresh(feed["url"], feed["sha256"], feed["path"]), sort_keys=True))
        except (OSError, ValueError) as error:
            parser.error(str(error))
        return 0
    if args.command == "check-stage1":
        entry = manifest.guarded_local().get(args.server)
        if entry is None:
            parser.error("server is not a guarded local entry")
        print(json.dumps(verify_stage1(entry, b_scored_elsewhere=manifest.b_scored_elsewhere(),
                                       trusted_publishers=_trusted_publishers(manifest)),
                         sort_keys=True))
        return 0
    if args.command == "deps":
        entry = manifest.guarded_local().get(args.server)
        if entry is None or (entry.get("stage1") or {}).get("provider") not in {"npm", "pypi"}:
            parser.error("server is not a guarded npm or pypi entry")
        if args.as_user and not (args.accept and manifest.allow_user_approval):
            parser.error("--as-user needs --accept and allow_user_approval")
        from mcp_guard.stage1 import Stage1Error

        try:
            lock, path = (accept_lock_and_record(manifest, args.server, args.as_user) if args.accept
                          else lock_and_record(manifest, args.server))
        except (OSError, ValueError) as error:
            code = error.code if isinstance(error, Stage1Error) else "S1_DEPENDENCY_LOCK_MISSING"
            parser.error(f"{code}: {error}")
        for finding in lock["findings"]:
            print(f"{finding['verdict']:6} {finding['code']} {finding['package']} {finding['detail']}")
        blocked = any(f["verdict"] == "block" for f in lock["findings"])
        print(f"{len(lock['packages'])} package(s), {len(lock['findings'])} finding(s); lock: {path}")
        if blocked:
            print("blocked: remove or replace the flagged packages, reinstall, and lock again")
            return 1
        if lock["findings"] and not lock.get("accepted"):
            print("review the findings, then run: deps --accept")
        print(f'pin in stage1: "dependency_lock": "{path}", '
              f'"dependency_lock_sha256": "{hashlib.sha256(path.read_bytes()).hexdigest()}"')
        return 0
    if args.command == "scan":
        if args.server not in manifest.guarded_local():
            parser.error("server is not a guarded local entry")
        if (manifest.guarded_local()[args.server].get("stage1") or {}).get("provider") == "docker":
            print("not applicable: Docker images are not scanned; Docker verifies the image "
                  "signature (D6-34)")
            return 0
        if args.as_user and not (args.accept and manifest.allow_user_approval):
            parser.error("--as-user needs --accept and allow_user_approval")
        if args.explain:
            from . import review_assist

            if not review_assist.is_local(manifest.review_assist):
                print(f"note: code excerpts are sent to {manifest.review_assist.get('base_url')}")
            try:
                result, out = explain_and_record(manifest, args.server)
            except ValueError as error:
                parser.error(str(error))
            for item in result["items"]:
                flag = " [code contains text aimed at AI reviewers]" if item["code_aimed_at_ai_reviewer"] else ""
                print(f"{item['assessment']:13} {item['package']}{flag}")
                for reason in item["reasons"]:
                    print(f"    - {reason}")
            print(f"advisory only; nothing was accepted. written to {out}")
            return 0
        if args.accept:
            try:
                report = accept_scan_and_record(manifest, args.server, args.as_user)
            except ValueError as error:
                parser.error(str(error))
            print(f"accepted {len(report['findings'])} code scan finding(s) for {args.server}")
            return 0
        from . import code_scan

        report = scan_and_record(manifest, args.server)
        for finding in report["findings"]:
            print(f"{finding['code']} {finding['path']}:{finding['line']} {finding['message']}")
        for package in report.get("packages", []):
            result = package["score"]
            label = f"{package['name']}@{package['version']}" if package["name"] else "(unpackaged)"
            print(f"{'HELD' if result['raise_review'] else 'ok':4} {label} "
                  f"score={result['probability']} threshold={result['threshold']} "
                  f"signals={','.join(result['signals'])}")
        print(f"{len(report['findings'])} finding(s) in {report['scanned_files']} file(s), "
              f"{len(code_scan.review_items(report))} item(s) to review; "
              f"report: {Path(manifest.code_scan['reports']) / (args.server + '.json')}")
        return 0
    if args.command == "pending":
        pending = Path(manifest.pending)
        print(pending.read_text(encoding="utf-8") if pending.exists() else '{"servers": {}}')
        return 0
    if args.command == "approve":
        # The service (administrator) approves by default; a user may approve
        # their own tools only when the administrator's manifest allows it.
        if args.as_user and not manifest.allow_user_approval:
            parser.error("user approval is not allowed by this manifest")
        if args.as_user and args.external_send == "no":
            parser.error("only the administrator can mark a tool as not sending data out")
        if args.as_user:  # D6-45: users approve only low-risk changes to approved tools
            pending_entry = {}
            if Path(manifest.pending).exists():
                pending_entry = json.loads(Path(manifest.pending).read_text(encoding="utf-8")).get(
                    "servers", {}).get(args.server, {})
            refused = [t["name"] for t in pending_entry.get("tools", [])
                       if (not args.tool or t["name"] in args.tool)
                       and not (t.get("reapproval") or {}).get("user_acceptable")]
            if refused:
                parser.error(f"only an administrator can approve {', '.join(sorted(refused))}: "
                             "new tools and risky changes need the administrator (D6-45)")
        target = manifest.user_approvals if args.as_user else manifest.approvals
        pending_file = Path(manifest.pending)
        if pending_file.exists():  # D6-38 follow-up: notes for the approver
            entry = json.loads(pending_file.read_text(encoding="utf-8")).get("servers", {}).get(args.server, {})
            for tool in entry.get("tools", []):
                note = tool.get("extends")
                if note and (not args.tool or tool["name"] in args.tool):
                    print(f"note: {tool['name']} extends {note['tool']} of server {note['server']} "
                          "by one word; check it is not imitating that tool")
                hint = tool.get("sends_data_hint")
                if hint and args.external_send is None and (not args.tool or tool["name"] in args.tool):
                    print(f"note: {tool['name']} may send data out ({hint}); it counts as sending "
                          "unless approved with --external-send no")
        names = approve_and_record(manifest, args.server, args.tool, args.as_user,
                                   {"yes": True, "no": False}.get(args.external_send or ""))
        print(f"approved {', '.join(names) or 'nothing'} for {args.server} in {target}")
        return 0
    if args.command == "revoke":
        if not manifest.user_approvals or not Path(manifest.user_approvals).exists():
            parser.error("this manifest has no user approvals file")
        try:
            removed = revoke_user_approval(manifest.user_approvals, args.server, args.tool)
        except ValueError as error:
            parser.error(str(error))
        manifest.audit_recorder().record(audit_event(
            "acceptance_revoked", verdict="block", server_name=args.server, tool_name=args.tool,
            details={"user": "local user", "revoked_by": local_user(),
                     "schema_hash": removed.get("schema_hash")}))
        print(f"removed {args.tool} of {args.server} from the user's approvals")
        return 0
    if args.command == "render":
        renderer = {"claude-code": render_claude_code, "claude-desktop": render_claude_desktop,
                    "claude-code-settings": render_claude_code_settings}[args.target]
        try:
            text = json.dumps(renderer(manifest), ensure_ascii=False, indent=2)
        except ValueError as error:
            parser.error(str(error))
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return 0
    if args.watch:
        watch(manifest, args.config, args.flavor, args.watch, threading.Event())
        return 0
    for change in rewrap_and_record(manifest, args.config, args.flavor, manifest.audit_recorder()):
        print(f"mcp-guard L3: {change}")
    return 0
