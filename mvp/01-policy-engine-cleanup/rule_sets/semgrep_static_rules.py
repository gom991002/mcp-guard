from __future__ import annotations

from dataclasses import dataclass

from .common import Rule, RuleAction, RuleFamily, Severity

# Semgrep accepts LOW / MEDIUM / HIGH / CRITICAL.
_SEMGREP_SEVERITY = {
    Severity.INFO: "LOW",
    Severity.WARNING: "MEDIUM",
    Severity.CRITICAL: "CRITICAL",
}


@dataclass(frozen=True)
class SemgrepRuleSpec:
    rule: Rule
    languages: tuple[str, ...]
    message: str
    # Alternatives: a match on any one of them is a hit.
    patterns: tuple[str, ...]
    # Optional regex on one metavariable ($PATH by default) to narrow the hit.
    path_regex: str | None = None
    regex_metavariable: str = "$PATH"
    # Code inside any of these does not match (e.g. function bodies).
    not_inside: tuple[str, ...] = ()

    @property
    def semgrep_id(self) -> str:
        # One Rule may have a spec per language; Semgrep ids must stay unique.
        suffix = "" if self.languages == ("python",) else "-" + self.languages[0]
        return self.rule.rule_id.lower() + suffix

    def to_semgrep_dict(self) -> dict[str, object]:
        # In Semgrep, `patterns` is AND and `pattern-either` is OR.
        either = {"pattern-either": [{"pattern": pattern} for pattern in self.patterns]}
        parts: list[dict[str, object]] = [either]
        if self.path_regex is not None:
            parts.append({"metavariable-regex": {"metavariable": self.regex_metavariable,
                                                 "regex": self.path_regex}})
        parts += [{"pattern-not-inside": pattern} for pattern in self.not_inside]
        body: dict[str, object] = either if len(parts) == 1 else {"patterns": parts}
        return {
            "id": self.semgrep_id,
            "message": self.message,
            "severity": _SEMGREP_SEVERITY[self.rule.severity],
            "languages": list(self.languages),
            **body,
        }


def _rule(rule_id: str, title: str, description: str, tags: tuple[str, ...]) -> Rule:
    # Stage 1 "B · 코드 행동 분석": a signal only, never a block decision (A-01).
    return Rule(
        rule_id=rule_id,
        family=RuleFamily.SEMGREP_STATIC,
        title=title,
        stage="1-integration",
        marker="B",
        severity=Severity.WARNING,
        default_action=RuleAction.SIGNAL,
        description=description,
        tags=tags,
    )


_PROCESS_EXECUTION = _rule(
    "B_CODE_PROCESS_EXECUTION",
    "Process execution in MCP server",
    "Finds code paths that execute shell or child processes.",
    ("static-analysis", "process-exec"),
)
_DYNAMIC_NETWORK_REQUEST = _rule(
    "B_CODE_DYNAMIC_NETWORK_REQUEST",
    "Dynamic network request",
    "Finds network calls that may send user data to a URL.",
    ("static-analysis", "network"),
)
_SECRET_FILE_READ = _rule(
    "B_CODE_SECRET_FILE_READ",
    "Credential file read",
    "Finds reads of common secret files, not every file read.",
    ("static-analysis", "credential"),
)
_DYNAMIC_EVAL = _rule(
    "B_CODE_DYNAMIC_EVAL",
    "Dynamic code evaluation",
    "Finds code that runs strings as code (eval, exec, new Function).",
    ("static-analysis", "eval"),
)
_DECODE_AND_EXECUTE = _rule(
    "B_CODE_DECODE_AND_EXECUTE",
    "Decoded payload executed",
    "Finds encoded or compressed data that is decoded and run as code.",
    ("static-analysis", "obfuscation"),
)
_ENV_HARVEST = _rule(
    "B_CODE_ENV_HARVEST",
    "Whole environment collected",
    "Finds code that copies or serialises the whole process environment.",
    ("static-analysis", "credential"),
)
_IMPORT_TIME = _rule(
    "B_CODE_IMPORT_TIME_EXECUTION",
    "Code runs on import",
    "Finds process, network or dynamic-code calls at module top level: they run "
    "as soon as the package is imported, not when a function is called.",
    ("static-analysis", "import-time"),
)
_SECRET_PATH = r".*(\.env|\.ssh|id_rsa|\.aws|credentials|\.npmrc|\.pypirc).*"
_JS = ("javascript", "typescript")

# Our own rules only: Semgrep Registry rules are licensed for internal use and
# not for a competing product or service (D6-30). Python and npm packages are
# covered; Docker images are not scanned.
SEMGREP_STATIC_RULES: tuple[SemgrepRuleSpec, ...] = (
    SemgrepRuleSpec(
        rule=_PROCESS_EXECUTION,
        languages=("python",),
        message="MCP server executes a process; review sandbox and arguments.",
        patterns=(
            "subprocess.run(...)",
            "subprocess.Popen(...)",
            "subprocess.call(...)",
            "subprocess.check_output(...)",
            "subprocess.check_call(...)",
            "os.system(...)",
            "os.popen(...)",
            "pty.spawn(...)",
        ),
    ),
    SemgrepRuleSpec(
        rule=_DYNAMIC_NETWORK_REQUEST,
        languages=("python",),
        message="MCP server makes network requests; review destination controls.",
        patterns=(
            "requests.get($URL, ...)",
            "requests.post($URL, ...)",
            "requests.request(...)",
            "httpx.get($URL, ...)",
            "httpx.post($URL, ...)",
            "urllib.request.urlopen($URL, ...)",
            "urllib.request.Request($URL, ...)",
            "http.client.HTTPSConnection(...)",
            "socket.socket(...)",
        ),
    ),
    SemgrepRuleSpec(
        rule=_SECRET_FILE_READ,
        languages=("python",),
        message="MCP server may read secrets; review least-privilege boundary.",
        patterns=(
            "open($PATH, ...)",
            "Path($PATH).read_text(...)",
        ),
        path_regex=_SECRET_PATH,
    ),
    SemgrepRuleSpec(
        rule=_PROCESS_EXECUTION,
        languages=_JS,
        message="MCP server executes a process; review sandbox and arguments.",
        patterns=(
            "require($MOD).$F(...)",
            "$CP = require($MOD);\n...\n$CP.$F(...)",
            "const {..., $F, ...} = require($MOD);\n...\n$F(...)",
            "import $CP from $MOD;\n...\n$CP.$F(...)",
            "import * as $CP from $MOD;\n...\n$CP.$F(...)",
            "import {..., $F, ...} from $MOD;\n...\n$F(...)",
        ),
        # Semgrep may bind a string literal with its quotes.
        path_regex=r"""^['"]?(node:)?child_process['"]?$""",
        regex_metavariable="$MOD",
    ),
    SemgrepRuleSpec(
        rule=_DYNAMIC_NETWORK_REQUEST,
        languages=_JS,
        message="MCP server makes network requests; review destination controls.",
        patterns=(
            "fetch($URL, ...)",
            "axios.post($URL, ...)",
            "axios.get($URL, ...)",
            "https.request(...)",
            "https.get(...)",
            "http.request(...)",
            "http.get(...)",
        ),
    ),
    SemgrepRuleSpec(
        rule=_SECRET_FILE_READ,
        languages=_JS,
        message="MCP server may read secrets; review least-privilege boundary.",
        patterns=(
            "fs.readFileSync($PATH, ...)",
            "fs.readFile($PATH, ...)",
            "fs.promises.readFile($PATH, ...)",
            "readFileSync($PATH, ...)",
        ),
        path_regex=_SECRET_PATH,
    ),
    # Added 2026-11-02 for the stage 1 B score (D6-35), from general supply
    # chain techniques and before looking at the training data. No indicator
    # strings (webhook hosts, attacker domains): the labelled malware was mostly
    # found by such rules, which would inflate the measured accuracy.
    SemgrepRuleSpec(
        rule=_DYNAMIC_EVAL,
        languages=("python",),
        message="MCP server runs strings as code; review where they come from.",
        patterns=("exec(...)", "eval(...)"),
    ),
    SemgrepRuleSpec(
        rule=_DYNAMIC_EVAL,
        languages=_JS,
        message="MCP server runs strings as code; review where they come from.",
        patterns=("eval(...)", "new Function(...)"),
    ),
    SemgrepRuleSpec(
        rule=_DECODE_AND_EXECUTE,
        languages=("python",),
        message="MCP server decodes data and runs it as code.",
        patterns=(
            "exec(base64.b64decode(...), ...)",
            "exec(zlib.decompress(...), ...)",
            "exec(marshal.loads(...), ...)",
            "exec(codecs.decode(...), ...)",
            "eval(base64.b64decode(...), ...)",
            "exec(compile(base64.b64decode(...), ...), ...)",
        ),
    ),
    SemgrepRuleSpec(
        rule=_DECODE_AND_EXECUTE,
        languages=_JS,
        message="MCP server decodes data and runs it as code.",
        patterns=(
            "eval(Buffer.from(...).toString(...))",
            "eval(atob(...))",
            "new Function(Buffer.from(...).toString(...))",
            "new Function(atob(...))",
        ),
    ),
    # Added 2026-11-03 (D6-37): where a call runs, which GuardDog's rules do not
    # look at. A library calls subprocess inside functions; malware often does
    # it at module level, so importing the package runs it.
    SemgrepRuleSpec(
        rule=_IMPORT_TIME,
        languages=("python",),
        message="Package runs a process, network call or dynamic code when imported.",
        patterns=(
            "subprocess.run(...)", "subprocess.Popen(...)", "subprocess.call(...)",
            "subprocess.check_output(...)", "subprocess.check_call(...)",
            "os.system(...)", "os.popen(...)", "exec(...)", "eval(...)",
            "requests.get(...)", "requests.post(...)", "urllib.request.urlopen(...)",
            "socket.socket(...)",
        ),
        not_inside=(
            "def $F(...):\n  ...",
            "async def $F(...):\n  ...",
            "class $C:\n  ...",
            "if __name__ == '__main__':\n  ...",
            "lambda $X: $Y",
        ),
    ),
    SemgrepRuleSpec(
        rule=_IMPORT_TIME,
        languages=_JS,
        message="Package runs a process, network call or dynamic code when imported.",
        patterns=(
            "exec(...)", "execSync(...)", "spawn(...)", "$CP.exec(...)", "$CP.execSync(...)",
            "$CP.spawn(...)", "$CP.spawnSync(...)", "eval(...)", "new Function(...)",
            "fetch(...)", "https.request(...)", "https.get(...)", "http.request(...)", "http.get(...)",
        ),
        not_inside=(
            "function $F(...) { ... }",
            "function (...) { ... }",
            "(...) => { ... }",
            "(...) => $X",
            "class $C { ... }",
        ),
    ),
    SemgrepRuleSpec(
        rule=_ENV_HARVEST,
        languages=("python",),
        message="MCP server collects the whole environment; review what leaves the process.",
        patterns=("dict(os.environ)", "os.environ.copy()", "str(os.environ)",
                  "json.dumps(os.environ, ...)", "json.dumps(dict(os.environ), ...)"),
    ),
    SemgrepRuleSpec(
        rule=_ENV_HARVEST,
        languages=_JS,
        message="MCP server collects the whole environment; review what leaves the process.",
        patterns=("JSON.stringify(process.env, ...)", "Object.keys(process.env)",
                  "Object.entries(process.env)", "{...process.env}"),
    ),
)


def export_semgrep_config() -> dict[str, object]:
    return {"rules": [rule.to_semgrep_dict() for rule in SEMGREP_STATIC_RULES]}
