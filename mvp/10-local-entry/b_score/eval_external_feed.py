"""Measure local lookup parity and overhead for a pinned external snapshot.

This is not a detection-rate benchmark: the held-out fingerprint records are
not shipped in this repository. It compares the bundled index with a verified
snapshot of the same bytes and reports local load/lookup timings only.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from mcp_guard import similarity  # noqa: E402
from mcp_guard.similarity_feed import checked_snapshot  # noqa: E402


def main() -> None:
    raw = similarity.INDEX_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    bundled = similarity.load_index()
    if bundled is None:
        raise RuntimeError("bundled index unavailable")
    with tempfile.TemporaryDirectory() as folder:
        snapshot = Path(folder) / "index.json"
        snapshot.write_bytes(raw)
        checks = []
        startup_checks = []
        bundled_loads = []
        loads = []
        for _ in range(5):
            start = time.perf_counter()
            checked_snapshot(snapshot, digest)
            checks.append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            checked_snapshot(snapshot, digest, validate_schema=False)
            startup_checks.append((time.perf_counter() - start) * 1000)
            similarity.load_index.cache_clear()
            start = time.perf_counter()
            similarity.load_index()
            bundled_loads.append((time.perf_counter() - start) * 1000)
            similarity.load_index.cache_clear()
            start = time.perf_counter()
            external = similarity.load_index(str(snapshot))
            loads.append((time.perf_counter() - start) * 1000)
        if external is None or bundled.labels != external.labels or bundled.signatures != external.signatures:
            raise RuntimeError("external snapshot differs from bundled index")
        samples = bundled.signatures[:min(100, len(bundled.signatures))]
        start = time.perf_counter()
        bundled_results = [bundled.best(sig) for sig in samples]
        bundled_lookup = (time.perf_counter() - start) * 1000
        start = time.perf_counter()
        external_results = [external.best(sig) for sig in samples]
        external_lookup = (time.perf_counter() - start) * 1000
        if bundled_results != external_results:
            raise RuntimeError("lookup results differ")
    report = json.loads((ROOT / "mvp/10-local-entry/b_score/data/similarity_report.json").read_text(encoding="utf-8"))
    print(json.dumps({
        "snapshot_bytes": len(raw), "entries": len(bundled.labels),
        "parity": "exact for all index entries and sampled lookups",
        "sampled_lookups": len(samples),
        "median_sha256_and_schema_check_ms": round(statistics.median(checks), 3),
        "median_startup_hash_check_ms": round(statistics.median(startup_checks), 3),
        "median_bundled_index_load_ms": round(statistics.median(bundled_loads), 3),
        "median_external_index_load_ms": round(statistics.median(loads), 3),
        "bundled_lookup_100_ms": round(bundled_lookup, 3),
        "external_lookup_100_ms": round(external_lookup, 3),
        "prior_heldout_only": report["test"],
        "new_heldout_evaluation": "unavailable: original fingerprint records absent",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
