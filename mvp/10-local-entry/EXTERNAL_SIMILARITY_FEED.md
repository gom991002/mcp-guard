# Stage 1 external similarity feed

The official Registry, npm/PyPI, and OSV checks remain in the Stage 1 A path.
This feed supplies advisory known-malware fingerprints to the B code scan.
Its matches are evidence in the scan report; they do not change a verdict.
The scan does not send package code to the feed server.

## Setup

Add this object inside the manifest's `code_scan` object:

```json
"similarity_feed": {
  "url": "https://your-feed.example/known-malware-index.json",
  "sha256": "<64 lowercase hex characters calculated and approved separately>",
  "path": "C:/mcp-guard/cache/known-malware-index.json"
}
```

The URL is an example, not an existing feed service. The SHA-256 pin must be
established by the person who approves the feed; a checksum read from the same
untrusted URL provides no independent trust. Then run:

```text
python mvp/10-local-entry/mcp_guard_config.py refresh-similarity --manifest guard-manifest.json
python mvp/10-local-entry/mcp_guard_config.py scan --manifest guard-manifest.json --server SERVER
```

The refresh command requires HTTPS, rejects redirects, limits size, verifies
the pinned hash and index schema, and atomically replaces the local snapshot.
A failed refresh preserves the old file. A configured feed that is missing or
differs from its pin stops the scan; an existing report becomes stale and the
wrapper will not start a guarded server until the feed and scan match again.
Changing the feed pin also requires a new scan. The scan report and M1 audit
summary record the source URL, snapshot hash, and embedded date/variant/source
metadata. Embedded metadata is descriptive; the approved hash is the trust
anchor. Without `similarity_feed`,
the bundled index remains the default.

## Evaluation scope

`python mvp/10-local-entry/b_score/eval_external_feed.py` checks that a verified copy of
the bundled snapshot gives identical fingerprints and sampled lookup results.
It times local hash/schema verification, index loading, and lookup. The original
held-out package fingerprints are not in this repository, so the old malicious
recall and false-positive results cannot be remeasured for a new feed here.
Externalizing the same bytes does not add new knowledge. A new feed needs a
separate representative held-out evaluation before changing any B decision.

## Measured in this checkout (2026-11-03)

The checked snapshot was a byte-for-byte copy of the bundled 543,905-byte
index (505 entries). All entries and signatures matched; 100 sampled lookups
returned the same matches. Over five local runs, median SHA-256 plus schema
verification was 31.919 ms; the startup hash-only check was 2.811 ms. Median
index load was 30.225 ms bundled and 34.813 ms from the external snapshot.
One lookup batch of 100 signatures took 17.020 ms bundled and 11.968 ms from
the external snapshot. The lookup timing difference is too noisy to infer a
speedup. These are local timings, not download time or an end-to-end scan.

The existing held-out report (`mvp/10-local-entry/b_score/data/similarity_report.json`)
records 53/183 malicious similarity matches, 0/230 benign matches, and zero
new malicious detections beyond the rule-held set. Those are earlier results,
not a new benchmark. The original package fingerprint records are absent, so
the held-out trial cannot be rerun against a newly populated feed in this
checkout.
