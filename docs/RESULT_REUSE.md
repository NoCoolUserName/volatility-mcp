# Persistent backend result reuse

This is core execution behavior, independent of Workbench, Codex, and reports.
The six MCP interfaces and their arguments are unchanged. `run_plugin` checks for
a reusable completed result before launching analysis; `get_image_info` uses this
same path for each discovery probe. It still derives its OS decision from output.

## Identity and eligibility

The SHA-256 reuse key covers:

- Source path, size, SHA-256 and existing file fingerprint fields. Metadata changes
  conservatively invalidate reuse even when bytes are identical; moved/copied images
  are separate identities. Hashes are computed from the complete source each time.
- Exact plugin identity and parsed argument values, including types. Option order,
  `--option=value` syntax, and equivalent integer spellings normalize to the same
  identity. List order remains significant. Declared file inputs are fingerprinted.
- Fresh installed plugin metadata, Volatility/Python/dependency versions, analyzer
  executable and installed dependency bytes, plugin sources, relevant backend/helper
  sources, and server/MCP versions. Catalog discovery still launches a helper;
  `reused: true` means no **analysis** subprocess, not zero subprocess activity.
- Configured symbol roots, symbol/cache file contents, addon enablement, executable
  paths and command timeout. Only the symbol-preparation audit JSON is excluded:
  it is provenance, not an analyzer input. Cache database bytes are included.

Only `success` with verified unchanged source identity, a finalized manifest,
valid outputs, and stable execution context is eligible. Successful empty JSON
results can be reused; errors, unsupported plugins, timeouts, cancellations,
malformed output, changed evidence and interrupted records cannot. Existing runs
without reuse metadata are not retroactively certified or modified.

Every hit rehashes all recorded original artifacts, including raw stdout/stderr,
readable output, extracted files, command metadata and addon snapshots. Missing,
changed, unexpected or symlinked artifacts cause a miss. Source and execution
context are checked again before returning the saved result. The original run
and its timestamps are retained; the response explicitly says it was reused.

Symbol downloads, cache updates, or dependency/input changes during a run make it
ineligible for reuse even if the analysis itself succeeded. A subsequent request
can establish a stable reusable run. This deliberately favors conservative misses;
there is no timestamp-only or sampled hashing optimization. It is not protection
against a malicious local user rewriting both artifacts and their provenance.
If Volatility's user-defaults file (`~/.config/volatility3/vol.json`) exists,
analysis still works but reuse is disabled with an explicit reason: defaults can
introduce external inputs whose transitive dependencies are not inventoried here.
The server does not edit or remove that operator configuration.

## Persistence, concurrency and cancellation

Completed run manifests are the persistent index; no database or new service is
required. The backend scans the selected image's saved manifests and verifies a
matching candidate. Histories with many runs may therefore have lookup overhead.
Scope is the same evidence identity within the same configured output root. Separate
Workbench cases/output roots are intentionally not a shared global cache.

A POSIX file lock at `<output_root>/.execution.lock` serializes backend requests
across processes. A waiting duplicate checks again after the first run completes
and reuses it. Waiting is cancellable and bounded by command timeout plus catalog
timeout; exceeding it reports an actionable error without launching analysis.
Keep client timeouts longer than execution, lock waiting, and integrity work.

The lock is never deleted/replaced by the backend. It releases when its last owning
file descriptor closes, so dead server processes do not create stale PID locks.
Analysis children inherit it: if an analyzer survives a force-killed server, the
lock remains held until that analyzer exits. No automatic orphan termination or
retry is added. Existing graceful cancellation and partial-output records remain.
Local POSIX filesystem lock semantics are required; network filesystems are untested.

Workbench's scheduler, submission IDs, conversation persistence, Stop action, report
revisions and presentation are unchanged. Cached results keep the original run ID,
so report packaging and evidence references continue to identify the actual run.
No historical report bundle is rewritten. Structured evidence queries, observable-
value citation validation, and explicit coverage tracking remain future work.

## Records and hashing measurements

New execution manifests (schema `1.2`) add `reuse_key`, `reuse_context`,
`reuse_eligible`, optional `reuse_unavailable_reason`, and `hashing`.
Responses add `reused`, `reuse_key`, `reuse_eligible`, `reuse_unavailable_reason`,
`reuse_receipt_path` and `hashing` without
removing existing fields. `case_history` includes execution reuse eligibility and
hashing metrics; it remains a history of real runs, not a count of tool requests.

Each hit creates `<image-output>/reuse/<timestamp-and-id>.json`, outside the original
run. This receipt records the original run/manifest, requested arguments, current
timestamp, verified source fingerprints, key and measurements. Use `read_output`
on `reuse_receipt_path` to inspect it. Receipts do not change the report schema.

`hashing` uses monotonic `perf_counter` durations, with seconds, bytes and completed
file counts for `image_before`, `image_after`, `runtime`, `symbols`, `input_files`,
`new_artifacts`, `saved_artifacts`, and `addon` when applicable, plus totals.
Durations include opening/reading/fingerprinting files; they exclude waiting for
the execution lock, catalog enumeration, analysis and output conversion. Erroring
hash attempts contribute elapsed time but not a completed file/byte count.
Both hits and misses retain full before/after source hashing. These measurements
are instrumentation, not a claim of measured speedup on large forensic images.

After upgrading, restart idle MCP clients/Workbench so they load the new backend.
Do not interrupt an active investigation merely to activate reuse. See
[VALIDATION.md](VALIDATION.md) for fixture counters, protocol checks and limits.
