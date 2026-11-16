# Persistent backend result reuse

This is core execution behavior, independent of Workbench, Codex, and reports.
The original synchronous analysis interfaces and their arguments remain available;
explicit background jobs use the same execution and reuse path. `run_plugin` checks for
a reusable completed result before launching analysis; `get_image_info` uses this
same path for each discovery probe. It still derives its OS decision from output.

## Identity and eligibility

The SHA-256 reuse key combines content-hashed inputs with the trusted symbol metadata inventory:

- Source path, size, SHA-256 and existing file fingerprint fields. Metadata changes
  conservatively invalidate reuse even when bytes are identical; moved/copied images
  are separate identities. Hashes are computed from the complete source each time.
- Exact plugin identity and parsed argument values, including types. Option order,
  `--option=value` syntax, and equivalent integer spellings normalize to the same
  identity. List order remains significant. Declared file inputs are fingerprinted.
- Fresh installed plugin metadata, Volatility/Python/dependency versions, analyzer
  executable/Python dependency code, plugin sources, relevant backend/helper
  sources, and server/MCP versions. Catalog discovery still launches a helper;
  `reused: true` means no **analysis** subprocess, not zero subprocess activity.
- Configured symbol roots and a trusted local metadata inventory of symbol/cache
  entries: relative paths/types, plus regular-file sizes, mtime/ctime and
  device/inode; directories carry only path/type. Additions/removals and missing
  roots affect identity. Admission/reuse/context checks do not bulk-open or hash the
  contents of symbol files or archives. The preparation audit remains excluded
  because it is provenance. Addon enablement, executable paths and timeout remain
  execution inputs.

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

Symbol/cache inventory changes or dependency/input changes during a run make it
ineligible for reuse even if analysis succeeded. A subsequent request can establish
a stable reusable run. Metadata-only changes can conservatively invalidate symbol
identity even when file contents are unchanged.

Symbol inventory deliberately trusts local filesystem metadata; its SHA-256 digest
does not cryptographically verify symbol bytes. It is not protection against a
malicious local user or filesystem falsifying metadata. No bulk symbol-content
rehash fallback runs after an inventory failure. Source-image, runtime/code,
declared input files and saved artifacts retain their content hashes. Provisioning
still verifies package checksums, and the analyzer can read its selected symbols.
Neither path authorizes rescanning the entire symbol store for execution identity.

This also covers installed/bundled symbol-data roots discovered by the runtime
catalog. Their metadata is included without adding symbol bytes to runtime/code
content hashing. The default symbol helper checks existing index readiness
read-only: no implicit payload verification, `manager.update`/index-all or bulk
reindex. A missing required XP cache/index returns an actionable explicit
`symbols-install` provisioning instruction. Queue execution and reuse do not
invoke that installer; full-store checksum/index work remains explicit.

The backend is also not protection against a local user rewriting outputs and
their provenance.

Context records declare
`symbols_identity_method: "trusted-local-filesystem-metadata-v1"` and
`symbol_content_verified: false`. Inventory covers catalog-discovered installed
symbol roots, supplemental symbols and the effective private cache. Symlinks and
special files are rejected before supported exclusions. Generated Python caches
and bytecode, symbol-preparation audit JSON and the cache SQLite `-shm` sidecar
are excluded; regular cache database files remain inventoried as metadata.

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

POSIX locks coordinate requests across processes sharing the output root.
A request-identity lock prevents concurrent equivalent analysis, and shared capacity
slots bound distinct requests by `max_concurrent_runs`. A waiting duplicate checks
again after admission and can reuse the first completed result. Source identity is
rechecked after waiting. Each lock/capacity wait is cancellable and bounded by
command timeout plus catalog timeout; failure starts no plugin. Keep client
timeouts longer than execution, lock waiting, and integrity work.

The persistent `.execution.lock` inode is a shared execution gate with an exclusive
maintenance form. Key locks, slot locks and capacity policy live under `.execution/`.
The backend never deletes/replaces lock inodes. Children inherit execution leases:
if an analyzer survives a force-killed server, leases remain until it exits. No
automatic orphan termination or retry is added. Local POSIX filesystem semantics
are required; network filesystems are untested.

Each request identity uses a private mutable cache under `.execution/caches/`,
seeded from the configured cache; SQLite files use coherent backup. Nested
symbol-cache/table trees are not copied into each private cache. Analyzer writes
do not modify that seed. Reuse inventories actual cache metadata, so inventory
changes during analysis can prevent reuse; it does not hash all cache contents. Backend request state is isolated across threads.
Changed code/context can conservatively miss earlier runs; originals remain intact.

`submit_jobs`, `get_job`, `list_jobs` and `cancel_job` add explicit incremental
execution. Job snapshots persist under `.jobs/`; the submitting process owns active
work. Shutdown requests cancellation and finalization; ownerless active records
are exposed as interrupted, never replayed. Local clients must close with
`shutdown_jobs(wait=True)`. See [PARALLEL_EXECUTION.md](PARALLEL_EXECUTION.md).

Cached results keep the original run ID, so report packaging and evidence
references identify the actual run. No historical report bundle is rewritten.
Structured evidence queries and observable-value checks are now described in
[SAVED_EVIDENCE.md](SAVED_EVIDENCE.md); explicit coverage is described in [COVERAGE_EVALUATION.md](COVERAGE_EVALUATION.md).

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
file counts for `image_before`, `image_admission`, `image_after`, `runtime`, `input_files`,
`new_artifacts`, `saved_artifacts`, and `addon` when applicable, plus totals.
Durations include opening/reading/fingerprinting files; they exclude waiting for
the execution lock, catalog enumeration, analysis and output conversion. Erroring
hash attempts contribute elapsed time but not a completed file/byte count.
`hashing.symbol_inventory` separately records `method`,
`content_bytes_read: 0`, `files`, `directories` and `seconds`. No symbol-content
group is added to `hashing.groups`. This records metadata traversal, not symbol
byte verification. Historical records may retain the former symbol-hashing measurements; they describe the old behavior.
Both hits and misses retain full before/after source hashing. These measurements
are instrumentation, not a claim of measured speedup on large forensic images.

After upgrading, restart idle MCP clients/Workbench so they load the new backend.
Do not interrupt an active investigation merely to activate reuse. See
[VALIDATION.md](VALIDATION.md) for fixture counters, protocol checks and limits.
