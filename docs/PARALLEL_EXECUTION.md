# Explicit parallel execution

Core runs explicitly selected Volatility requests concurrently and exposes each
result as it finishes. The same backend serves stdio MCP and local integrations;
Workbench remains a separate client. Core never chooses follow-ups, retries,
additional plugins, or reports.

## Submit, inspect, then choose

Discover installed names and argument schemas with `list_plugins`. Submit 1–256
explicit requests through `submit_jobs(jobs, order="input")`:

~~~json
{
  "jobs": [
    {"image": "example.vmem", "plugin": "windows.pslist.PsList", "arguments": []},
    {"image": "example.vmem", "plugin": "windows.dlllist.DllList", "arguments": []}
  ],
  "order": "input"
}
~~~

These names are examples; discovery does not establish image compatibility. Each
request contains only `image`, `plugin`, and optional string-list `arguments`. The
complete batch passes path, case-scope and installed-argument validation before
any job is queued. Later environment or execution failures remain possible.
Submission returns saved records in input order, including `job_id`; it does not
wait for analysis to finish.

Use `get_job(job_id)` for full state and final `result`. A result uses the normal
`run_plugin` contract: status, reuse information, run/manifest references, bounded
preview and artifact paths. Read saved data through `query_output`, `get_evidence`
or `read_output`. An AI client can inspect a completed result and explicitly submit
a relevant follow-up while other jobs continue. Missing evidence does not authorize
additional collection by itself.

`list_jobs(offset=0, limit=100)` returns authorized summaries, total `count`,
`returned_count` and `next_offset`; maximum page size is 256. Follow the cursor and
fetch individual jobs for full results. `CaseBackend` applies its registered image
set to submission, lookup, listing and cancellation, including records owned by
another process sharing those outputs.

`run_plugin` remains available for synchronous requests. Both paths use the same
validation, execution limits, saved evidence and verified result reuse.

## Scheduling and resources

Trusted configuration `max_concurrent_runs` accepts integers 1–64. Its default is
`min(8, os.cpu_count() or 1)`; setup accepts `--max-concurrent-runs N`. It caps work
across processes sharing an output root. Clients using that root must agree on
the setting; changing it requires an idle boundary and reloading clients. A
conflicting active configuration fails rather than creating another capacity pool.

This is a process concurrency limit, not a CPU-core allocation. Plugins compete
for RAM, storage bandwidth, cache space and output space. Integrity hashing and
metadata discovery also cost time. Lower the limit on constrained machines;
increasing it does not guarantee a speedup. Separate output roots have independent
pools and can exceed one root's limit in aggregate.

`order="input"` submits work in caller order. Optional `order="slowest-first"`
places known longer estimates first, followed by unknowns; ties retain input order.
Estimates use successful saved command durations for the same image, plugin and
normalized arguments, inspecting up to the latest 2,000 manifests per image.
Successive samples are folded with equal weight on the previous estimate and new
sample. Older records may use command timestamps when precise elapsed seconds
are absent. No timing probe, failed-run duration, copied upstream default, or
remote statistics service is used. Runtime changes can affect actual duration:
these are scheduling hints, not reuse eligibility. `estimated_seconds` is null
when no eligible timing was found.

## Jobs, sessions and cancellation

Private `.jobs/` JSON records persist under the output root. Snapshots include
`state`, submission/start/completion timestamps, normalized request, owner session,
input position, selected order, estimate, `result` and `error`. `queued` and
`running` are incomplete; running can include integrity work and lock waiting
before a plugin starts. Final states follow the normal run status, with explicit
cancellation/error states when no normal result was produced.

`cancel_job(job_id)` records a cancellation request visible across processes and
returns a snapshot. Cancellation is cooperative: poll until terminal. A queued
cancellation starts no plugin; an executing child process group is killed/reaped
through the existing cancellation path, retaining partial outputs and finalized
metadata. Completed results remain available. Failed, timed-out, cancelled,
interrupted or incomplete work cannot establish a clean system.

Jobs belong to the submitting process. Persistence provides audit/status records;
it is not a detached service or permission to restart work. Another process can
poll or cancel a live job. If its owner lease has vanished, lookup presents an
active saved record as `interrupted` without resubmission. Inspect run history
and local processes before explicitly deciding whether new work is appropriate.

Local integrations must call `shutdown_jobs(wait=True)` when closing. The stdio
server does this on EOF or graceful SIGTERM: it requests cancellation and waits
for workers to finalize evidence records. Returning job IDs does not detach work
from the server's lifetime. SIGKILL, crashes and power loss cannot guarantee
finalization; surviving analyzer children retain execution leases until they exit.
No automatic orphan termination or expensive retry occurs.

## Locks, caches and evidence

POSIX file locks coordinate the output root. A shared `.execution.lock` gate permits
keyed requests; its exclusive form remains a maintenance gate. Under `.execution/`,
`keys/<configured-input-digest>.lock` prevents equivalent concurrent work,
`slot-NNN.lock` files enforce capacity, and `policy.lock` coordinates changes.
Waiting duplicates recheck verified results after admission. Waiting is cancellable
and bounded. Never delete/replace lock inodes while clients or analyzers may be
active. Analyzer children inherit gate, key and slot leases: a force-killed server
cannot release them while its analyzer still runs. Local POSIX filesystem semantics
are required; network filesystems are unverified.

Different request identities use separate mutable caches under `.execution/caches/`,
seeded from the configured cache. SQLite databases use coherent backup; transient
sidecars and nested symbol-cache/table trees are not copied. Analyzer writes stay in its private cache. Request-local
backend state prevents catalog/cache fields from overwriting each other. Existing
read-only symbol readiness checks use that private cache. No discarded warmup analysis
or parallel `--clear-cache` operation is added. Provision approved symbols first
where downloads are disallowed; private caches consume disk and can acquire
image-specific symbols through normal Volatility behavior.

Reuse retains source-image, runtime/code, declared input-file and saved-artifact
content hashes. Symbol/cache identity uses trusted local metadata: relative paths/types,
regular-file size/mtime_ns/ctime_ns/device/inode, directory path/type, and
additions/removals or missing-root markers. Context checks
for admission, hits and queued work do not bulk-read/hash symbol files or archives.
The inventory digest is not cryptographic verification of symbol bytes; it trusts
the local filesystem. Context declares
`symbols_identity_method: "trusted-local-filesystem-metadata-v1"` and
`symbol_content_verified: false`. Symlinks/special files are rejected before
generated Python cache/bytecode, cache audit JSON and SQLite `-shm` exclusions.
`hashing.symbol_inventory` records metadata traversal separately, with
`content_bytes_read: 0`; `hashing.groups` contains no symbol-content hash group.
No full-store hash fallback follows an inventory failure.
Provisioning checksums and the analyzer's selected symbol reads remain separate.

Installed/bundled symbol-data roots discovered by the runtime catalog also use
metadata inventory, while executable/Python runtime code retains content hashes.
Runtime symbol helpers check existing indexes read-only; no per-job full-payload
verification, `manager.update`/index-all, or silent bulk reindex occurs. A missing
required XP cache/index gives an actionable explicit `symbols-install` step.
Full-store verification/indexing remains explicit provisioning and is never an
automatic queued-job or reuse side effect.

Source identity is checked again after admission waiting. Symbol/cache inventory
changes during analysis can make a successful run ineligible for reuse. Job JSON
points to run evidence and does not replace it. See [RESULT_REUSE.md](RESULT_REUSE.md)
for integrity, receipts and overhead. [AGENTS.md](../AGENTS.md) makes the no-bulk-read
rule and focused regression requirement explicit.

## Local measured workload — 2026-11-16

One pass on a 10-core Apple-silicon macOS host with 24 GiB RAM ran the same
16 preselected supported Windows requests (15 plugin identities) at each limit.
Fresh per-level outputs prevented result reuse. Parallel worklists used the
observed serial durations, longest first.

| Configured limit | Wall seconds | Speedup vs 1 | Observed peak analyzer processes | Sampled process-tree RSS, MiB |
| --- | ---: | ---: | ---: | ---: |
| 1 | 123.322 | 1.000× | 1 | 729.5 |
| 2 | 79.693 | 1.547× | 2 | 876.4 |
| 4 | 79.332 | 1.555× | 4 | 1184.4 |
| 8 | 104.535 | 1.180× | 7 | 1485.4 |
| 12 | 105.617 | 1.168× | 12 | 1606.2 |

All 80 requests succeeded with zero reuse, preserved input integrity and unchanged
runtime/source identity. Each parallel result matched its corresponding serial
result after JSON object-key and row-dictionary ordering normalization; recovered
fields, duplicate rows, tree relationships and scalar-list order were preserved.
Every inventory measurement reported zero symbol-content bytes read and
`symbol_content_verified: false`. This concerns identity bookkeeping, not the
analyzer's normal selected-symbol reads.

Limits 2 and 4 were a near tie: only 0.361 seconds apart in this single pass.
They form a reasonable starting range for this measured host/workload; 8 and 12
were slower and used more sampled memory. This does not establish an optimal
default or show that more processes are generally better. The portable default
remains the smaller of 8 and detected logical CPU count.

Wall time runs from immediately before submission until every job is terminal.
It includes admission, per-job integrity hashing/metadata inventory, private-cache
creation/seeding, analysis, finalization and polling overhead. It excludes initial
offline warmup, per-level seed-cache copying and standalone catalog setup. Each
level used fresh output/cache roots cloned from the same primed local seed; the
shared OS cache was uncontrolled.

This was one sequential matrix on an active desktop, without repetitions or
confidence intervals. Resource sampling used 250 ms intervals; summed process RSS
includes harness/monitor overhead, can double-count shared pages and can miss short
peaks. These are workload-specific observations, not cold-start latency, a memory
cap, or certification of other acquisitions/plugins. No private image identity,
path, hash or recovered content is published.

## Reference and validation scope

The design considered bounded subprocess, longest-first and symbol-race lessons
from [VolGolangWrapper at commit 0fbc6d8](https://github.com/BeanBagKing/VolGolangWrapper/tree/0fbc6d8de9c859e5270bde2bfb5ee15cfe82497a).
This implementation uses its own Python backend and local observations; no upstream
source or timing CSV was copied. It uses private mutable caches instead of that
wrapper's serial warmup scan.

See [VALIDATION.md](VALIDATION.md) for recorded checks and their scope. A fixture,
Windows image or measured workload does not certify every plugin, guest OS,
acquisition, client or resource limit. Speedup depends on workload and machine;
enabling concurrency alone does not establish a benchmark result.
