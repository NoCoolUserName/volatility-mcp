# Validation

Assessment: **ready with stated limitations for the documented local Apple-silicon
stdio use case**. The public GitHub repository is accessible. Authenticated API
requests and a Git read of the configured SSH remote succeeded; local `main` and
remote `main` both pointed to `0b904c7f420670eca6e5834feb186dd3a69c23d5` at the
access verification checkpoint, before the documentation follow-up commit.
See [GitHub access](GITHUB_ACCESS.md) for the earlier conflicting results and
verified permission settings. Hosted CI results were not inspected during this
follow-up. Validation date: 2026-10-03.

The optional local UI was added afterward. Its separate scope, actual integration
checks, review repairs, and remaining limits are recorded in
[UI_VALIDATION.md](UI_VALIDATION.md). The checks below describe the original core
delivery; they are not a claim that every UI behavior or client is verified.

## Environment and actual integrations

- macOS 26.4.1 / ARM64; native Python 3.12.13; existing official Volatility 2.28.2;
  MCP Python SDK 2.3.0; Codex CLI 0.160.0. The existing analyzer was not reinstalled.
- Actual SDK stdio connections negotiated **2026-07-28** (auto) and **2025-11-25**
  (legacy). Both discovered all six tools and obtained installed plugin options.
  These protocol checks do not certify other clients.
- Codex CLI `mcp list` and `mcp get volatility --json` confirmed the existing enabled
  registration. A fresh SDK connection using that registered compatibility-launcher
  command exercised the updated server. Rewriting the user-level registration was
  denied by filesystem restrictions; its original configuration remained unchanged.
  A new interactive Codex/model turn against this revision was not tested.
- A minimal **real local MCP** call ran `windows.info.Info` against an existing
  Windows training acquisition: success, 23 rows, one analyzer execution, preserved
  stdout/stderr and metadata, and identical before/after source fingerprints.
  `read_output` retrieved the saved result through MCP. The image, paths, hashes,
  raw output, and detailed receipt remain private. This was not an exhaustive
  investigation, networking test, or malware-family validation.
- Discovery found 197 official plugins plus the separately identified local XP
  addon, with no import failures. Import health is not runtime coverage of all
  kernels, symbols, formats, or plugins.

## Automated and simulated checks

The full server-environment suite completed **46 passing tests and one optional
module skip**. Cycle 2 added two reporting regressions; all **15 affected reporting
tests** passed afterward, for **48 distinct passing core/protocol/report tests**. The separate existing Volatility environment completed **16 addon tests**
using original harmless synthetic pool bytes and a minimal synthetic symbol table.
No real image, extracted binary, or live malware is needed by CI.

Covered: traversal/metacharacters and internal/escaping symlinks; configured root
boundaries; typed/list/URI plugin arguments; denied global/output/plugin overrides;
one analyzer execution; exact output hashes and unchanged sources; deliberate
synthetic source mutation; missing symbols and malformed output; timeout, MCP
cancellation, and graceful SIGTERM; interrupted-history classification; oversized
output previews and bounded paging; FIFO rejection; private/idempotent setup;
registration backup/rollback/concurrency checks; and report identity, references,
artifact linkage, checksums, timestamps, and failure-status consistency.

The stdio tests use a deliberately labeled fake analyzer but exchange actual MCP
messages. Both protocol modes exercise discovery, execution, output reading, and
history. No reporting configuration or report files are required or generated.
Registration failure tests simulate the CLI and touch temporary files only.
The example report is explicitly synthetic: five artifacts, three simulated calls,
two findings, and one contextual indicator. `report-check` passes, but this does
not validate forensic conclusions or detection efficacy.

## Setup journey

A fresh isolated virtual environment installed the pinned runtime dependencies
from locally cached PyPI wheels, then installed this package. Wheel archives passed
CRC and RECORD checks; cache origin/version metadata was recorded privately.
Installed site-packages were not copied into the fresh environment. Live package
index access was unavailable. Setup was idempotent, dependency checks passed, and
`doctor --mcp` worked with empty evidence/output directories and **no reporting
configuration**. It reused the separate native analyzer.

A genuine clean local Git clone was installed into another newly created virtual
environment using the documented dependency/package steps (cached wheels because
network access was unavailable). Import paths were verified to point at the clone.
Idempotent setup, both SDK protocol modes, all six tools, installed plugin discovery,
the compatibility launcher, the full harmless suite, and the synthetic report check
passed. The final reporting-only changes were checked with the affected tests.
The GitHub Actions workflow is configured for harmless Python 3.12/3.13 tests on Linux;
its hosted execution status has not been verified here. Linux host analysis, Windows hosts, other MCP clients,
Linux/macOS guest analysis, and pristine online prerequisite installation remain
unverified (Windows hosts currently require implementation changes).

## Review and repairs

Two separate agent reviewers examined core execution and the setup/report journey;
the coordinating agent reviewed privacy, staged files, and integrated repairs.
This was a project-team review, not an external forensic or security certification.
At most two review/repair cycles are allowed for this delivery.

Cycle 1 found and fixed:

- SIGTERM left a detached analyzer alive. Shutdown now cancels the process group,
  waits for execution records to finalize, and exits. The regression asserts server
  exit before client cleanup, child termination, and retained partial evidence.
- A FIFO could block the output reader. Nonblocking open plus regular-file checks
  now rejects it. A misleading fixed discovery-timeout message was corrected.
- Report checks accepted contradictory call/run artifacts, artifact-ID prefixes,
  and inconsistent bundled-source identities. Exact linkage/identity checks and
  negative regressions now reject them.
- Failed registration could leave changed client configuration. Guarded atomic
  rollback and exact command verification now preserve or explicitly refuse to
  overwrite concurrent changes, with private backups for recovery.
- Development instructions named a nonexistent dependency file; the instructions
  now use the actual minimal dependencies. Synthetic CSV/checksums were normalized.

Cycle 2 found two remaining forms of contradictory report ownership: a run could
claim another run's output, and an optional call `run_id` could name a different
run. Both were fixed with exact reverse-link checks and passing regression tests.
The clean-clone journey and scoped repair verification passed. No further review
cycle was started. The tracked tree and all local history were inspected for
private data; only original source/docs/tests and explicitly synthetic artifacts
are included. The initial publication attempt was withheld after GitHub commands
failed. Later verification confirmed the repository was public and the remote
branch contained the local implementation commit. This supersedes the earlier
publication blocker; it does not establish why the original commands failed.
The documentation follow-up did not rerun setup, tests, or memory analysis.

## Practical limits

The application validates controlled paths/arguments; it is not an OS sandbox,
write blocker, or protection from a malicious concurrent local writer. Dependencies
and the configured analyzer are trusted. SIGKILL or host failure cannot run cleanup
and may leave partial records or a child process. Hashing and output conversion
extend beyond the plugin timeout; each output read fingerprints the whole file.
Disk use is not capped, although returned previews/chunks are bounded. Individual
JSON records above the converter limit fail explicitly with raw output preserved.

Matching symbols remain operator-supplied. XP carving does not prove active
connections or traffic. AI clients may transmit returned excerpts to their service.
Report design/schema 0.1 is intentionally provisional; elaborate presentation and
broader dataset evaluation are deferred. No evidence, private reports, credentials,
local configuration, virtual environments, symbols, or third-party books belong
in the public project.

## Persistent backend reuse — focused validation

Assessment: **ready with stated limitations for the documented local POSIX use
case**. This change implements result reuse, invalidation, duplicate prevention,
and hashing instrumentation only. Structured saved-row queries, value-level citation
checks, explicit coverage tracking and forensic detection evaluation remain future
work. No memory-image investigation or historical report regeneration was run.

Automated checks used the harmless analyzer fixture and a persistent analysis-only
subprocess counter. Fifteen reuse tests passed, demonstrating:

- Equivalent typed arguments reuse one original run and artifact set, including
  a newly constructed backend. Original run bytes remain unchanged, and separate
  receipts record both full source hashes plus phase durations/bytes/counts.
- Two independent concurrent backend processes launch exactly one analyzer; one
  response is a hit with the same run ID. Discovery probes also reuse after restart.
- Source content, arguments, URI file inputs, executable/dependency bytes,
  versions, plugin metadata, symbols/cache and timeout changes invalidate reuse.
- Missing, altered, additional, symlinked and traversal-containing artifact paths
  cannot be reused; traversal is rejected before reading the outside file.
  Legacy, corrupt, incomplete, cancelled, unsupported and failed records are misses.
- A successful empty result is reusable. A symbol/cache change during execution
  leaves a successful run ineligible; the next stable run can be reused. Unknown
  transitive inputs from Volatility user defaults explicitly disable reuse.
- A waiting duplicate can be cancelled without starting analysis. Dead lock owners
  do not leave stale locks. A harmless analyzer surviving a killed server retains
  the lock and prevents an overlapping retry; the test cleans it up explicitly.
- Source mutation during hit validation is rejected without launching analysis.

Ten existing backend checks, two real stdio MCP protocol checks (with the fake
analyzer), and the graceful SIGTERM check passed. The protocol test opens separate
server sessions in both supported protocol modes and verifies one analysis invocation
total, original run identity, and hit hashing metadata. Fifteen reporting checks
and all 21 existing Workbench checks also passed across the recorded runs, including
immutable revisions, evidence links, coins, cancellation and reopened state.
Total: **64 distinct passing tests**; this was focused verification, not a full suite
or new browser walkthrough. Workbench jobs/UI and the report format were unchanged.

Initial verification found a fixed-delay cancellation test could cancel before
analysis started as setup work increased. It now waits for the fake analyzer's
counter before testing in-flight cancellation. A worker-completion callback also
retrieves exceptions when a cancelled/disconnected MCP request no longer awaits
its worker. The HTTP boundary test initially could not bind loopback under the
implementation sandbox; the single test passed with that operation permitted.
These initial failures are not presented as successful test results.

Read-only inspection of the real installed Volatility catalog helper confirmed
version 2.28.2, 198 plugins, ten installed dependency packages, 1,898 inventoried
runtime files and no import failures. It did not open a memory image or run a
forensic plugin. This verifies inventory integration, not real-image cache-hit
performance. No benchmark claim is made from synthetic hashing timings.

Two focused implementation reviews inspected the changed execution path,
artifact/path confinement, invalidation inputs, lock lifetime, cancellation,
documentation and outgoing files. Repairs added lock inheritance for surviving
analyzers, conservative handling of implicit user defaults, malformed-manifest
handling, and canonical artifact-path checks; affected tests passed. This is
project implementation review, not an independent audit.

Limits: full source and dependency/artifact hashing remains potentially expensive;
identity changes favor safe misses, including symbol-cache warming and source
metadata changes. Older runs are preserved without retroactive reuse certification.
Results/locks are scoped to the same output root; network-filesystem locking and
non-macOS hosts remain unverified. Restart idle clients to load the new backend.
