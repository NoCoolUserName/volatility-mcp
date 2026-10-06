# volatility-mcp

A local, client-neutral MCP server for evidence-backed queries with **official
Volatility 3**. It runs your separately installed Volatility executable, saves
complete outputs and execution records, and exposes small, controlled tools over
stdio. It makes no LLM API calls and needs no model API key.

An **optional investigation and reporting workflow** lives in the same repository.
Individual queries do not require reports, templates, case-report metadata, or
Codex. No report is generated as a side effect of a tool call.

An experimental [local Workbench](docs/LOCAL_UI.md) optionally adds a browser
interface for case selection, readiness, reports, evidence and follow-up questions.

This is an independent project, not endorsed by the Volatility Foundation,
OpenAI, or Dragos. Original project material is MIT licensed; see
[third-party notices](THIRD_PARTY_NOTICES.md).

## Quick start 1: use the MCP server

### Prerequisites

- Python 3.12 or newer, Git, and a local MCP client that supports stdio.
- Official [Volatility 3](https://github.com/volatilityfoundation/volatility3),
  installed separately. Setup can reuse an existing installation or create one.
- Enough storage for the image, complete outputs, symbol cache, and optional dumps.
- A stable, readable acquisition copy you are authorized to analyze.

The verified local target is macOS on Apple silicon with native ARM64 Python
3.12 and Volatility 3 2.28.2. Platform and client checks, their scope, and remaining
limitations are recorded in [VALIDATION.md](docs/VALIDATION.md). Linux analysis-host
support is unverified; Windows hosts are currently unsupported because process
management uses POSIX primitives. A plugin importing successfully does
not establish support for every guest OS, symbol set, or image.

Clone this repository using its GitHub **Code** URL, enter the clone directory,
then create the server environment:

```sh
python3 -c 'import platform, sys; print(sys.executable, platform.machine())'
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
.venv/bin/python -m pip install --no-deps -e .
```

On Apple silicon the architecture must be `arm64`. If Python is missing or
running through Rosetta, install a suitable native build from
[python.org](https://www.python.org/downloads/macos/), then recreate only the new
server environment with that interpreter. Do not move an existing virtual
environment: its executable paths are not portable.

Reuse an existing working Volatility environment:

```sh
.venv/bin/python -m volatility_mcp setup \
  --config "$PWD/config.local.json" \
  --vol-python "$HOME/Forensics/volatility-env/bin/python" \
  --vol "$HOME/Forensics/volatility-env/bin/vol" \
  --evidence-root "$HOME/Forensics/cases" \
  --output-root "$HOME/Forensics/outputs"
```

For a new installation, replace the two `--vol-*` options above with
`--install-volatility`. This uses the official `volatility3[full]` package from
PyPI in a separate environment; it does not add Volatility to the MCP environment.
Use `setup --help` for an alternate Volatility environment location. Setup is
idempotent: a suitable installation is reused, and existing evidence is retained.

Put `.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`, or `.dd` acquisitions in the evidence
root, optionally in case subfolders. These are accepted filename extensions,
not a promise that every file or acquisition format is supported by Volatility.
Keep archives separately and extract only intended memory images after validating
the archive; the server does not unpack archives. Source files should be read-only.

Verify a real MCP handshake and discovery call:

```sh
.venv/bin/python -m volatility_mcp doctor --config "$PWD/config.local.json" --mcp
```

### Connect a client

For any stdio MCP client, configure the **absolute** server Python as the command
and these separate arguments:

```text
command: <clone>/.venv/bin/python
args: ["-m", "volatility_mcp", "serve", "--config", "<clone>/config.local.json"]
```

Replace `<clone>` with your clone's absolute path; do not paste angle-bracket
placeholders literally. Alternatively set `VOLATILITY_MCP_CONFIG` to the absolute
JSON configuration path. There is no HTTP listener, bearer token, or server-side
model credential. Configure your client's tool timeout above the configured
subprocess timeout, allowing extra time for hashing large images and discovery.

For **local Codex CLI**, this helper backs up the previous registration and Codex
configuration before registering the server and configuring compatible timeouts:

```sh
.venv/bin/python -m volatility_mcp register-codex \
  --config "$PWD/config.local.json" \
  --backup-dir "$HOME/Forensics/config-backups"
codex mcp list
codex mcp get volatility --json
codex -C "$PWD" --no-daemon
```

The underlying supported registration command is:

```sh
codex mcp add volatility -- "$PWD/.venv/bin/python" \
  -m volatility_mcp serve --config "$PWD/config.local.json"
```

The helper sets startup and tool timeouts to at least 90 and 1,800 seconds,
respectively, increasing them for configured execution limits and preserving
larger existing values and unrelated settings. CLI registration
listing proves configuration exists; `doctor --mcp` and an actual client tool call
prove protocol/tool operation. After code or configuration changes, exit the old
session and launch the command above to use a fresh server process. See the
[official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

Keep other configuration editors idle during registration. If registration or its
verification fails, the helper restores the previous configuration atomically
when the observed file has not changed again. If it detects a concurrent change,
it leaves the newer contents intact and reports the private backup for comparison.

Codex CLI runs on your computer and can use the configured local server. It can
use a [ChatGPT sign-in](https://learn.chatgpt.com/docs/auth); the MCP server itself
requires no extra model API key. An ordinary browser ChatGPT conversation cannot
directly access this local stdio server or your memory-image files. Analysis is
local, but excerpts returned through MCP can be sent to the connected AI service;
read [SECURITY.md](SECURITY.md) before analyzing sensitive acquisitions.

First request in your connected client:

> Use the volatility MCP tools to list memory images and discover installed
> plugins. For `example.vmem`, identify the guest OS, then run its appropriate
> process-list plugin. Cite saved output and report failures explicitly. Do not
> create a report.

The file must actually exist beneath the configured evidence root. No example
image or malware is distributed here.

## Available tools

| Tool | Purpose |
| --- | --- |
| `list_memory_images` | Inventory supported files with size and SHA-256. |
| `get_image_info` | Save OS/banner discovery probes; keep failures and unknowns explicit. |
| `list_plugins` | Discover installed plugin names; an exact/single match includes accepted arguments. |
| `run_plugin` | Reuse a verified equivalent result or run a discovered plugin with validated arguments; preserve raw outputs, metadata, and derived files. |
| `read_output` | Read a saved text output in bounded chunks with a continuation offset and truncation status. |
| `case_history` | Retrieve saved run history, commands, timestamps, hashes, and output locations. |
| `get_coverage` | Read declared scope, saved attempts, effective results, reuse and unknowns; never collect or retry. |
| `query_output` | Filter/select/count/group/sort saved rows with stable pagination and source status; no new analysis. |
| `get_evidence` | Resolve hash-bound source rows, fields or byte ranges and check declared typed values. |
| `inspect_artifact` | Inspect an existing registered run artifact for PE headers/sections or paginated ASCII/UTF-16LE strings; save source-linked results without rescanning memory. |

Discover names and options rather than relying on older Volatility cheat sheets.
For example, call `list_plugins` with `{"query":"pslist"}`, choose the appropriate
OS-specific match, inspect its schema, then call `run_plugin` with an exact name
and arguments such as `[]` or `["--pid", "1234"]`. Do not pass shell command strings.
Refer to live `tools/list` for complete schemas.

For saved reconstructions, get the run ID from `case_history` and the exact
run-relative artifact path from that run's manifest. Call `inspect_artifact` with
`image`, `run_id`, `artifact` (for example `json/files/reconstructed.dmp`) and
`operation: "pe"` or `"strings"`. String pages expose file offsets, encoding,
`next_offset`, and truncation; follow the cursor to continue. Results and provenance
are saved privately and reused when source/parser/settings identity still matches.
No Volatility analysis or full-image hash is needed for this inspection.

The pinned, pure-Python `pefile` dependency parses headers; nothing recovered is
executed. Header-declared DLL/executable flags, structural range checks, and parser
warnings are separate from maliciousness and completeness. Printable extraction
covers U+0020..U+007E in ASCII or UTF-16LE, not all Unicode. See
[ARTIFACT_INSPECTION.md](docs/ARTIFACT_INSPECTION.md) for limits and examples.
After upgrading, install the updated `requirements.lock.txt` and restart idle
clients/Workbench to expose the updated MCP tools.

### Execution, evidence, and recovery

- Input paths must resolve inside the evidence root; symlink escapes, shell syntax,
  arbitrary plugin directories, and output overrides are rejected. Plugin options
  and value types are checked against the installed catalog. Execution uses argument
  arrays with `shell=False`; there is no generic shell tool.
  A discovered regex contract has narrowly scoped pattern validation: the
  `windows.vadregexscan.VadRegExScan --pattern` value accepts valid byte-regex
  punctuation, bounded to 4,096 UTF-8 bytes with no literal control characters.
  Other string/path restrictions and plugin execution timeouts remain in force.
- On a reuse miss, the plugin runs once with Volatility's JSON renderer. Complete stdout,
  stderr, execution metadata, and any extracted files stay in the configured output
  directory. A readable text view is derived from saved JSON without another scan.
  Conversion failures retain the original bytes and an explicit error.
- Run records include source fingerprints and SHA-256 before/after execution,
  tool versions, exact arguments, timestamps, status, and artifact hashes. Local
  compatibility-addon runs also preserve the addon source and its hash.
- Analysis is serialized across backend processes sharing an output root. Timeouts, cancellation,
  client disconnects, and graceful shutdown retain partial output and status.
  Forced termination can leave child processes or interrupted records; inspect
  them before retrying. Failed or incomplete work is never a clean finding.
- Output previews are bounded; `read_output` pages saved text in chunks of at most
  65,536 bytes, and `case_history` provides paginated execution summaries. These
  are byte reads, not structured row/field queries.

**Persistent result reuse** applies to every client using the backend, including
the discovery probes in `get_image_info`. Equivalent requests reuse a successful,
integrity-verified run after restart, retaining its run ID and artifact paths.
The identity includes the source fingerprint/SHA-256, typed arguments, file inputs,
analyzer/plugin/dependency code and versions, symbols/cache content, and execution
configuration. Changed context or damaged artifacts prevents reuse. A filesystem
lock prevents concurrent duplicate analysis within the same output root.

Responses indicate `reused` and include hashing measurements; reuse receipts are
saved separately without editing the original run. Full source hashes before and
after each request remain mandatory, including hits. Hashing seconds, bytes, and
file counts are recorded by phase; no integrity shortcuts were introduced.
Catalog refresh and dependency/artifact hashing still take time, so a hit is not
an instant lookup. Plugin timeouts exclude this overhead.

Older runs without the new identity are preserved but cannot be safely reused.
Failed/incomplete runs are never hits. If symbols/cache or other inputs change
during a successful run, that run remains available but is not reuse-eligible;
a subsequent request executes again against the stable context. Separate output
roots do not share results or locks. See [RESULT_REUSE.md](docs/RESULT_REUSE.md)
for the identity, receipts, measurements, and recovery limits.

The included `xpnet.XpNetScan` is a **local compatibility addon**, separate from
official Volatility plugins. It carves Windows XP x86 TCPT/TCPA pool candidates;
stale or damaged allocations are possible. It cannot prove active connection
state, traffic, or malicious communication. Official Windows NetScan/NetStat may
reject XP. Discover actual compatibility and retain the exact failure.

### Optional pypykatz plugin

[pypykatz-volatility3](https://github.com/skelsec/pypykatz-volatility3) is a
third-party addon for Mimikatz-style credential extraction from saved Windows
LSASS memory. It is not bundled with this project or an official Volatility
Foundation plugin. Extracted credentials do not establish that Mimikatz previously
ran on the captured system.

Install `pypykatz` into the **configured Volatility environment**, not the MCP
server environment, and place the author's `vol_pypykatz.py` in that environment's
`volatility3/plugins/` directory. Retain the upstream license and record the source
commit/hash; keep installation records and local assets outside tracked files.
Existing MCP configuration then discovers it without allowing arbitrary plugin
directories in tool arguments. Installing the dependency alone does not install
the Volatility plugin file.

The verified local combination is **pypykatz 0.6.13**, upstream plugin commit
[`1b722f0`](https://github.com/skelsec/pypykatz-volatility3/commit/1b722f00f7095e8e13648ce6bd355af52c12b21c),
and **Volatility 2.28.2 / Python 3.12 / ARM64 macOS**. Dependency checks, CLI plugin
help, and discovery through both an existing MCP session and a fresh registered
stdio connection passed, with no plugin import failures. Existing analyzer package
versions were preserved. No image was opened or credentials extracted for this
verification; runtime compatibility with individual guest OS/images is untested.

Call `list_plugins` with `{"query":"pypykatz"}`; the exact installed name is
`vol_pypykatz.pypykatz`, with no additional plugin arguments. If an idle client or
Workbench retains an older plugin catalog, reconnect/restart it. The catalog's
`installed_volatility` origin describes installation location, not endorsement;
the upstream wrapper reports an inherited version of `0.0.0`, separate from the
pypykatz dependency version. Treat any extracted secrets as sensitive case output.

## Quick start 2: optionally use investigation and reporting

After the MCP quick start succeeds, read the versioned
[report specification](docs/REPORT_SPEC.md) and use
[prompts/GENERATE_REPORT.md](prompts/GENERATE_REPORT.md) in a client that can read
the repository and write your chosen private case-output folder. With local Codex,
give that folder workspace write access, for example:

```sh
codex -C "$PWD" --add-dir "$HOME/Forensics/outputs" --no-daemon
```

Copyable request:

> Read `docs/REPORT_SPEC.md` and `prompts/GENERATE_REPORT.md`. Investigate
> `~/Forensics/cases/example.vmem` using the existing volatility MCP server. Create
> a new timestamped case bundle under `~/Forensics/outputs/reports` with all required
> deliverables. Discover plugins, follow evidence-supported pivots, preserve exact
> outputs and failures, and distinguish observations, inference, and unknowns.

The companion supplies an [editable template](reporting/templates/report.md),
an [explicitly synthetic example](examples/synthetic-case/README.md), and a structural
provenance check:

```sh
.venv/bin/python -m volatility_mcp report-check examples/synthetic-case
```

Required deliverables are `report.md`, `case-manifest.json`, `investigation.jsonl`,
`iocs.csv`, and `artifacts/`. Hunting content is conditional. Markdown is canonical;
the Workbench supplies safe browser viewing and optional per-image decorative
coins. Polished standalone HTML, PDF, and DOCX exports remain deferred. The core
server never assembles a report itself. The reporting workflow adds no runtime
dependencies and is not loaded during ordinary tool interactions.

Reports link findings and contextualized IOCs to stable artifact IDs and useful
locators, retain failures and limitations, and separate observations from inference
and unknowns. The checker validates artifact paths/hashes, run ownership, required
structure, and references. Supported structured citations also validate declared
typed observable values against actual source rows/fields or byte ranges. Legacy
locators remain readable without acquiring value-verified status. Free-form claims
and analytical conclusions still require review; see the
[saved-evidence contract](docs/SAVED_EVIDENCE.md).
Changes to sealed bundles belong in a new revision, not an overwrite.

## Optional local browser interface

The experimental Workbench adds image selection, readiness, a sequential case
queue, report/evidence viewing, case questions, and explicit versioned report
updates. It reuses your existing Volatility and Codex login; ordinary MCP clients
do not need the UI. From this repository:

```sh
.venv/bin/python -m volatility_mcp.ui.http --config config.local.json --project "$PWD"
```

This opens a loopback browser interface and stores private UI cases beneath the
configured output root. See [LOCAL_UI.md](docs/LOCAL_UI.md) for choosing another
private output directory, security boundaries, and platform/validation limits.
Images remain local, while questions and selected outputs may reach your configured
AI service. The first version adds no runtime dependencies.

### Implemented Workbench features

| Capability | Current behavior |
| --- | --- |
| Case selection | Newest first by creation time; fresh loads select the first case unless a valid `?case=` link requests another. Background refresh preserves manual selection; missing IDs fall back safely. |
| Image selection | Path entry, configured-evidence-folder browsing, and a macOS Finder helper. Images are read in place, not uploaded or copied. |
| Multiple images | Unrelated images become separate cases; explicitly related captures can share a case with separate image identities and provenance. Jobs run sequentially, with one dedicated Codex conversation per case. |
| Readiness | Checks account/tool access, plugin discovery, image hashes with byte progress, and OS/symbol discovery through MCP. Reports **Ready**, **Ready with limitations**, or **Blocked** with reasons; these are not malware verdicts. |
| Activity and evidence | Shows current operations, elapsed time, conversation, saved outputs, errors, and failures. Text, JSON/JSONL, and raw-output views are bounded; complete artifacts remain on disk. |
| Questions | Resumes the case's conversation and instructs the agent to use saved evidence first, making additional MCP queries when needed. Questions do not rewrite reports. Equivalent analysis requests also benefit from backend result reuse; the agent's investigative choices remain guidance-driven. |
| Report generation and updates | Explicit actions create new timestamped revisions. Packaging copies actual artifacts, records provenance, checks source integrity, validates the bundle, and seals it with checksums. Updates link to the previous sealed version and preserve earlier versions and evidence IDs. Failed drafts remain incomplete. |
| Report viewing | Section navigation, constrained local evidence links, and a version selector. New bundles contain portable relative artifact and artwork links; source memory images are not included. Recovered HTML is not executed. |
| Image coins | One stable decorative coin per saved image hash, reused across reopening and report revisions. Original PNGs can be imported; otherwise a local SVG renderer creates a distinct coin without malware attribution, analysis, or extra image hashing. Artwork failure does not block reporting. |
| Human-readable times | UI labels use U.S. Central time with date-aware CST/CDT and the Zulu clock in parentheses. Metadata stays UTC; new filenames use readable UTC timestamps with unique suffixes. Original evidence content and historical paths are preserved. |

Click a coin to enlarge it; left-click anywhere or press Escape to close it.
Right-click the enlarged image to use the browser's **Save Image As** menu.
Keyboard users can focus a coin and press Enter or Space. For existing saved
images, the [metadata-only coin population/import commands](docs/LOCAL_UI.md#image-coins)
preserve historical report bundles; the viewer can display coins above old reports
without editing their files.

### Jobs, cancellation, and persistence

Case records, job status, conversation excerpts, activity, image identities, and
reports are saved in the private Workbench state directory. Codex retains its own
thread history. Keep the same `--state-dir` when relaunching to reopen the same
cases. Browser refresh/reconnection reads existing state without starting scans;
launching again against the same state directory reopens the existing application.
The launcher detects stale application code and asks for a backend restart.

Repeated request IDs return the existing job, and a second operation of the same
kind cannot be queued while that operation is active or queued for the case.
This prevents duplicate UI submissions; backend reuse separately handles equivalent
plugin requests across runs and client restarts.
Jobs distinguish queued, running, stopping, completed, cancelled, failed, and
incomplete states.

**Stop all work** interrupts the active operation and cancels all queued follow-on
work, including other cases. Completed artifacts survive; interrupted jobs and
unsealed drafts remain incomplete. On application restart, unfinished jobs are
marked incomplete and are **not automatically retried or resumed**. Explicitly
submit a new question or report operation to continue the saved case conversation.
Cancellation during core hashing/conversion may wait for that stage to finish;
forced process death cannot guarantee child cleanup.

### Access boundaries and verified scope

The UI binds to loopback, validates Host/Origin, and uses a per-launch capability
and HttpOnly session cookie. Keep its launch URL private. Case threads receive
scoped Volatility tools preauthorized for requested analysis, without exposing a
generic shell tool or changing global Codex configuration. Other supported approval
requests remain explicit; incompatible enforced settings block investigation.

Recorded checks include harmless-fixture MCP/HTTP/browser workflows, cancellation,
duplicate submissions, restart handling, portable report links and immutable
revisions, plus a short real Codex/Volatility integration with saved-evidence
follow-ups. See [UI_VALIDATION.md](docs/UI_VALIDATION.md) for the actual runs and
their limits. Interactive Finder selection, non-macOS hosts, and other browsers
remain unverified. Explicit plan-scoped coverage and a deterministic synthetic
evaluation harness are implemented; they do not establish comprehensive plugin
coverage or real-world detection accuracy. Parallel investigations, multiple agents per
case, additional agent adapters, hosted access, and polished exports remain future
work. Structural report validation is not forensic certification.

## Configuration and troubleshooting

For clone/publication connectivity or conflicting GitHub authentication errors,
use the [GitHub access checks](docs/GITHUB_ACCESS.md). Test actual API and Git
operations before treating a restricted session's DNS/auth-status error as an
invalid credential.

`config.local.json` is private and ignored by Git. Setup records absolute
Volatility interpreter/executable paths and evidence/output roots. Keep evidence,
outputs, and symbol caches outside the clone. See
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for configuration fields, execution metadata,
and boundaries.

- **No images listed:** use an accepted extension under the evidence root. Derived
  outputs, symlinks, AppleDouble files, and archive metadata are excluded.
- **Interpreter/plugin import failure:** run `doctor`; verify the configured
  interpreter and executable belong to the same working Volatility environment.
  Install missing official analysis dependencies there, not into the server venv.
- **Unknown argument:** inspect `list_plugins` for the exact plugin. Global flags,
  custom plugin directories, traversal, shell syntax, and output overrides are rejected.
- **Missing symbols or unsupported kernel:** retain stderr and the failed run.
  Supply matching official symbols through local configuration; do not substitute
  an unrelated profile. A failed scan is never a clean result.
- **Timeout or interrupted run:** consult `case_history` and saved metadata before
  retrying. Partial output is not complete analysis. Tune the local command timeout
  and the client's longer tool timeout for the image size.
- **Large output:** use artifact references and `read_output` in bounded chunks.
  Full raw output stays on disk; response previews explicitly indicate truncation.
- **MCP protocol error:** run `doctor --mcp`; stdout must contain only MCP messages.
  Diagnostics belong on stderr. A stale client process may still use old code.

For guided local installation, use [prompts/SETUP.md](prompts/SETUP.md).
Development instructions are in [CONTRIBUTING.md](CONTRIBUTING.md); implemented
capabilities and future work are separated in [ROADMAP.md](docs/ROADMAP.md).

Saved results can be filtered, counted, grouped and cited with the core
`query_output` and `get_evidence` tools. Workbench follow-ups use saved evidence
first; its report viewer can resolve checked citations to source values. Historical
locators remain readable but are not promoted to value-verified citations. See
[the saved-evidence contract](docs/SAVED_EVIDENCE.md).


Coverage is available in Workbench's **Coverage** tab and through `get_coverage`.
Existing cases remain scope-unspecified unless a plan is explicitly declared;
new report revisions package coverage and state its limitations. The offline
synthetic evaluation command is:

```sh
.venv/bin/python tests/evaluation/run.py --output /tmp/volatility-evaluation
```

See [coverage and evaluation](docs/COVERAGE_EVALUATION.md) for plans, state definitions,
fixtures, supported versus unsupported tasks, and interpreting the result counters.
