# Optional local Workbench — experimental

The repository has three independently usable layers: the client-neutral stdio
MCP server, the optional reporting workflow, and this optional local browser UI.
The UI uses the standard library and the existing official MCP SDK; it adds no
runtime dependencies to the core. It requires a local Codex CLI installation and
the repository's report specification. No server-side LLM API client or model key
is added. The current adapter targets Codex app-server 0.160.0.

## Launch

From the repository, using the existing configured environment:

```sh
.venv/bin/python -m volatility_mcp.ui.http --config config.local.json --project "$PWD"
```

This binds an available port on `127.0.0.1` and opens the local browser. Keep the
Terminal process running. Ctrl-C stops work and exits. `--no-open` prints the
private launch URL without opening a browser; `--port 8765` requests a fixed port.
Treat the launch URL as a local access credential; do not share it or put it in
issues. Repeating the launch command for the same state directory opens the
existing application instead of starting another queue.

Default private storage is `<configured output_root>/workbench`. To use another
private output directory outside the repository, add:

```sh
--state-dir "$HOME/Forensics/reports/workbench"
```

The chosen directory is the UI's configured case output root. Keep the same
argument on later launches to reopen those cases. Do not put UI state under Git.
Source images remain in the configured evidence root; output and source roots
must not overlap in a way that makes the output directory contain the evidence.
No migration or rewrite of previous reports is performed.

A fresh clone follows the existing MCP setup first. Install the project normally
or with the optional `.[ui]` extra (currently no additional dependencies). The
`volatility-workbench` console command is available after package installation;
the module command above also works with an existing editable installation.

## Workflow

The Cases list displays newest first by case creation time. A fresh page selects
the first displayed case unless a valid `?case=<case-id>` URL requests another.
Background refreshes preserve the selected case, including a manual selection.
If the selected/requested case no longer exists, selection falls back to the
first displayed case; an empty list shows the start screen.

1. Add existing `.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`, or `.dd` files through
   path entry, evidence-folder browsing, or **Choose in Finder** on macOS. The
   native helper returns filesystem paths; the browser does not upload files.
   Selected files must remain inside the configured evidence root and cannot be
   symlinks. To use another source location, deliberately configure that root
   through the normal setup/configuration path first. No automatic copying occurs.
2. Unrelated images become separate cases. Check **related captures** only when
   intentionally grouping them. Each capture keeps its own evidence ID, hash,
   discovery result, run associations, and report provenance. New cases get a
   dedicated conversation; the UI never controls an unrelated open Codex session.
3. **Check readiness** connects to the existing Codex account, initializes the ten
   actual scoped MCP tools, discovers plugins, hashes each image with byte progress,
   and runs OS/symbol discovery through MCP. **Ready** means ready to attempt
   analysis. **Ready with limitations** records discovery/import/compatibility
   gaps. **Blocked** records authentication, tool, file, or integrity errors that
   prevent readiness. None is a malware verdict or guarantee every plugin works.
4. **Generate report** starts an adaptive investigation, optionally narrowed by
   your focus. The report must follow `docs/REPORT_SPEC.md`. The agent records
   important runs and saves Markdown/findings/IOCs; the application packages actual
   execution metadata and exact artifacts, validates provenance, rehashes source
   evidence, and seals a new version. A failed or incomplete draft stays visibly
   incomplete. Structural validation does not validate the analyst's conclusions.
5. View reports with their section navigation and evidence links. Raw outputs,
   readable text views, JSON/JSONL, activity, failures, current operation and elapsed
   time are accessible in the other tabs. Large files are read in bounded chunks;
   complete originals remain on disk. Recovered HTML is never executed.
6. **Ask / investigate further** resumes the same case conversation. It may run
   more MCP queries, but does not rewrite reports. **Update report** explicitly
   creates a new revision with a link to the previous version and preserved stable
   evidence IDs. Previous sealed versions are immutable through UI operations.
7. Multiple cases/jobs run sequentially. Refreshing/reopening the browser reads
   existing state and cannot start a scan. **Stop all work** interrupts the active
   turn/readiness operation and cancels all queued follow-on work. Completed
   artifacts remain, and interrupted jobs/drafts are marked incomplete. An app
   restart marks unfinished jobs incomplete; it never automatically restarts them.
   Explicitly queue a new question/report operation to continue the saved thread.

Core [result reuse](RESULT_REUSE.md) now applies beneath readiness and agent tool
calls. Equivalent requests can reuse verified successful runs after restart, with
their original run IDs and artifact paths. This is independent of the Workbench
queue and leaves sealed report versions unchanged. Old runs without reuse metadata
remain available for saved-output reading but are not automatically certified as
cache hits. Hashing remains mandatory; failed or changed-context runs are not reused.

The investigator can now call `inspect_artifact` through that same scoped MCP
connection. It inspects saved registered files for PE metadata or bounded printable
ASCII/UTF-16LE strings; it does not rerun extraction or memory analysis. Guidance
explicitly separates header flags, readable ranges, string observations and malware
conclusions. New report revisions package inspection outputs as separate derived
runs linked to the original extraction artifact; historical bundles remain intact.
Install updated locked dependencies and restart idle Workbench after upgrading so
both its MCP process and resumed case guidance load the new capability.

## Architecture and boundaries

```text
Browser (loopback, escaped views)
  -> local HTTP controller + durable private job/case state
     -> readiness: official MCP client -> scoped core MCP -> existing Volatility
     -> investigation: Codex app-server stdio -> scoped core MCP -> Volatility
          -> optional case tools: notes, bounded artifact reads, report packaging
```

`ui/codex.py` isolates newline-delimited JSON-RPC initialization, thread start/resume,
turns, events, interruption, and server requests. It follows the
[official app-server interface](https://learn.chatgpt.com/docs/app-server), checked
against JSON schemas generated by installed Codex 0.160.0. Dynamic case tools use
its documented experimental API. A different agent adapter can replace this
module later; only Codex is currently implemented.

The adapter reuses existing authentication and provider selection without setting
an API key, model provider, or billing mode. It requests read-only shell/filesystem
access, user-reviewed on-request approvals, and disables shell execution, unrelated
MCP servers, apps, plugins, hooks, browser tools, and delegation for case threads.
The explicit scoped MCP process can still write its case analysis outputs, and
case tools can write the current report draft. Effective returned approval and
sandbox settings are checked; incompatible overrides block investigation and are
recorded. This is an application boundary, not isolation from a compromised local
account, trusted analyzer, parser, or Codex installation.

Case-scoped Volatility tools are preauthorized with
`mcp_servers.volatility.default_tools_approval_mode = "approve"` on thread start
and resume. Requested analysis runs without a second approval click. Restart
Workbench after upgrading to apply this to existing case conversations. This does
not change global Codex configuration or authorize generic shell commands.
The launcher checks a fingerprint of the installed application code before
reopening an existing instance. If that instance predates an update (or predates
fingerprint tracking), it tells you to stop the old Terminal process and relaunch
instead of silently reopening outdated code. A browser refresh alone cannot
restart the Python backend. Stopping marks active work incomplete and preserves
completed artifacts; submit a follow-up after relaunch to continue.

Workbench displays timestamps in U.S. Central time with the Zulu clock in
parentheses, e.g. `2026-10-05 22:15:01 CDT (03:15:01Z)`, including legacy
report versions, activity, conversation timestamps, and evidence-path labels.
Conversion uses `America/Chicago` for each timestamp, so CST/CDT and the local
calendar date reflect daylight saving time at that instant. The leading date is
the Central date; the parenthesized Zulu clock can belong to the next UTC day.
Execution/state metadata remains seconds-resolution UTC (`YYYY-MM-DD HH:MM:SSZ`).
New run/report folders and registration backups use portable names such as
`2026-10-06_02-52-39Z-<unique suffix>`; the suffix prevents same-second collisions.
Existing folders, sealed reports, and raw evidence remain unchanged. Evidence
buttons retain their original link targets (hover to see the actual path), and
the raw artifact preview preserves source content and timestamp precision.

Other supported command/file approvals and scoped Volatility MCP form requests are
shown with details and approve-once/decline/cancel choices; user-input requests
accept answers. MCP forms support scalar and single-choice fields, with server-side
schema validation; unsupported fields cannot be approved through this UI. URL and
device-verification elicitations are declined. There is no automatic privileged
approval or persistent rule amendment. Unsupported request kinds fail without a
permission grant. No generic shell endpoint is exposed by the UI.

HTTP actions require an exact local Host and Origin and a per-launch capability
exchanged for an HttpOnly, SameSite=Strict session cookie. No CORS access is granted.
The capability is removed from the URL fragment after connection; no model
credentials enter browser storage. Responses are no-store with restrictive CSP,
no-referrer and nosniff headers. Report rendering uses text DOM nodes and permits
only constrained local artifact navigation; remote links are displayed as text.
These controls do not protect against another process running as the same user.

Private state includes case records, job status, conversation excerpts, activity,
scoped MCP configuration, source paths, and reports. Codex also keeps its own thread
history under its existing user state. Source images are never copied to bundles.
The image stays local, **but questions and selected tool output may reach the
configured AI service**. Volatility may fetch symbols. See `SECURITY.md`.

## Limits and troubleshooting

- macOS ARM64 is the verified host. The Finder helper is macOS-only; other POSIX
  hosts have path entry/browsing but are unverified. Windows hosts remain unsupported.
  The helper's AppleScript was compiled successfully; interactive Finder selection
  was not exercised during automated verification. Path entry and folder browsing
  do not depend on that helper.
- Keep Codex signed in using its supported CLI login. A workspace-restricted agent
  may be unable to start app-server because it cannot open `~/.codex` state. Run the
  documented launch command in ordinary Terminal or grant that specific operation;
  the application does not bypass an enforced policy.
- A connected UI with an unsigned-in account does not establish model access.
  Readiness checks account state; a completed inference turn establishes actual use.
- Agent turns have a two-hour application limit. Per-plugin limits remain configured
  in MCP. Cancellation during existing core hashing/conversion may wait for that
  stage to finish; plugin cancellation retains partial execution records.
- Forced process death cannot guarantee child cleanup. Inspect leftover processes
  before resuming after a crash. No automatic expensive retry is performed.
- Text previews are bounded; the evidence list shows at most 5,000 files, folder
  browsing at most 500 entries. This is not a large-scale evidence management system.
- Reports may fail validation or need factual correction. Continue with a focused
  question and explicitly generate/update a new version; do not edit sealed bundles.
- Parallel analysis, multiple agents per case, other model providers, hosted access,
  advanced Markdown/export styling, artwork and polished document exports are deferred.

See `docs/UI_VALIDATION.md` for actual checks and their limits.

## Image coins

Each image gets a stable, decorative coin once normal readiness has saved its
SHA-256. Original report PNGs can be imported explicitly; otherwise a local SVG
renderer uses the existing display name (or filename), a hash-derived monogram,
and distinct circuit traces. Silver concentric rims, graphite faces, emerald
inlays and curved lettering follow the earlier report coins. The SVG companion
is stylized rather than the originals' photographic metal finish. It assigns no
malware family. No image model, network call, forensic command, or evidence hashing
is involved in artwork creation.

Assets stay in private Workbench storage: `coin-library/<image-sha256>/` stores the
immutable master and provenance; `<case-id>/assets/coins/` stores case copies.
New report versions carry portable copies, Markdown image links, manifest coin
metadata, and checksums. The report viewer also displays coins above old reports
without changing their sealed files. Hover artwork for its decorative label.
Click a coin to enlarge it. Left-click anywhere (including the coin) or press
Escape to dismiss; right-click the enlarged image to use the browser's Save Image
As menu. Keyboard users can focus a coin and press Enter or Space.

Populate existing images from saved metadata only (safe to repeat):

```sh
python -m volatility_mcp.ui.coins --state-dir /path/to/private/workbench
```

To reuse original PNG artwork, import it **before** population for that identity:

```sh
python -m volatility_mcp.ui.coins --state-dir /path/to/private/workbench \
  --sha256 <already-recorded-image-sha256> --png /path/to/original-coin.png \
  --label 'Existing image display name' \
  --provenance 'Original report asset; decorative, not forensic evidence'
```

Then run the population command. Existing coins are never replaced. Restart an
idle Workbench to load populated assets; do not interrupt an active investigation.
An artwork error is recorded without preventing analysis or report generation.
Core MCP tools remain entirely independent of this optional presentation layer.

Saved results can be filtered, counted, grouped and cited with the core
`query_output` and `get_evidence` tools. Workbench follow-ups use saved evidence
first; its report viewer can resolve checked citations to source values. Historical
locators remain readable but are not promoted to value-verified citations. See
[the saved-evidence contract](SAVED_EVIDENCE.md).


The **Coverage** tab shows each selected image's explicit plan or unspecified
scope, effective collection states, prior attempts and saved evidence/failure links.
Refresh reads saved data only. Orchestration jobs are separate from plugin outcomes.
New reports include a coverage snapshot and limitations summary; old reports are
unchanged. See [COVERAGE_EVALUATION.md](COVERAGE_EVALUATION.md). Restart only an idle
Workbench to load the new tool inventory, case guidance and view.
