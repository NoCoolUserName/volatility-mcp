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
3. **Check readiness** connects to the existing Codex account, initializes the six
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
