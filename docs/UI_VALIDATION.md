# Workbench validation — experimental first version

Validation: 2026-10-04 UTC. Assessment: **ready with stated limitations for the
local Apple-silicon/Codex use case**. This records project-team implementation
review and testing, not an independent security audit or forensic certification.
Private receipts, screenshots, actual paths, and memory outputs are excluded from Git.

## Automated checks with harmless fixtures

- The full suite completed 57 passing tests and one expected skip for the optional
  addon tests that require the separate Volatility environment. This included nine
  initial UI tests. After focused repairs, all 17 affected UI tests passed, for
  65 distinct passing core/protocol/report/UI checks across these runs.
- The UI tests exchange real stdio MCP messages with the existing server code and
  a clearly synthetic analyzer. Codex responses are simulated; no model API or real
  malware is used in CI. Existing protocol checks verify the core's six tools
  without reporting configuration or UI imports.
- Covered: readiness, provenance/links, report sealing, source preservation, same
  conversation follow-ups, immutable prior versions, grouped/separate captures,
  input and artifact path/symlink rejection, bounded large-output reads, duplicate
  request IDs, queued-work cancellation, interrupted readiness, restart recovery,
  missing-symbol limitations, changed evidence/run identity rejection, unsupported
  approvals, explicit command and MCP form decisions, and enforced-policy mismatch.
- Real local HTTP checks covered authentication, cross-origin/Host rejection,
  action requests without Origin, cookie flags, and refresh without new jobs.
- Python compilation and JavaScript syntax checks passed. A wheel built without
  installing dependencies and included all UI static assets. Importing the core
  server in isolated Python imported neither the UI nor reporting module. The UI
  adds no runtime dependency beyond the core's existing dependencies.

## Actual browser checks

Headless installed Chrome was driven with Playwright 1.63.0 from a temporary
validation installation, not a UI dependency. A harmless fixture exercised path
registration, readiness, first report, executive-summary placement, evidence-link
navigation, reload/reconnection, case question, second sealed report, and Stop.
No JavaScript page errors were recorded. UI state and completed work survived
refresh without duplicate scans. The fixture agent/analyzer were simulated.
A final browser check against the real case verified three report versions,
saved-evidence navigation, and inert rendering of controlled HTML/script-like
text and unsafe link syntax, again with no JavaScript errors.

The macOS native file-picker AppleScript compiled successfully. Interactive Finder
selection was not exercised; it remains a manual platform check. Other browsers,
accessibility assistive technologies, and non-macOS hosts remain unverified.

## Real Codex and Volatility integration

- Installed Codex 0.160.0 app-server initialized over stdio and reported existing
  ChatGPT authentication. No model provider, API key, or billing mode was changed.
  The actual generated protocol schema was inspected before implementation.
- A dedicated private case thread reported read-only sandboxing and on-request
  approvals routed to the user. Codex's state database required a specific approved
  execution outside the implementation session's workspace filesystem sandbox;
  the Workbench did not alter global Codex settings or disable its sandbox.
- Browser-driven readiness used a single existing Windows training image. Actual
  MCP banner and Windows info discovery succeeded and saved complete outputs.
  Source integrity checks passed. No exhaustive investigation was performed.
- The first agent-initiated process-list request was rejected before execution
  because MCP form elicitation was not supported yet. The first report correctly
  documented this gap. A sealed report is structurally valid and preserved; it is
  not proof of complete investigative coverage.
- A real follow-up after application restart resumed the same case thread and
  answered from saved outputs. An explicit report update produced a second sealed
  version without changing the first version's checksums or running more analysis.
- The second review repaired MCP form approvals. The exact scoped PsList request
  was inspected and approved once through the browser; the actual process-list
  execution then succeeded with unchanged source identity. No persistent approval
  rule was granted. The earlier failed-request evidence and report versions remain
  preserved. A third sealed revision incorporated the successful process inventory;
  all six readiness/report/question/update jobs completed. The final case has
  exactly three analyzer runs: banners, Windows info, and PsList. Follow-up report
  revisions reused outputs instead of rescanning.

## Two focused review-and-repair cycles

Cycle 1 corrected interruption classification, a turn-start/Stop race, and
synchronous report packaging that could block browser responsiveness. Stop now
marks interrupted work incomplete, handles an accepted turn whose response is
still pending, and waits for outstanding packaging tasks. Packaging checks every
run's source identity against case readiness before combining evidence. Large
activity/message previews are explicitly truncated while private originals remain.
Regression checks covered source mismatch, bounded reads, and policy overrides.

Cycle 2 inspected actual saved run records, exposing the unsupported MCP form
approval rather than accepting a successful chat/report turn as proof that PsList
ran. The form handler now waits for an explicit decision and validates submitted
content. Unsupported forms fail closed. Failed MCP requests without a core run
are preserved as separate artifacts and investigation steps; they are not fabricated
as successful runs or attributed to a different plugin. Both focused regressions
passed and the repaired approval was exercised through the real browser/agent/MCP
path. No third review cycle was performed.

## Limits

No independent proof of analytical correctness, complete symbol/plugin coverage,
or malware attribution is claimed. Report content and classification require human
review. Native selection interaction, other host platforms/clients/browsers,
complex/URL/device approval flows, long-running resource exhaustion, and forced
process-death recovery remain limited or unverified. SIGKILL cannot guarantee child
cleanup. Core hashing/conversion can delay cancellation; disk output has no quota.
The app-server/dynamic-tool API is experimental and may change in later Codex builds.
The UI is local-only, not a multi-user service or security sandbox. Model excerpts
may leave the machine through the configured AI service.

## Scoped analysis preauthorization follow-up

Workbench now sets the documented MCP `default_tools_approval_mode = "approve"`
for its case-scoped Volatility server on both thread start and resume. Global
Codex configuration, the read-only sandbox, and disabled shell tools are unchanged.
A regression test checks both new and resumed thread configuration.

The installed Codex 0.160.0 app-server completed a real authenticated turn through
the Workbench and scoped MCP server: a harmless simulated Volatility `run_plugin`
call completed, saved one analysis run, preserved the fixture, and raised zero
approval prompts. This checks the real agent/MCP approval path, not the accuracy
of memory analysis. No private memory image was analyzed. The 18 UI checks passed;
the HTTP check required permission to bind localhost outside the restricted test
sandbox. Tests also exposed an unclosed activity-log reader, repaired with a
context manager. Restart Workbench to apply the policy to loaded case threads.

## Stale running instance follow-up

The reported repeat approval prompts came from a Workbench backend started before
scoped tool preauthorization was committed. Reopening the launcher had reused that
backend; installing new source did not replace code already loaded in memory.
The affected process was gracefully restarted, preserving completed artifacts and
marking its paused request incomplete. The replacement session's application-code
fingerprint matched the installed code.

The launcher now rejects reopening an instance with a stale or absent code
fingerprint and explains how to restart it. Regression checks cover matching,
stale, and legacy fingerprints and exercise the locked-instance launch path to
verify that it does not reopen the browser. All 20 UI checks passed. A real
Codex-to-scoped-MCP turn using the harmless simulated analyzer completed with one
saved run, zero approval prompts, and unchanged source bytes. No private image
was reanalyzed for this verification.
