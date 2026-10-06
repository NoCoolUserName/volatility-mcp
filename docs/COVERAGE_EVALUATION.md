# Investigation coverage and offline evaluation

Coverage is a read-only projection of durable run manifests, verified saved outputs,
static inspections, reuse receipts, and explicitly declared plans. It is not another
scheduler/database or an installed-plugin checklist. Retrieving or refreshing it
never starts/retries analysis, inspects extracted bytes again, or hashes a memory
image. It verifies saved artifact hashes using the #2 saved-evidence machinery.

## Scope and plans

`get_coverage(image, offset=0, limit=20, entry_id=null, attempt_offset=0,
attempt_limit=10)` is the client-neutral MCP tool. Its two independent cursors page
scopes and each scope's attempts. It includes exact image/case namespace, plan
identity, question, plugin/meaningful arguments, run IDs/timestamps, result references,
reason codes, limitations, effective result and all prior attempts. `read_output`
opens its relative manifest/evidence/receipt paths inside the configured output root.

Without a plan, scope is **unspecified**. Ad hoc observed scopes are listed without
inventing intent. Exact plugin and argument vectors define a scope; different PID,
range or filter arguments remain separate. Option-order variants may remain separate;
coverage does not invoke plugin discovery to normalize them. Unknown legacy arguments
are not grouped as equivalent. Inspection scopes retain their input identity/settings.

A plan declares intent now, never asserts success. Save this illustrative JSON outside
Git, using real discovered plugin names/options for the actual investigation:

```json
{"profile":"Requested process examination","entries":[{"id":"processes","question":"Which processes were observed?","plugin":"windows.pslist.PsList","arguments":[]}]}
```

Then, for a standalone server's configured evidence/output roots:

```sh
.venv/bin/python -m volatility_mcp coverage-plan --config config.local.json --image example.raw --plan /path/to/private-plan.json
.venv/bin/python -m volatility_mcp coverage --config config.local.json --image example.raw
```

This only writes bounded metadata under `<image-output>/coverage/plans/`. Identical
latest plans are idempotent; changes append timestamped revisions with a previous ID.
Older plans/attempts remain. Optional applicability/reason in each entry is an explicit
operator declaration, displayed separately from observed execution applicability.
Core analysis tools do not require a plan or reporting configuration.

In Workbench, ask the case investigator to declare the actual requested scope using
`case_set_plan(image_id, plan)`. This optional case tool uses the same plan storage,
only for an already registered image. It does not authorize or schedule collection.
The live **Coverage** tab reads each registered image independently and shows summary,
attempt/failure detail, saved evidence links, and orchestration jobs. Refreshing the
browser or coverage does not submit jobs. Refresh coverage to see new recorded results.

## State dimensions and authoritative sources

| Dimension | States / source |
|---|---|
| Execution | `not_run`, `queued`, `running`, `succeeded`, `failed`, `timed_out`, `cancelled`, `interrupted`, `unknown`; saved run status and exit/completion metadata. |
| Applicability | `applicable`, `not_applicable`, `unsupported`, `blocked_prerequisites`, `unknown`; recorded failure categories or explicitly labeled plan declarations. Successful recorded execution indicates observed applicability, not universal compatibility. |
| Availability | `rows_present`, `successfully_empty`, `partial`, `malformed`, `unavailable`, `unknown`; hash-verified saved output parsing and collection status. |
| Delivery | Complete response or bounded pagination/truncation, with continuation offsets; never changes collection state. |

A zero exit with malformed JSON is **succeeded execution / malformed output**. A
missing or zero-byte output is never successfully empty. Empty requires valid `[]`,
verified unchanged artifacts, completed success and recorded zero exit. Timeout or
failed output containing rows is partial. Explicit `collection_complete:false` in
source metadata retains partial status. Otherwise the scope is the recorded plugin
completion; unknown acquisition gaps are not magically detected by the server.
Static string windows with continuation and incomplete PE reconstructions remain
partial observations. Source image freshness is not re-certified by a saved-only read.

The **latest recorded attempt** is effective. Earlier successful run IDs and every
failed/retried attempt stay visible; a later failure does not disappear behind a prior
success. Reuse receipts must match the original image/run/hash metadata and do not add
physical runs. `physical_commands_recorded` counts command records with an exit code;
legacy/interrupted launches without that metadata may be uncountable. It is a lower
bound from history, not a live process monitor. A still-running manifest retains a
liveness-unverified reason; a different MCP session alone does not prove interruption.

Workbench job states come from its existing scheduler, including `incomplete` mapped
to interrupted. They are shown separately because a completed conversational job does
not prove plugin completion. Client-observed failed tool requests are likewise separate;
without a linked run they cannot establish another physical execution. Core-only
clients need their own history for requests rejected before a run manifest exists.

Counts label **declared plan entries with successful collection**, not answered
questions, exhaustive coverage, or certainty that an image is clean. No percentage is
shown. `question_answered` is deliberately `not_determined`; factual observation checks
remain the job of `get_evidence`, and interpretation requires review.

## Legacy import, bounds and reports

There is no destructive migration or copied evidence database: import is the same
idempotent saved-record projection on each read. Missing/malformed legacy metadata
is unknown or an explicit issue, never reconstructed intent or a clean result. The
current plan plus original records survive restarts. Historical report bundles stay
untouched. Bounds: 2,000 records per image per category, 4 MiB per manifest, 256 MiB
saved-output budget per retrieval, inherited 64 MiB/JSON parser limits, 50 entries or
attempts per page, approximately 60 KB core response. Over-budget records stay unknown;
issues and receipt lists are explicitly truncated with totals. Large single entries
produce an actionable error instead of a nonadvancing cursor.

New Workbench report revisions package `coverage.json` as a hashed artifact, preserve
reuse receipts, and map supporting evidence/attempt manifests to portable bundle links.
A mechanical limitations block states missing/partial/unknown scope; the report checker
requires that block and checks basic ownership/state consistency. It does not certify
free-form negative conclusions. See [REPORT_SPEC.md](REPORT_SPEC.md). Standalone report
packaging without a coverage adapter explicitly records unknown scope instead of
inventing completeness. Existing 0.1/0.2 reports remain readable without adding coverage.

## Offline evaluation

From the repository with its ordinary server dependencies installed:

```sh
.venv/bin/python tests/evaluation/run.py --output /tmp/volatility-evaluation
.venv/bin/python -m unittest discover -s tests -p test_coverage.py -v
```

No private image, credential, network, paid model or installed Volatility is required.
The harness rejects **all** subprocess launches and network connections during replay.
It writes `results.json` and `summary.md` outside the repository. The fast default
replay runs in CI, where only synthetic results are attached as a build artifact.

- **A: software/contracts.** Deterministic saved state derivation, query/reference
  handling, source identity, retries/reuse/pagination, and fixture report behavior.
  Focused unittest checks also exercise actual stdio MCP restart and UI data paths.
- **B: defined forensic tasks.** The supported lead task is an explicitly configured
  exact-name saved query, gated on complete collection. It is evaluated with positive,
  negative and incomplete-source controls. PE/string metadata and the existing XP
  addon exercise observations, never execution/maliciousness attribution.
- **Unsupported detectors.** Process-hiding from pslist/psscan disagreement, cross-capture
  process identity and benign/malicious injection classification are not implemented.
  Their fixtures document counterexamples and test relevant contracts; outcomes are
  **unsupported**, not successful detection or model abstention.
- **C: model-assisted evaluation.** Not implemented or run. No claim about free-form
  reasoning, live-agent compliance, model quality or costs is made by this harness.

If the separate official Volatility environment is already installed, its pure-Python
framework can optionally be made importable to exercise the existing XP fixture. Do
not install it merely for the default suite. For example, prepend that environment's
`lib/python3.12/site-packages` directory to `PYTHONPATH` when running the same command
with the server Python (use the actual matching Python version). The fixture uses a
private temporary symbol-validation cache; no memory image or analyzer subprocess is
used. Default environments without it report XP as unsupported, not a pass.

Results record expected/actual states, mismatches, passed/failed/skipped/unsupported
counts, fixture/ground-truth hashes, implementation version and source hash, configuration,
invocation counters, task-specific false-positive leads/missed leads and appropriate/
inappropriate abstentions. A tiny designed query-rule control set is not malware
accuracy; precision/recall and an aggregate accuracy score are intentionally omitted.
Saved fixture command counts describe simulated history, distinct from actual replay
invocations (zero). Passing synthetic tests does not establish real-world accuracy.

## Ground truth and adding scenarios

`tests/evaluation/fixtures.json` holds renderer-shaped synthetic tables; versioned
`scenarios.json` holds independently authored expectations, origin, purpose, image/OS
scope, expected observables/coverage/references, required abstention or supported lead,
forbidden conclusions and limitations. The separately reviewed `baseline.json` pins the scenario count, unsupported tasks
and designed lead/abstention controls; a drift fails the replay command. Generated
results never overwrite these inputs.
New scenarios must identify an existing capability and a narrowly defined task, include
positive/negative or ambiguity controls, and independently justify expected values from
fixture bytes. Mark missing detectors unsupported; do not write a detector just to make
the score higher. Review expectation changes as behavioral changes. No sensitive dumps,
live malware, private outputs or external restricted source documents belong in fixtures.
