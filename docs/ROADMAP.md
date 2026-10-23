# Roadmap

This is the remaining-work list, reviewed against current main on 18 October 2026.
Completed implementation and rollout history belongs in [VALIDATION.md](VALIDATION.md),
[COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md) and [RUNTIME_ADDONS.md](RUNTIME_ADDONS.md).
Close an item only when its acceptance evidence is recorded; successful imports,
fixture tests and installed command counts do not establish forensic accuracy.

Core owns plugin adapters, the single versioned addon inventory, execution policy,
symbols, evidence provenance and forensic evaluation. Application controls,
providers, packaging and presentation belong to the
[Workbench roadmap](https://github.com/NoCoolUserName/volatility-workbench/blob/main/docs/ROADMAP.md).

## Priority 1: authorized compatibility and accuracy evaluation

Create a small, versioned fixture manifest before running the next image campaign.
For every selected Windows/Linux build and runtime, record architecture, acquisition
format, image provenance/hash, matching local symbol hashes, known positive and
negative artifacts, independently expected values/source offsets, applicable
commands/arguments and byte/time/output limits. Include missing-page, malformed,
unsupported-layout and benign lookalike controls. Obtain explicit authorization
for that named fixture set and bounded executions. Existing private cases, saved
analyses and evidence are not authorized test fixtures.

Publish results by exact OS/build/runtime/plugin scope: success with observed rows,
valid empty, skipped prerequisite, unsupported, failure and incomplete. Record
false leads, missed known artifacts, source-offset agreement, read/output volume,
duration and peak resource cost. Separate integrity hashing and reuse from physical
plugin execution. Broaden support claims only for the combinations actually tested.

| Family | Remaining core work | Acceptance gate |
| --- | --- | --- |
| BitLocker | Validate pool layouts across selected Windows x64 builds; distinguish AES schedules from actual BitLocker material and establish key role/cipher mode independently. Evaluate raw-key and decryption-schedule variants separately. | Known-key positive/negative fixtures with expected pool/schedule offsets and independently established FVEK/tweak roles; demonstrate decryptability only against expressly authorized test volumes. Retain candidate wording and exclude adjacency pairing/export until this evidence exists. |
| Go | Establish a real-image matrix for candidate Go 1.16–1.25 layouts; heap/string paths start at 1.18. Measure strings, functions, goroutine/frame recovery and typed-heap coverage on Windows/Linux AMD64, including absent runtime pages and stripped/obfuscated metadata. | Build-matched fixtures with known runtime artifacts and offsets, independent expected values and measured cost within current bounds. Unknown layouts must fail; version parsing alone is not support. Any additional architecture/version or restored helper needs its own offline design and fixtures. |
| Python | Validate the exact pinned CPython 3.8 x64 research layout and examiner-supplied runtime address on representative builds. Determine useful coverage of classes, modules, functions, active frames and selected locals. Evaluate frozen/permanent-generation, untracked objects and other instance/metaclass layouts as separate extensions. | Known-artifact fixtures with build/layout provenance and expected addresses; explicit unsupported/incomplete outcomes for mismatches and missing pages. Other Python versions require separate layouts. Preserve raw target bytecode; any future disassembly must use the target version and never construct executable host code. |
| First community batch and existing addons | Extend the narrow public-image sample with known-positive and benign controls for CobaltStrike, RichHeader, ZoneID3, PteResolve and the earlier profile. Quantify artifact/signature and acquisition gaps. | Establish source offsets and expected values independently, including PTE states and missing pagefile content. Rich fingerprints do not identify authors; ZoneID3 memory strings do not prove an NTFS stream. Preserve the existing command-name set and recheck every affected adapter hash/dependency. |
| Sensitive recovery | Evaluate PasswordManager's historical browser fragments and SSHKeys' supported `sshenc` layouts using fabricated credentials/keys and known positive, negative and malformed fixtures. Measure completeness and false matches before wider claims. | PasswordManager may participate in an authorized automatic investigation when relevant and scoped to an explicit browser PID; its installation is not a separate manual-only gate. SSHKeys remains manually selected with an explicit PID/address. Other manual-only addons retain their catalog policy. Record sensitive-output handling and prevent recovered values from leaking into diagnostics or public test artifacts. |

The existing runtime bounds and exact excluded behavior are documented in
[RUNTIME_ADDONS.md](RUNTIME_ADDONS.md). Relaxing a bound, expanding a layout gate or
changing automatic-selection policy requires focused fixtures and a recorded reason;
it is not a side effect of the accuracy campaign.

## Priority 2: separately scoped plugin changes

Each row is a separate core change. Start with source/dependency/license review,
current API adaptation, source locators, explicit failure/empty semantics and
harmless fixtures; then use only authorized representative images. Extend the
existing inventory and retain installed names. The limits below are initial
acceptance budgets, not claims that these candidates already satisfy them.

| Candidate | Work before integration | Representative fixture and cost gate |
| --- | --- | --- |
| SwapEnumerator | Repair legacy symbols/APIs and eliminate eager PFN work; distinguish resident, transition, software/swapped and compressed PTEs. Report unavailable pagefile content explicitly. | Known counts, boundary addresses, corrupt entries and absent pagefiles; one PID/range, at most 1,000,000 PTEs, 67,108,864 read bytes, 10,000 rows and 60 seconds. |
| Parent-spoof checks | Port process/thread APIs; independently evaluate PID-minus-one/minus-two inference and AppInfo/conhost exceptions against existing native overlap. Missing metadata must be inconclusive. | Normal/spoofed/reused/terminated-parent and benign-broker fixtures; at most 1,024 processes, 65,536 threads and 60 seconds. |
| Docker | Adapt current Linux namespace/cgroup helpers with matching kernel ISFs; resolve source redistribution terms. Preserve native PsList/PsTree. | cgroup v1/v2, rootful/rootless, shared PID/net namespaces, privileged/unprivileged, no-container and malformed/cyclic fixtures; at most 10,000 nodes, depth 128, 67,108,864 read bytes and 60 seconds. |
| Alternate EVTX carver | Correct legacy namespace/layer handling, Provider/Keywords mapping and suppressed errors; pin EVTXtract dependencies/licenses, retain physical offsets and avoid repeated template rescans. | Valid/deleted/truncated/bad-checksum/missing-template/duplicate records and layered inputs; 67,108,864 input bytes, 10,000 records, one template pass, 67,108,864 output bytes and 60 seconds. Compare incremental recovery with installed EVTXLog before adopting it. |
| PFNInfo/P2V/RamMap and WinObj | Keep deferred until a concrete investigative need justifies the larger kernel-layout and traversal work. | A proposal identifying supported builds, symbols, independent expected results and bounded PFN/object traversal before porting. |
| CryptoMem real-memory validation | The independent scanner and pinned integration are documented in [CRYPTOMEM.md](CRYPTOMEM.md). Address formats and bounded payment requests have synthetic fixtures; private keys, wallet databases and transaction reconstruction remain out of scope. | Validate known-positive and negative authorized Windows acquisitions, symbols, exact memory locations, unreadable-page behavior and coverage before claiming real-world recovery accuracy. |

Source pins and detailed prerequisites remain in
[COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md). Workbench may expose reviewed additions
through its current catalog; these ports do not require new investigation modes.

## Priority 3: evaluation and report quality

- Extend the existing offline evaluation harness with independently reviewed,
  narrowly defined forensic tasks and counterexamples. Process hiding, cross-capture
  identity and injection classification need actual validated implementations before
  being scored as supported detectors; current synthetic scenarios are not detection
  accuracy. See [COVERAGE_EVALUATION.md](COVERAGE_EVALUATION.md).
- Evaluate report findings, uncertainty, hypothesis dispositions, timeline semantics
  and negative conclusions against authorized, curated saved-evidence sets. Keep
  factual observation checks distinct from interpretation and contract validity.
- Design a bounded model-assisted evaluation with explicit provider/data/cost scope
  before any live-model runs. Measure unsupported conclusions, citation-value errors,
  appropriate abstentions and missed known artifacts; preserve human review.
- Refine the report specification only where that evaluation identifies a gap.
  Preserve revision provenance and keep reporting optional for core tools.

## Distribution and host support

- Follow the VSL/MIT component map and source-publication steps in
  [LICENSING.md](../LICENSING.md). The VSL grant for original integration code is
  in place. Before expanding distributed bundles, check each added third-party
  source's own terms, including GPL/AGPL obligations and missing reuse grants.
- Add operational acceptance on selected Linux distributions and additional MCP
  clients. Windows host support needs process-management/cancellation work and its
  own tests; cross-platform CI alone does not establish host or guest-image support.
- Measure cancellation and resource limits during large integrity checks/conversion
  and analysis. Coordinate any core changes with Workbench's Stop/recovery and output
  storage work without weakening evidence preservation or result-reuse integrity.

An ICS memory-image collection remains a separate future project. This repository
does not create that collection or acquire malware/private cases as roadmap work.
