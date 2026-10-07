# Roadmap

## Implemented in the initial project

- One standalone stdio MCP server using the official MCP Python SDK and a separate
  official Volatility installation; no report requirement or model API key.
- Configurable evidence/output roots, controlled subprocess arguments, complete
  saved outputs and execution metadata, bounded reading, and case history.
- Persistent backend result reuse with conservative content/version/configuration
  invalidation, cross-process duplicate prevention within an output root, and
  hashing-time/byte measurements. See [RESULT_REUSE.md](RESULT_REUSE.md).
- Installed plugin/argument discovery, OS discovery, and the isolated XP x86
  network-pool compatibility addon with explicit carving limitations.
- Setup, diagnostics, optional Codex registration, focused harmless tests, and CI.
- Optional version 0.3 reporting contract (legacy 0.1/0.2 readable), reusable prompts, editable Markdown
  template, synthetic example, and structural provenance validation.
- Experimental optional loopback Workbench: native macOS selection/path entry,
  readiness, sequential cases, report/evidence views, resumable Codex conversations,
  explicit report revisions and cancellation. See [LOCAL_UI.md](LOCAL_UI.md) and
  [UI_VALIDATION.md](UI_VALIDATION.md) for the tested scope.

Implementation is not proof of universal support. [VALIDATION.md](VALIDATION.md)
records what was actually checked, including private local integration scope and
unverified conditions.

## Next: refine the report specification

- Structured saved-row queries and deterministic observable-value citations are
  implemented; see [SAVED_EVIDENCE.md](SAVED_EVIDENCE.md). Explicit coverage and a focused offline synthetic evaluation harness are also
  implemented; see [COVERAGE_EVALUATION.md](COVERAGE_EVALUATION.md). Real-world
  forensic accuracy and model-assisted evaluation remain unestablished.
- Review finding structure, evidence locators, uncertainty language, hypothesis
  dispositions, timeline semantics, completion status, and revision provenance.
- Evaluate report quality against curated, legally redistributable or locally
  provisioned training datasets with explicit expected artifacts and counterexamples.
- Strengthen report checks where useful without mistaking schema validity for
  correct interpretation or introducing reporting requirements into core tools.

## Later, subject to evidence and demand

- Additional host testing (Linux first; Windows requires process-management work),
  guest OS/symbol combinations, acquisition formats, and client interoperability.
- Application presentation, model adapters and desktop integration are tracked in
  [Workbench](https://github.com/NoCoolUserName/volatility-workbench).
- Reproducible detection evaluation using appropriate positive/negative controls
  and real telemetry coverage; no unsupported claim of detection efficacy.

An **ICS memory-image collection is a separate future project**. This repository
does not contain or create that collection, a Dragos dataset, malware samples, or
private case reports. The existing server repository remains authoritative for forensic code. Core and Workbench are independently maintained; see [SEPARATION.md](SEPARATION.md).
