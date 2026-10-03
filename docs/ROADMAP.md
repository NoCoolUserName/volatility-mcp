# Roadmap

## Implemented in the initial project

- One standalone stdio MCP server using the official MCP Python SDK and a separate
  official Volatility installation; no report requirement or model API key.
- Configurable evidence/output roots, controlled subprocess arguments, complete
  saved outputs and execution metadata, bounded reading, and case history.
- Installed plugin/argument discovery, OS discovery, and the isolated XP x86
  network-pool compatibility addon with explicit carving limitations.
- Setup, diagnostics, optional Codex registration, focused harmless tests, and CI.
- Optional version 0.1 reporting contract, reusable prompts, editable Markdown
  template, synthetic example, and structural provenance validation.

Implementation is not proof of universal support. [VALIDATION.md](VALIDATION.md)
records what was actually checked, including private local integration scope and
unverified conditions.

## Next: refine the report specification

- Review finding structure, evidence locators, uncertainty language, hypothesis
  dispositions, timeline semantics, completion status, and revision provenance.
- Evaluate report quality against curated, legally redistributable or locally
  provisioned training datasets with explicit expected artifacts and counterexamples.
- Strengthen report checks where useful without mistaking schema validity for
  correct interpretation or introducing reporting requirements into core tools.

## Later, subject to evidence and demand

- Additional host testing (Linux first; Windows requires process-management work),
  guest OS/symbol combinations, acquisition formats, and client interoperability.
- Optional human-readable evidence viewers and export improvements. Prior design
  preferences include left linked contents, Light/Matrix radio theme, original
  decorative case coins, and an actual decision/call dependency graph. Keep
  presentation dependencies optional and the Markdown report canonical.
- PDF/DOCX/HTML packaging, accessibility, print/offline review, and schema migration
  only after the reporting contract is refined. Do not create a web app for this.
- Reproducible detection evaluation using appropriate positive/negative controls
  and real telemetry coverage; no unsupported claim of detection efficacy.

An **ICS memory-image collection is a separate future project**. This repository
does not contain or create that collection, a Dragos dataset, malware samples, or
private case reports. No separate server repository or duplicate implementation is
planned. Core and optional companion remain in this one repository.
