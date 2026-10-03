# Synthetic reporting example

**Every image identity, process, address, timestamp, command result, and finding in
this example is invented. No memory image was analyzed and no Volatility plugin
was executed.** `artifacts/SYN-E001-input.txt` is harmless plain text, deliberately
not a supported image extension. It is included only so example hashes are real
hashes of actual harmless bytes.

This example demonstrates the optional report contract: evidence-linked findings,
a successful mocked result, a failed mocked scan that remains unresolved, exact
artifact hashes, a decision table, a contextual IOC row, and no unjustified hunting
package. The three recorded calls are explicitly simulated. The mock JSON is not
claimed to reproduce the complete output schema of an actual Volatility version.

Read [report.md](report.md), inspect [case-manifest.json](case-manifest.json) and
[investigation.jsonl](investigation.jsonl), then run from the repository root:

```sh
.venv/bin/python -m volatility_mcp report-check examples/synthetic-case
```

The checker tests packaging and provenance structure, not forensic truth. These
artifacts are public-safe fixtures; never substitute them for a real investigation.
