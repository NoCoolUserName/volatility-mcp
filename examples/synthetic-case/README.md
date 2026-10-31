# Synthetic reporting example

**Every image identity, process, address, timestamp, command result, and finding in
this example is invented. No memory image was analyzed and no Volatility plugin
was executed.** `artifacts/SYN-E001-input.txt` is harmless plain text, deliberately
not a supported image extension. It provides file contents for the example’s hash checks.

This example demonstrates the optional report contract: evidence-linked findings,
a successful mocked result, a failed mocked scan that remains unresolved, exact
artifact hashes, a decision table, a contextual IOC row, and no hunting package where the evidence does not support one. The three recorded calls are explicitly simulated. The mock JSON does not reproduce a complete Volatility output schema.

Read [report.md](report.md), inspect [case-manifest.json](case-manifest.json) and
[investigation.jsonl](investigation.jsonl), then run from the repository root:

```sh
.venv/bin/python -m volatility_mcp report-check examples/synthetic-case
```

The checker tests packaging and provenance structure, not forensic truth. These
fixtures are safe to share publicly; never substitute them for a real investigation.
