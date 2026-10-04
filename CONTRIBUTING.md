# Contributing

Keep the core small: stdio MCP, controlled Volatility execution, evidence
preservation, saved outputs, and case history. Investigation methodology and
report composition belong to the optional companion workflow.

Create a Python 3.12+ virtual environment, install `requirements.lock.txt`, then
install the project with `python -m pip install --no-deps -e .`. The focused tests
use standard-library `unittest` and the installed MCP SDK; no additional test
dependency is required. Run:

```sh
python -m unittest discover -s tests -v
python -m volatility_mcp report-check examples/synthetic-case
```

Use harmless fixtures and mocked Volatility output for automated tests. Cover
meaningful failure paths: path/symlink validation, argument boundaries, evidence
integrity, output confinement, cancellation/timeouts, MCP calls, and provenance.
Do not require a real memory image, AI credential, or network access in CI.
Separate simulated tests from actual integration checks in validation notes.

Update the relevant docs and tests when behavior changes. Keep
`docs/REPORT_SPEC.md` authoritative for reporting; do not create competing rules
in prompts. Document actual platform/client checks rather than assuming support.
Inspect the diff and staged files before submitting. **Never attach sensitive
dumps, live malware, recovered binaries, private reports, credentials, or personal
configuration to ordinary issues or pull requests.** See [SECURITY.md](SECURITY.md)
for private vulnerability reporting.

The optional UI lives under `src/volatility_mcp/ui/`. `tests/test_ui.py` uses
harmless analyzer fixtures, simulated Codex responses, and real local HTTP/MCP
exchanges; it needs no browser, model credentials, or UI-only dependencies. For UI
changes, also exercise the browser flow in `docs/LOCAL_UI.md` and record the actual
scope in `docs/UI_VALIDATION.md`. Keep screenshots and real case receipts private.
