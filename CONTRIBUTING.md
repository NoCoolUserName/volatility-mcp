# Contributing

Original project contributions are accepted under both VSL 1.0 and MIT, as mapped
in [LICENSING.md](LICENSING.md). Preserve upstream notices on third-party material;
do not submit material you cannot license on the applicable terms.

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

Workbench development and browser checks belong to the
[Workbench repository](https://github.com/NoCoolUserName/volatility-workbench).
Keep core independently installable. Shared interface changes must preserve or
explicitly version `volatility_mcp.api.API_VERSION`. Tag tested core releases as
`v<package-version>`; Workbench adopts eligible releases through tested dependency
PRs. Never float a production dependency on main.

The manual **Publish bundled symbols** workflow requires the latest main-push
runs of Core tests, Code quality, and Security to have succeeded for its exact
source commit. Wait for those runs before dispatching; missing, pending, skipped,
or failed runs block publication. A rerun must also finish successfully.
The gate checks package/runtime/manifest versions and source provenance, resolves
lightweight or annotated release tags, and refuses an existing tag pointing at a
different commit. A missing `v<package-version>` tag is created at the checked
commit and verified again before uploads and publication. Published releases are
never overwritten; bump the version for a new release. These checks reuse CI;
they do not publish on tag pushes or change normal MCP execution.
