# Optional local setup prompt

Paste this into **local Codex CLI** while its working directory is this repository.
Replace the three input values if your directories differ. This prompt configures
the standalone server; it does not request an investigation or report.

```text
Set up this volatility-mcp checkout for local stdio MCP use.

Inputs:
- Repository: the current working directory
- Evidence root: ~/Forensics/cases
- Output root: ~/Forensics/outputs

Read README.md, AGENTS.md, and docs/ARCHITECTURE.md. Inspect the actual OS, home,
Python architecture, existing Volatility executable/interpreter, and current MCP
registration before making changes. On Apple silicon, use native ARM64 Python.
Reuse a suitable working official Volatility installation; do not move its venv.
If prerequisites are absent, install them from their official sources. Install
official volatility3[full] in a separate environment only if needed. Never use a
community Volatility-MCP implementation, Docker, or a generic shell MCP tool.

Create this server's own .venv using the documented pinned requirements, install
the package, and run the documented idempotent setup with an ignored local config.
Keep evidence, output, cache, registration backups, and personal paths out of Git.
Do not download images or generate a report for this setup task.

Run doctor --mcp so verification includes genuine MCP initialization, tools/list,
and a harmless tool call, not just a direct vol shell command. Verify the Python
architecture, actual framework/SDK versions, installed plugin discovery, and no
reporting configuration requirement. Back up existing Codex registration/settings
before using register-codex. Preserve unrelated client configuration. Confirm with
codex mcp list and codex mcp get volatility --json; explain that listing alone does
not establish a connected tool call. Use compatible startup/tool timeouts.

Troubleshoot routine errors and finish all authorized local work. Ask only if a
required credential/interactive authentication is unavailable or a destination is
genuinely ambiguous. Do not upload evidence, publish anything, or change repository
visibility. Report exactly what passed/failed, actual local paths, the registered
command, and the supported command to restart Codex with a fresh MCP process.
```
