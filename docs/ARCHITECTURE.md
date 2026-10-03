# Architecture

## Core and optional companion

```text
Local MCP client
    | stdio MCP (official Python SDK)
    v
volatility_mcp.server -> validated backend -> existing official Volatility CLI
                             |                     |
                       read-only image       saved JSON/stdout, stderr, dumps
                             |                     |
                         evidence root         output root + run metadata

Optional analyst/client workflow
    saved artifacts + REPORT_SPEC.md -> report.md + case provenance + IOC exports
```

The server does no LLM inference, requests no model API key, and has no HTTP service,
database service, Docker dependency, web app, or report-generation side effect. The official
MCP SDK is its runtime dependency; Volatility and its full analysis dependencies
remain in a separate environment. The optional reporting checker uses the Python
standard library. A reporting client composes the report only when asked, using
actual outputs plus the versioned report specification.

Source code is in `src/volatility_mcp/`. `server.py` at repository root is a small
compatibility launcher for an existing local registration; it uses ignored local
configuration. The module/console CLI is the portable entry point. There is one
server implementation. Tests use harmless fixtures, while private real-image runs
remain outside Git.

## Configuration

`python -m volatility_mcp setup` writes private JSON. Selection order is explicit
`--config`, `VOLATILITY_MCP_CONFIG`, then
`~/.config/volatility-mcp/config.json`. The compatibility launcher also supports
the existing ignored `config.local.json` next to it. Operator configuration is
trusted and is never accepted as an MCP tool argument.

| Field | Purpose/default |
| --- | --- |
| `schema_version` | Configuration schema `1`; separate from report/run schemas. |
| `vol_python`, `vol_executable` | Absolute paths to the existing Volatility environment's Python and `vol` script. |
| `evidence_root` | Read-only acquisitions; setup defaults to `~/Forensics/cases`. |
| `output_root` | Per-case run artifacts; defaults to `~/Forensics/outputs`. |
| `symbols` | Optional operator-provided supplemental symbol directory. |
| `cache_path` | Symbol cache; defaults to `~/.cache/volatility-mcp/symbols`. |
| `command_timeout` | Plugin process timeout in seconds, default `300`. |
| `catalog_timeout` | Plugin discovery timeout in seconds, default `60`. |
| `enable_xpnet` | Enable the packaged fixed local compatibility addon, default `true`. |

Directories are canonicalized and checked; an output root cannot equal or contain
the evidence root. For an older installation with outputs below the evidence root,
discovery excludes that output tree. New installations use separate roots.
No personal paths are baked into tracked configuration. Local symbol fixes and
caches are not redistributed; supply matching official symbols for your image.
New evidence/output/cache directories are private to the local account; existing
directory permissions are preserved. Keep shared-directory access deliberate.

The optional Codex registration helper backs up the original configuration and
registration before invoking the installed CLI. It verifies the resulting exact
stdio command and restores the original file on failure using an atomic write
guarded by the last observed bytes. A detected concurrent edit prevents automatic
restoration and produces a backup reference. This is not a lock against a malicious
writer racing the final comparison/rename; avoid concurrent configuration edits.

## Tools and execution

- `list_memory_images()` returns supported source files and fingerprints, excluding
  derived trees, symlinks, and archive metadata.
- `get_image_info(image, os_hint="auto")` preserves banner/OS discovery attempts,
  returning identified, mixed, or unknown OS with caveats. A banner is a clue, not
  proof that typed symbols and every OS plugin work.
- `list_plugins(query="")` imports the installed Volatility catalog with the fixed
  addon directory. It reports origins, versions, import failures, and validated
  supported argument schemas when narrowed to one plugin.
- `run_plugin(image, plugin, arguments=[])` validates the exact installed name and
  list of strings, records source identity, and runs a process using `shell=False`.
  Global flags, caller-selected plugin directories, output overrides, traversal,
  shell syntax, unknown options, and unsafe input references are rejected.
- `read_output(path, offset=0, limit=16384)` reads only inside the configured output
  root. Limits are byte counts (maximum 65,536); `next_offset` and `truncated` support
  paging. UTF-8 decoding uses replacement for invalid bytes; raw files retain exact
  bytes. Do not use this text API to claim byte-exact reconstruction of binary data.
- `case_history(image, limit=50, offset=0)` returns bounded prior execution summaries.
  Read the referenced manifests for full metadata and hashes.

The server owns the command's image path, renderer, plugin path, symbols/cache, and
output directory. Plugin argument support follows installed requirement metadata;
the conservative allowlist can reject otherwise valid free-form strings. This is
intentional and should yield an actionable error, not a hidden shell fallback.
The fixed addon may be disabled locally; an MCP caller cannot substitute plugin code.

Each requested plugin runs **once with the JSON renderer**. Complete raw stdout and
stderr go directly to files; a human-readable view is generated from that saved JSON
without rerunning analysis. Invalid/unsupported JSON leaves raw bytes intact and
marks `output_error`. A single unusually large JSON record can exceed the bounded
converter's record limit; this is explicit conversion failure, not an empty result.
Process output and extracted files are not artificially truncated on disk.

The process timeout bounds plugin execution, not the entire tool's pre/post hashing,
catalog loading, or artifact conversion. Clients need a longer timeout; the Codex
registration helper uses at least 90 seconds for startup and 1,800 for tools,
increasing these for configured limits. Large images may need longer settings.
Analysis is serialized in a server process. Cancellation, timeout, client disconnect, and graceful SIGTERM kill the child
process group and retain partial output/status. Uncatchable termination (such as SIGKILL) can
leave a `running` manifest; a later session identifies it as interrupted or from
another session rather than declaring it successful. A force-killed server can leave a
child process running; inspect local processes before retrying. No automatic expensive retry
or alternate-renderer rescan occurs.

Protocol messages alone use stdout; diagnostics use stderr. The current process
confinement uses POSIX process groups; Windows as an analysis host is unsupported.

## Core provenance and output structure

```text
output_root/
  <image-stem>-<relative-path-hash>/
    runs/<UTC timestamp>-<random run ID>/
      manifest.json
      command.started.json
      json/stdout.json       # exact stdout, valid JSON only when parsing succeeds
      json/stderr.txt        # exact diagnostics, including failed commands
      json/output.txt        # derived readable view when conversion succeeds
      json/files/            # optional plugin-created extraction
      plugin-source/         # local addon source snapshot when applicable
```

A run manifest records image-relative identity, before/after SHA-256 and file
fingerprints, actual versions, plugin/options, exact subprocess argv, UTC times,
timeout and exit status, output paths/hashes, and integrity status. Local-addon runs
snapshot/hash the addon source and verify it did not change. Immutable source bytes
and complete raw output are the evidence; previews are navigation aids. An execution
metadata manifest is not the optional reporting `case-manifest.json`.

Reports reference stable artifact IDs with row/field/offset locators and copy exact
outputs to their separate `artifacts/` directory for portable links. Investigator
questions, concise rationale, finding IDs, IOC classification, and hunting decisions
are companion records; the core does not fabricate them.

## Compatibility and limitations

**Protocol compatibility** means standard stdio MCP negotiation and tool calls via
the official SDK. It does not certify every MCP client. **Actually tested clients
and protocol versions** are listed in [VALIDATION.md](VALIDATION.md). The Codex CLI
and official SDK are the local integration targets; other clients require their
own checks and timeout configuration. Ordinary browser chat has no direct local
stdio/file access.

Volatility plugin import availability is separate from runtime image compatibility.
Symbols, architecture, kernel versions, missing pages, and acquisition formats can
block a plugin. XP networking in the local addon is carving, not active-table
enumeration or traffic evidence. Linux/macOS guest analysis needs matching symbols
and is not established by a Windows smoke test. Real-image findings must be reviewed;
neither MCP nor structural report validation establishes malware attribution.

This is a controlled local application, not a security sandbox or evidence-acquisition
tool. A malicious concurrent local writer, compromised configured executable,
dependency/parser vulnerability, exhausted disk, or forced process death can exceed
its guarantees. See [SECURITY.md](../SECURITY.md) for data handling and AI-service
exposure. No report or core tool uploads evidence on its own.
