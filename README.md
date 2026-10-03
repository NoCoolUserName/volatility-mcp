# volatility-mcp

A local, client-neutral MCP server for evidence-backed queries with **official
Volatility 3**. It runs your separately installed Volatility executable, saves
complete outputs and execution records, and exposes small, controlled tools over
stdio. It makes no LLM API calls and needs no model API key.

An **optional investigation and reporting workflow** lives in the same repository.
Individual queries do not require reports, templates, case-report metadata, or
Codex. No report is generated as a side effect of a tool call.

This is an independent project, not endorsed by the Volatility Foundation,
OpenAI, or Dragos. Original project material is MIT licensed; see
[third-party notices](THIRD_PARTY_NOTICES.md).

## Quick start 1: use the MCP server

### Prerequisites

- Python 3.12 or newer, Git, and a local MCP client that supports stdio.
- Official [Volatility 3](https://github.com/volatilityfoundation/volatility3),
  installed separately. Setup can reuse an existing installation or create one.
- Enough storage for the image, complete outputs, symbol cache, and optional dumps.
- A stable, readable acquisition copy you are authorized to analyze.

The verified local target is macOS on Apple silicon with native ARM64 Python
3.12 and Volatility 3 2.28.2. Platform and client checks, their scope, and remaining
limitations are recorded in [VALIDATION.md](docs/VALIDATION.md). Linux analysis-host
support is unverified; Windows hosts are currently unsupported because process
management uses POSIX primitives. A plugin importing successfully does
not establish support for every guest OS, symbol set, or image.

Clone this repository using its GitHub **Code** URL, enter the clone directory,
then create the server environment:

```sh
python3 -c 'import platform, sys; print(sys.executable, platform.machine())'
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
.venv/bin/python -m pip install --no-deps -e .
```

On Apple silicon the architecture must be `arm64`. If Python is missing or
running through Rosetta, install a suitable native build from
[python.org](https://www.python.org/downloads/macos/), then recreate only the new
server environment with that interpreter. Do not move an existing virtual
environment: its executable paths are not portable.

Reuse an existing working Volatility environment:

```sh
.venv/bin/python -m volatility_mcp setup \
  --config "$PWD/config.local.json" \
  --vol-python "$HOME/Forensics/volatility-env/bin/python" \
  --vol "$HOME/Forensics/volatility-env/bin/vol" \
  --evidence-root "$HOME/Forensics/cases" \
  --output-root "$HOME/Forensics/outputs"
```

For a new installation, replace the two `--vol-*` options above with
`--install-volatility`. This uses the official `volatility3[full]` package from
PyPI in a separate environment; it does not add Volatility to the MCP environment.
Use `setup --help` for an alternate Volatility environment location. Setup is
idempotent: a suitable installation is reused, and existing evidence is retained.

Put `.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`, or `.dd` acquisitions in the evidence
root, optionally in case subfolders. These are accepted filename extensions,
not a promise that every file or acquisition format is supported by Volatility.
Keep archives separately and extract only intended memory images after validating
the archive; the server does not unpack archives. Source files should be read-only.

Verify a real MCP handshake and discovery call:

```sh
.venv/bin/python -m volatility_mcp doctor --config "$PWD/config.local.json" --mcp
```

### Connect a client

For any stdio MCP client, configure the **absolute** server Python as the command
and these separate arguments:

```text
command: <clone>/.venv/bin/python
args: ["-m", "volatility_mcp", "serve", "--config", "<clone>/config.local.json"]
```

Replace `<clone>` with your clone's absolute path; do not paste angle-bracket
placeholders literally. Alternatively set `VOLATILITY_MCP_CONFIG` to the absolute
JSON configuration path. There is no HTTP listener, bearer token, or server-side
model credential. Configure your client's tool timeout above the configured
subprocess timeout, allowing extra time for hashing large images and discovery.

For **local Codex CLI**, this helper backs up the previous registration and Codex
configuration before registering the server and configuring compatible timeouts:

```sh
.venv/bin/python -m volatility_mcp register-codex \
  --config "$PWD/config.local.json" \
  --backup-dir "$HOME/Forensics/config-backups"
codex mcp list
codex mcp get volatility --json
codex -C "$PWD" --no-daemon
```

The underlying supported registration command is:

```sh
codex mcp add volatility -- "$PWD/.venv/bin/python" \
  -m volatility_mcp serve --config "$PWD/config.local.json"
```

The helper sets startup and tool timeouts to at least 90 and 1,800 seconds,
respectively, increasing them for configured execution limits and preserving
larger existing values and unrelated settings. CLI registration
listing proves configuration exists; `doctor --mcp` and an actual client tool call
prove protocol/tool operation. After code or configuration changes, exit the old
session and launch the command above to use a fresh server process. See the
[official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

Keep other configuration editors idle during registration. If registration or its
verification fails, the helper restores the previous configuration atomically
when the observed file has not changed again. If it detects a concurrent change,
it leaves the newer contents intact and reports the private backup for comparison.

Codex CLI runs on your computer and can use the configured local server. It can
use a [ChatGPT sign-in](https://learn.chatgpt.com/docs/auth); the MCP server itself
requires no extra model API key. An ordinary browser ChatGPT conversation cannot
directly access this local stdio server or your memory-image files. Analysis is
local, but excerpts returned through MCP can be sent to the connected AI service;
read [SECURITY.md](SECURITY.md) before analyzing sensitive acquisitions.

First request in your connected client:

> Use the volatility MCP tools to list memory images and discover installed
> plugins. For `example.vmem`, identify the guest OS, then run its appropriate
> process-list plugin. Cite saved output and report failures explicitly. Do not
> create a report.

The file must actually exist beneath the configured evidence root. No example
image or malware is distributed here.

## Available tools

| Tool | Purpose |
| --- | --- |
| `list_memory_images` | Inventory supported files with size and SHA-256. |
| `get_image_info` | Save OS/banner discovery probes; keep failures and unknowns explicit. |
| `list_plugins` | Discover installed plugin names; an exact/single match includes accepted arguments. |
| `run_plugin` | Run a discovered plugin with a validated string argument list; save raw outputs, metadata, and derived files. |
| `read_output` | Read a saved text output in bounded chunks with a continuation offset and truncation status. |
| `case_history` | Retrieve saved run history, commands, timestamps, hashes, and output locations. |

Discover names and options rather than relying on older Volatility cheat sheets.
For example, call `list_plugins` with `{"query":"pslist"}`, choose the appropriate
OS-specific match, inspect its schema, then call `run_plugin` with an exact name
and arguments such as `[]` or `["--pid", "1234"]`. Do not pass shell command strings.
Refer to live `tools/list` for complete schemas.

The included `xpnet.XpNetScan` is a **local compatibility addon**, separate from
official Volatility plugins. It carves Windows XP x86 TCPT/TCPA pool candidates;
stale or damaged allocations are possible. It cannot prove active connection
state, traffic, or malicious communication. Official Windows NetScan/NetStat may
reject XP. Discover actual compatibility and retain the exact failure.

## Quick start 2: optionally use investigation and reporting

After the MCP quick start succeeds, read the versioned
[report specification](docs/REPORT_SPEC.md) and use
[prompts/GENERATE_REPORT.md](prompts/GENERATE_REPORT.md) in a client that can read
the repository and write your chosen private case-output folder. With local Codex,
give that folder workspace write access, for example:

```sh
codex -C "$PWD" --add-dir "$HOME/Forensics/outputs" --no-daemon
```

Copyable request:

> Read `docs/REPORT_SPEC.md` and `prompts/GENERATE_REPORT.md`. Investigate
> `~/Forensics/cases/example.vmem` using the existing volatility MCP server. Create
> a new timestamped case bundle under `~/Forensics/outputs/reports` with all required
> deliverables. Discover plugins, follow evidence-supported pivots, preserve exact
> outputs and failures, and distinguish observations, inference, and unknowns.

The companion supplies an [editable template](reporting/templates/report.md),
an [explicitly synthetic example](examples/synthetic-case/README.md), and a structural
provenance check:

```sh
.venv/bin/python -m volatility_mcp report-check examples/synthetic-case
```

Required deliverables are `report.md`, `case-manifest.json`, `investigation.jsonl`,
`iocs.csv`, and `artifacts/`. Hunting content is conditional. Markdown is canonical;
HTML, PDF, DOCX, custom artwork, and elaborate presentation are deferred. The
server never assembles a report itself. The reporting workflow adds no runtime
dependencies and is not loaded during ordinary tool interactions.

## Configuration and troubleshooting

`config.local.json` is private and ignored by Git. Setup records absolute
Volatility interpreter/executable paths and evidence/output roots. Keep evidence,
outputs, and symbol caches outside the clone. See
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for configuration fields, execution metadata,
and boundaries.

- **No images listed:** use an accepted extension under the evidence root. Derived
  outputs, symlinks, AppleDouble files, and archive metadata are excluded.
- **Interpreter/plugin import failure:** run `doctor`; verify the configured
  interpreter and executable belong to the same working Volatility environment.
  Install missing official analysis dependencies there, not into the server venv.
- **Unknown argument:** inspect `list_plugins` for the exact plugin. Global flags,
  custom plugin directories, traversal, shell syntax, and output overrides are rejected.
- **Missing symbols or unsupported kernel:** retain stderr and the failed run.
  Supply matching official symbols through local configuration; do not substitute
  an unrelated profile. A failed scan is never a clean result.
- **Timeout or interrupted run:** consult `case_history` and saved metadata before
  retrying. Partial output is not complete analysis. Tune the local command timeout
  and the client's longer tool timeout for the image size.
- **Large output:** use artifact references and `read_output` in bounded chunks.
  Full raw output stays on disk; response previews explicitly indicate truncation.
- **MCP protocol error:** run `doctor --mcp`; stdout must contain only MCP messages.
  Diagnostics belong on stderr. A stale client process may still use old code.

For guided local installation, use [prompts/SETUP.md](prompts/SETUP.md).
Development instructions are in [CONTRIBUTING.md](CONTRIBUTING.md); implemented
capabilities and future work are separated in [ROADMAP.md](docs/ROADMAP.md).
