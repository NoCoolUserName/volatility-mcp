# CryptoMem: standalone cryptocurrency artifact detection

CryptoMem is maintained in
[NoCoolUserName/volatility3-cryptomem](https://github.com/NoCoolUserName/volatility3-cryptomem).
That repository owns the detector, tests, and releases. The profile pins
revision `d64aab3fe1a595336f51023a9a3d5d3da4678511` (CryptoMem 0.1.0). Core's compatibility
revision 8 adds it to the existing opt-in community inventory without copying
the implementation into MCP or Workbench, adding MCP tools, or changing the XP
addon setting. Installed CryptoMem discovery is independent of `enable_xpnet`.

## What changed from CryptoScan

The reviewed [CryptoScan revision](https://github.com/BoB10th-BTC/CryptoScan/tree/9588ff800ba625f7ef044ddb98a23013810fbf29)
targets Volatility 3 version 1.0.1 and uses legacy `primary`/`nt_symbols` and PsList APIs.
Its address/transaction enrichment makes external requests, its PDF path is a
scan side effect, and it depends on requests, reportlab, pytz, enchant and local
wordlist/art files without a reproducible dependency lock. Its main source has a
VSL-1.0 notice; no separate repository LICENSE was present at that revision.

CryptoMem uses those detection ideas as references, with a new scanner and
standards-based format checks. It is not a compatibility port or feature-parity
claim. It returns BTC legacy/Bech32/Bech32m, Ethereum-style, and XRP classic
address candidates, plus a bounded subset of direct-address payment requests.
ASCII and UTF-16LE matches have PID, process, layer, exact virtual offset and byte
length. Format/checksum status is separate from interpretation. Nearby context
or repeated occurrences do not prove wallet use, ownership, control or activity.

No mnemonic/private-key extraction, wallet database parsing, transaction
reconstruction, swap attribution, balances, API enrichment or automatic PDF
generation is included. Ethereum-shaped addresses do not establish a chain.
Unknown or unsupported formats are not evidence of absence.

## Install and invoke

Use the configured isolated **Volatility 3 2.28.2** analyzer and Python 3.12+.
CryptoMem needs `pycryptodome==3.23.0` for ERC-55; core's own dependencies remain
unchanged. With clients idle:

```sh
volatility-mcp plugins-install --config /absolute/path/to/config.json
```

This installs the existing community profile as well as CryptoMem. The profile
pins its complete commit, unchanged source hashes and LICENSE hash. The existing
installer rejects mismatches, native-file replacement and unknown local edits;
it preserves the existing catalog and rolls plugin files back on discovery
failure. No MCP request installs software. Restart clients after upgrading.

```json
{"name":"list_plugins","arguments":{"query":"windows.cryptomem.CryptoMem"}}
```

Select a PID from actual process evidence, then call the existing tool:

```json
{"name":"run_plugin","arguments":{"image":"windows.raw","plugin":"windows.cryptomem.CryptoMem","arguments":["--pid","1234","--currency","all","--max-scan-bytes","67108864","--max-results","1000"]}}
```

Currency choices are `all`, `btc`, `eth`, `xrp`. PID is required and scalar.
Defaults are 67,108,864 scan bytes and 1,000 findings; hard maxima are 268,435,456
bytes and 10,000 findings. Semantic bounds are validated by the plugin before
scanning; existing MCP schemas validate required arguments, types and choices.
The plugin is manual-only and core forces Volatility `--offline`. Missing local
symbols remain actionable failures. The scanner and analyzer make no address
enrichment requests or evidence uploads. MCP returns results to the requesting
client; Workbench's existing AI-provider data handling still applies.

Successful rows distinguish `Kind`, `Currency`, `Value`, `Canonical`,
`Format`, `Validation`, `Reason`, `Encoding`, `Context`, `Network`,
`Amount`, `PID`, `Process`, `Layer`, `Offset`, and `ByteLength`.
For example, a synthetic checksum-valid Bitcoin address row has
`Validation: "checksum_valid"`; that field makes no ownership claim. Original
text is preserved even when a normalized comparison value is available.
Uniform-case Ethereum-style addresses are `format_only`; invalid checksums
remain distinguishable candidates. Address-family prefixes do not establish
which blockchain a recovered string was used on.

## Artifacts, isolation and reuse

The normal run retains raw JSON/stdout, stderr, readable output and manifest.
The plugin's `cryptomem-findings.jsonl` and `cryptomem-scan-summary.json` are ordinary registered
files under that run's `json/files/`. The summary records actual scan coverage;
partial results, read failures and exhausted limits must not be treated as a
complete empty result. Timeout/cancellation retain whatever was written and are
not reusable successes. A summary missing after termination means completion is
unknown. No full process dump or report is generated.

Core retains its image-before/after hashing, case boundaries, installed source
and dependency identity, artifact hashes, timeout/cancellation and cache checks.
Use `query_output` to filter `Canonical` or group occurrences without rescanning.
For address occurrence counts, also filter `Kind` to `address`: a payment-request
row and its embedded address row otherwise share a canonical value and both
contribute to a group count. Use `get_evidence` for hash-bound saved-row citations.
Virtual memory offsets are not asserted to be offsets into the original
acquisition file.

## Workbench adoption

The catalog automatically exposes the installed command through the shared
backend. No dedicated UI or Workbench detector is needed. An older packaged app
must adopt this core revision to receive its installer, attribution, manual-only
and offline policy; merely installing the plugin beside an old core is not the
complete integration.

Workbench's existing dependency updater selects newer stable versioned releases;
it does not select an arbitrary same-version core commit. To adopt this integration
before such a release, update `core-dependency.json`'s `commit` and the Git pin in
both `pyproject.toml` and `requirements.lock.txt` to the same full merged core SHA.
Keep the recorded version consistent with that core's package metadata; this
change does not alter core runtime dependencies. Validate the proposed Workbench
pin in its checkout using its existing checks:

```sh
.venv/bin/python -m pip install -r requirements.lock.txt
.venv/bin/python scripts/install_core_pin.py
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m unittest discover -s tests -q
node --check src/volatility_workbench/static/app.js
.venv/bin/python scripts/package_smoke.py
```

For an ARM64 Mac package, then follow Workbench's documented build and validation:

```sh
python3 scripts/build_macos.py --output dist/macos
python3 scripts/validate_macos.py 'dist/macos/Volatility Workbench.app'
python3 scripts/install_macos.py 'dist/macos/Volatility Workbench.app' --desktop-launcher
```

Use the updated app's explicit addon installation into its managed writable
overlay or an external analyzer. Do not edit a signed bundle. No Workbench source,
dependency pin, bundle or installed application is changed by this MCP PR.

## Validation and licensing

The standalone repository tests actual detectors with public vectors and
synthetic buffers, using real Volatility layers/renderers and fake process/VAD
enumeration. Core adds installed-plugin smoke checks and subprocess-simulator
tests for parameters, artifacts, isolation, failures, timeout/cancellation and
reuse. CI installs the pinned source in an isolated analyzer. None establishes
real-memory recovery or a Windows-build support matrix. Local validation on
2026-10-23 passed 56 standalone tests, 119 core tests (one optional analyzer test
skipped there), five installed CryptoMem checks and 79 existing addon checks,
including XPNet. The isolated full analyzer retained all 197 native commands:
236 with community plugins, or 237 with XP enabled; no import failures. The
actual installed plugin rejected a deliberately corrupt synthetic acquisition
through MCP without changing its hash. Real-image validation
still needs authorized positive/negative acquisitions, matching symbols, known
artifact locations, acquisition hashes and per-run coverage.

CryptoMem publishes its source under VSL-1.0, retains CryptoScan reference
attribution and standards notices, and ships its required notices in LICENSE.
Core archives the pinned LICENSE with the installation receipt. Existing
community-plugin licensing restrictions remain unchanged; see
[LICENSING.md](../LICENSING.md) and [COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md).
