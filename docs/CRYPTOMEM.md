# CryptoMem: standalone cryptocurrency artifact detection

CryptoMem is maintained in
[NoCoolUserName/volatility3-cryptomem](https://github.com/NoCoolUserName/volatility3-cryptomem).
That repository owns the detector, tests, and releases. The profile pins
revision `f462c79dd249f2251698620485e1241a3b35d5cc` (CryptoMem 0.4.0 prerelease).
Compatibility revision 11 adds experimental `mac.cryptomem.CryptoMem`, preserving
the Windows and Linux commands and output schemas. All three commands use the
existing ten MCP tools, manual selection and forced offline execution. Discovery
of installed/bundled analyzer CryptoMem is independent of `enable_xpnet`; that
setting only controls the XP compatibility path.


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
Version 0.2.0 adds Monero standard addresses, subaddresses and integrated
addresses, validating block Base58, type/length, mainnet/testnet/stagenet prefixes
and Keccak checksums. Curve validity, wallet presence and activity are unverified.
Monero URI parameters, wallet files, keys/seeds and transaction hashes are not parsed.
ASCII and UTF-16LE matches have PID, process, layer, exact virtual offset and byte
length. Format/checksum status is separate from interpretation. Nearby context
or repeated occurrences do not prove wallet use, ownership, control or activity.

No mnemonic/private-key extraction, wallet database parsing, transaction
reconstruction, swap attribution, balances, API enrichment or automatic PDF
generation is included. Ethereum-shaped addresses do not establish a chain.
Unknown or unsupported formats are not evidence of absence.

## Install and invoke

Use the configured isolated **Volatility 3 2.28.2** analyzer and Python 3.12+.
CryptoMem needs `pycryptodome==3.23.0` for ERC-55 and Monero checksums; core's own dependencies remain
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

Currency choices are `all`, `btc`, `eth`, `xrp`, `xmr`. PID is required and scalar.
Use `--currency xmr` for Monero alone; `all` includes it automatically. CryptoMem exposes Windows, Linux and experimental Intel64 Mac commands; the **MCP tool count stays ten**.
The profile accepts the previous 0.2.0 Windows source hash and unchanged format
helper bytes while rejecting unrecognized local changes. Older 0.1.0 installs
should first upgrade to the documented 0.2.0 profile in an isolated analyzer.
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

## Linux memory images

Linux support starts with **x86-64 (Intel64)**. Other Linux architectures are
unsupported until tested. This adds memory-image analysis, not Linux desktop
packaging or a Workbench implementation.

```json
{"name":"list_plugins","arguments":{"query":"linux.cryptomem.CryptoMem"}}
```

Select the process PID/TGID (not a thread ID) from `linux.pslist.PsList`:

```json
{"name":"run_plugin","arguments":{"image":"linux.lime","plugin":"linux.cryptomem.CryptoMem","arguments":["--pid","1234","--currency","all","--max-scan-bytes","67108864","--max-results","1000"]}}
```

Matching **captured-kernel** symbols must be locally provisioned; a bundled pack
does not cover all distributions, kernel builds or configurations. Configure the
operator-owned `symbols` directory with a matching Linux ISF before using offline
analysis. Missing symbols/layers are explicit failed runs, not absence of addresses.
Pre-scan failures may not produce a CryptoMem summary; retain stderr and manifest.

Linux scans a single thread-group leader once, excludes kernel threads/tasks
without user memory, uses a process layer and VMAs with exclusive ends, and
preserves virtual offsets and process provenance. The same plain scanner and
unchanged BTC, Ethereum, XRP and Monero validators serve Windows and Linux.
Read overlap never crosses separate mappings or unreadable gaps; failed reads
stop with incomplete coverage. Volatility can omit invalid tasks/VMAs, so a
complete scan covers only enumerated mappings. Linux summary fields are
`vma_count`/`completed_vmas`; Windows retains `vad_count`/`completed_vads`.
Rows and limits are otherwise the same. No address occurrence proves ownership.

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

CryptoMem 0.3.0 has 76 standalone synthetic tests with real Volatility layers,
renderers and CLI discovery, plus simulated task/VMA enumeration. Includes four
address families crossing ASCII/UTF-16LE read boundaries, adjacent/separate VMAs,
unreadable gaps, TGID/TID semantics, symbol errors, limits and Windows regression.
Core tests run both adapters through the existing subprocess/artifact policies.
Real stdio MCP tests exercise discovery with XP enabled/disabled, execution,
empty results, missing symbols, incomplete scans, invalid arguments, timeouts and
in-flight cancellation in both protocol modes, including child termination and
preserved manifests. Installed-analyzer smoke tests exercise both actual adapters.
See [VALIDATION.md](VALIDATION.md) for measured versions and counts.

**Real-memory Linux validation remains outstanding.** Public sample references
were inspected but no suitably licensed Linux x86-64 acquisition with matching
symbols was established. Neither synthetic fixtures nor Windows regressions
validate Linux kernel/distribution coverage. No recovered data was uploaded.

CryptoMem publishes its source under VSL-1.0, retains CryptoScan reference
attribution and standards notices, and ships its required notices in LICENSE.
Core archives the pinned LICENSE with the installation receipt. Existing
community-plugin licensing restrictions remain unchanged; see
[LICENSING.md](../LICENSING.md) and [COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md).

## Experimental legacy Intel64 macOS adapter (0.4.0)

The existing `list_plugins` and `run_plugin` tools expose `mac.cryptomem.CryptoMem`
after `plugins-install`. It is manual-only and forced offline, independent of the
XP add-on toggle. Select a positive BSD PID from `mac.pslist.PsList`, not a Mach
thread ID. For example:

```json
{"name":"run_plugin","arguments":{"image":"mac.raw","plugin":"mac.cryptomem.CryptoMem","arguments":["--pid","1234","--currency","all"]}}
```

Reuse the bundled legacy `mac.zip` only when its Darwin kernel banner exactly
matches the capture. No new Mac symbol download or MCP tool is added. Existing
Mac plugins and symbols do not imply modern macOS support; upstream Mac analysis
is no longer actively maintained. Intel32, Apple silicon/ARM64 and modern macOS
captures are unsupported. An ARM64 analysis host is distinct from the capture.

The adapter reuses the shared scanner and validators, selects one BSD process and
checks exclusive-ended VM maps against the declared map count. Damaged/truncated
lists, overlaps, missing fields/layers, unreadable pages and limits fail explicitly.
Nested submaps are currently unsupported and cause incomplete failure before
scanning; this can affect ordinary processes with shared-region mappings. The
Mac summary uses `vma_count` and `completed_vmas`. No kernel build matrix is claimed.

Validation is synthetic. Real-memory macOS validation remains outstanding. An
address in memory establishes neither wallet ownership nor activity. Workbench
needs a pin to this core release and a new package to embed the updated inventory;
its existing UI/tools need no separate Mac detector.
