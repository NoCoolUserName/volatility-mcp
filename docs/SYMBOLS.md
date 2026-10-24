# Symbol setup

Normal `volatility-mcp setup` provisions all four pinned official Volatility
Foundation packs and indexes them using the configured analyzer. The total
download is 928,304,944 bytes (about 885 MiB); indexing can take several minutes.
This is setup-time acquisition, not data bundled in the repository or wheel.
There is no new MCP tool and no bulk download during server startup or analysis.

For an existing installation, while analysis is idle:

```sh
python -m volatility_mcp symbols-install --config /path/to/config.json
```

Both commands accept `--symbol-packs windows` (base Windows pack plus the Windows
10 build 19041 supplement). Setup also accepts `--symbol-packs none` to retain
offline/custom provisioning. `--symbol-source /path/to/packs` uses predownloaded
official ZIP files with the same size/hash checks and makes no download requests.
Without an existing `symbols` setting, setup uses `<cache_path>/tables` and saves
that path only after successful provisioning. Existing custom symbol stores are
retained. Keep symbols/cache outside evidence and case-output trees.

## Integrity and retries

Downloads use fixed official HTTPS release URLs and reviewed sizes/SHA-256 hashes
from [the upstream checksum list](https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS).
Files are verified before atomic publication. Existing mismatched files are
refused rather than overwritten. Preserve/move an operator-modified pack before
retrying. ZIP contents are not extracted or executed. A local receipt records
sources, hashes, and index results. Symbols remain upstream data with their
applicable upstream rights; this project does not relicense or redistribute packs.

Rerunning verifies/reuses complete packs. Interrupted transfers leave no active
partial ZIP; a later indexing failure leaves verified packs available for retry.
After a hard process termination, remove `.symbol-packs.lock` only after confirming
that no installer is still running. Network errors are reported; setup does not
silently claim complete provisioning. Indexing is offline and never reads a memory
image. The existing typed XP preference also accepts its byte-identical duplicate
inside the official Windows pack, while still rejecting different table contents.
Fresh pack-only stores also apply that preference if an older analyzer contains
an incomplete table for the same reviewed XP identifier.

## Coverage and consumers

The [official packs](https://github.com/volatilityfoundation/volatility3#symbol-tables)
are representative snapshots, not all historical or future Windows/macOS/Linux
kernels. The base Windows pack is older; the separate supplement adds one Windows
10 build. Windows symbols require matching PDB identifiers; Linux/macOS require
matching kernel banners. Unmatched images can still need individually acquired
symbols. CryptoMem remains Windows x86/x64 only; these packs do not extend its OS
support or establish real-memory recovery accuracy.

Workbench uses the same configured symbol directory and cache. Existing
Workbench installs can use the command above from an updated core environment
with their existing config. This change does not add a Workbench settings button
or automatic provisioning to older packaged apps. The public core API exposes
`symbol_pack_config(config)` and `install_symbol_packs(config, packs='all',
source_dir=None)` for operator-driven setup integrations; persist the returned
configuration after successful installation and run only while analysis is idle.

Automated tests use tiny synthetic archives and ISFs with mocked downloads plus
real Volatility indexing in the analyzer CI job. No private images or live symbol
downloads are required by tests.
