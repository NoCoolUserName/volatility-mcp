# Symbol setup

The full release wheel includes all four pinned official Volatility Foundation
packs: 928,304,944 bytes of original ZIPs (about 885 MiB). Normal `setup` verifies
and copies these bundled files into the configured writable symbol store, then
indexes them using the analyzer. No separate symbol download is needed.
Allow space for the installed bundle and working copy; indexing takes several minutes.
Source/development installs without a bundle retain the verified download fallback.
The release asset contains the data; GitHub's automatic Source code ZIP does not.
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
applicable upstream rights. The full release redistributes the unchanged packs
under the upstream VSL notice, retained in `resources/SYMBOL_PACK_NOTICES.md`, with
the license text and corresponding source/pack provenance. An incomplete or corrupt
installed bundle fails rather than falling back to the network.

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
symbols. CryptoMem 0.3.0 supports Windows x86/x64 and Linux x86-64 process memory. Its
Linux support is synthetic-tested; these packs do not establish real-memory
recovery accuracy or compatibility with an unmatched kernel.

## Additional Linux kernel symbols

The Linux starter ZIP contains four older CentOS/Debian x86-64 tables. For newer
kernels, Volatility's [Linux tutorial](https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html)
points to [Abyss-W4tcher/volatility3-symbols](https://github.com/Abyss-W4tcher/volatility3-symbols),
which provides Ubuntu, Debian, Kali, AlmaLinux and Rocky Linux ISFs. As checked on
2026-10-24, its files are served as individual GitHub release assets. Its
[banner index](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/banners/banners_plain.json)
and [release mapping](https://github.com/Abyss-W4tcher/volatility3-symbols/blob/master/banners/releases.json)
identify the relevant files. Historical raw-file URLs may no longer work.

Obtain the full banner locally with the existing `banners.Banners` tool, then
compare it exactly against a locally downloaded index. Do not send the image,
recovered content or banner to an external search service. Check the selected
asset's published SHA-256 digest and inspect its embedded Linux banner before
installing the compressed `.json.xz` under the configured symbol store's `linux/`
subdirectory. Reindex offline with the configured analyzer. Keep a local receipt
with source URL/revision, digest and the banner; never change the ISF banner to
force a mismatch. A matching banner is necessary, not proof that every plugin
or kernel structure has been validated.

This community collection is an additional source, not a promise of universal
coverage and not newly redistributed in the four-pack release bundle. If there
is no exact match, generate an ISF with official
[dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from that captured
kernel's matching distro debug package (and System.map where available). Do not
substitute a nearby version, another distro's build or another architecture.


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

## Building a full release

From a clean committed checkout with the server build dependencies installed:

```sh
python scripts/build_symbol_bundle.py --output-dir /path/to/release
```

The builder acquires the fixed upstream packs once, verifies them, and includes
them in the wheel with notices and `symbol-bundle.json`. To build without symbol
downloads, add `--symbol-source /path/to/verified-packs`. Only tracked project
files enter the build; private evidence, configuration and caches are excluded.
The script verifies embedded pack hashes and writes wheel `SHA256SUMS` and an
external provenance manifest. Publish the full wheel, checksums and manifest as
release assets, with the exact source revision publicly available. Do not publish
the tiny fixture wheel used by `package_smoke.py` as a release.

Maintainers can run **Publish bundled symbols** from GitHub Actions on `main` to
build and publish the package version after its normal CI checks pass. It uses
the same builder, verifies uploaded asset hashes, and publishes only after all
three assets succeed. An interrupted draft can be resumed; an already published
release is never overwritten. The runner needs no evidence or local configuration.

## Additional Linux x86-64 collection

Core 0.1.2 ships a pinned, checksum-verified catalog of 10,255 community ISFs
from Abyss-W4tcher/volatility3-symbols revision
`297d1eacda67567c134d2873a426ec4ed8009f4d`. The complete compressed download is
20,974,550,776 bytes (19.53 GiB), covering Ubuntu, Debian, Kali, AlmaLinux and
Rocky Linux builds. This is a snapshot, not every kernel or distribution.
Other CryptoMem architectures remain unsupported until tested.

Run these operator commands while analysis is idle:

```sh
volatility-mcp symbols-catalog
volatility-mcp symbols-catalog --linux-banner 'FULL CAPTURED KERNEL BANNER'
volatility-mcp symbols-install --config /path/to/config.json --linux-banner 'FULL CAPTURED KERNEL BANNER'
# Or explicitly install the complete pinned x86-64 collection:
volatility-mcp symbols-install --config /path/to/config.json --linux-all
```

Selection occurs locally. The banner is never submitted to a remote search API;
only public catalog asset URLs are requested. Files are SHA-256/size verified
against published GitHub asset digests, decoded with an expanded-size bound,
and checked for a little-endian 64-bit pointer, Linux types and the full embedded
kernel banner. The installer writes under `symbols/linux/community/`, then runs
the existing Volatility offline indexer. It never opens a memory image.
Four concurrent downloads are used by default (`--workers 1` through `8`).
Initial full validation/indexing can take hours. Each transfer has a 30-minute
bound and 60-second I/O timeout; offline indexing has a six-hour bound.

Interrupted or failed installs retain completed verified files and remove
partial downloads. Repeat the same command to reverify and resume; unknown or
modified files are refused rather than overwritten. The shared pack-install lock
prevents overlapping installers. After a hard process kill, confirm no installer
is running before removing `.symbol-packs.lock`. An indexing failure is not a
ready install; retry after resolving the diagnostic. A successful run writes
`linux-community-symbols.receipt.json` with the catalog revision and hashes.
For offline transfer, provide `--symbol-source /path/to/collection` containing
catalog-relative paths (for example `Ubuntu/amd64/...json.xz`).

The wheel includes catalog metadata only; the downloaded community tables stay
outside both MCP and Workbench packages. Existing `--symbol-packs all` behavior
still provisions the four official starter packs. No MCP tool was added, and
analysis does not trigger community downloads. Workbench can use the same
configured store and cache without copying 19.53 GiB into each app update.
`volatility_mcp.api` additionally exports `linux_symbol_catalog(banner=None)`
and `install_linux_symbols(config, banner=None, source_dir=None, workers=4)`
(keyword-only options after config) for explicit operator integrations.

The community collection's public metadata identifies downloadable kernel-derived
ISFs; these are not relicensed under the project's MIT grant. Original URLs and
asset digests are retained. This release does not redistribute their ISF payloads.
A valid download and matching banner do not establish wallet ownership or prove
correct analysis against a real memory image. Real-memory Linux validation
remains outstanding.

Maintainers can regenerate metadata with `scripts/build_linux_symbol_catalog.py`
from the two upstream JSON indexes at one pinned commit and the public paginated
GitHub release asset metadata. Review changed URLs/digests/banners/counts, update
`CATALOG_SHA256`, and run catalog and installer tests before publishing. Runtime
code never trusts a floating remote catalog update.
