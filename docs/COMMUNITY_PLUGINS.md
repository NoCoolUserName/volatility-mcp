# Optional community analyzer profile

The `community-2026-10` profile adds third-party plugins to the **configured
Volatility environment**, independently of MCP clients and Workbench. It is
operator opt-in; no MCP tool, catalog request, or report installs packages.
Official Volatility 3 remains at 2.28.2. Core runtime requirements stay minimal.

With all clients idle, run from an installed core environment:

```sh
volatility-mcp plugins-install --config /absolute/path/to/config.json
```

The packaged `resources/addons.json` is the versioned source/dependency inventory.
It pins full upstream Git commits, original SHA-256, adapted SHA-256, exact
dependency versions, expected command names, notices and limitations. The installer
downloads from those pinned GitHub URLs, verifies both hashes, refuses native-file
replacement/unrecognized local edits, and uses the analysis execution lock. A
failed discovery rolls plugin files back. Dependency installation failures can
leave installed packages for diagnosis; evidence is never opened. Exact existing
dependency versions must match the profile; automatic upgrades/downgrades are
refused. Repeating the same install is safe.

| Commands | Upstream | Pinned revision |
| --- | --- | --- |
| `windows.ptemalfind.PteMalfind`, `windows.simple_pteenum.SimplePteEnumerator`, `windows.imgmalfind.ImageMalfind`, supporting `windows.apisearch.ApiSearch` | [f-block/volatility-plugins](https://github.com/f-block/volatility-plugins) | `c4b6ad45ce34f0b7eae9aef80dd6e9594e8c5b84` |
| `windows.prefetch.Prefetch`, `windows.anydesk.AnyDesk`, `windows.keepass.KeePass` | [forensicxlab/volatility3_plugins](https://github.com/forensicxlab/volatility3_plugins) | `5d6c67eff47e065aa734eb7090d9ff92846d80ba` |
| `windows.evtxlog.evtxlog` | [spitfirerxf/vol3-plugins](https://github.com/spitfirerxf/vol3-plugins) | `0d3968a05113096e35e4484febbb142221031acb` |
| `windows.browserhistoryextractor.BrowserHistoryExtractor` | [aynaitlamine/volatility3-browser-history](https://github.com/aynaitlamine/volatility3-browser-history) | `ce2197ac778e3651789cbbac9dc90208e798a83e` |

Ptenum is a helper library; SimplePteEnumerator is its callable enumeration
plugin. ApiSearch and PE helpers support ImgMalfind. The profile requires
Capstone 5.0.9, pefile 2024.8.26, future 1.0.0, python-evtx 0.8.1 and hexdump 3.3.
It preserves separately installed addons such as pypykatz.

Compatibility revision 1 updates old FileScan/PsList contracts, removes the extra
legacy Ptenum symbol requirement, and declares PTE-family analysis Intel64-only.
Cached-file reconstruction respects file offsets and a 536.87 MB per-file bound.
Prefetch decompression is bounded at 67.11 MB. Browser SQLite is read-only/immutable,
timestamps are UTC, parsing errors remain failures, output paths must come from
the current framework extraction, and summaries no longer corrupt JSON stdout.
Use `--full-urls` for untruncated browser URLs. EVTX does not recover the claimed
last-modified timestamp; it explicitly reports that as unavailable and does not
claim reconstructed files are complete. This is EVTX support, not XP EVT support.
Legacy upstream PluginRequirement deprecation warnings remain under the pinned
framework; updating the framework requires re-evaluating this profile.

Original downloaded files, notices and a receipt remain under the analyzer venv's
`share/volatility-mcp/addons/community-2026-10/`. This private receipt is not a
second case/evidence store. It contains software provenance only. Catalog refresh
discovers these plugins; source labels and compatibility notes are passed through
MCP to Workbench. Restart idle clients that retain their own catalog cache. The
existing argument validation, file boundaries, timeouts and reuse invalidation
continue to apply. Import/help success is not proof of image support or accuracy.

## Reproducibility, licensing and future distributions

Upstream plugin code is **not bundled** in the core wheel or this repository.
The f-block files contain MIT/BSD notices and GPL-derived portions; EVTXLog has an
MIT license retained by the installer. No explicit redistribution license was
found for the pinned forensicxlab or browser-history repositories. Local opt-in
download does not resolve permission to redistribute those sources. Resolve that
permission and relevant GPL obligations before baking them into public app or
container artifacts. Until then, a future distribution can retain this explicit
operator download step rather than claiming the sources are bundled/licensed.
No container or app packaging implementation is added here.

Add future plugins to this same profile/inventory after source, dependency,
license, output-boundary and compatibility review. Update original/adapted hashes
and focused fixtures; never silently replace a known pin or widen MCP permissions.

## Checks without private images

```sh
python -m unittest discover -s tests -p 'test_addons.py' -v
/absolute/path/to/analyzer/bin/python tests/addon_runtime_smoke.py
```

The optional second check requires the installed profile. It checks imports,
dependency versions and run-wrapper API signatures with mocked file/process
lists; synthetic Prefetch/AnyDesk/SQLite data, KeePass formatting, malformed
Prefetch/EVTX/database handling, and stdout/read-only safeguards. It forbids
subprocess and network calls after import. It does **not** evaluate PTE/ImageMalfind
algorithms, real credential recovery, all Windows builds or malware detection.
