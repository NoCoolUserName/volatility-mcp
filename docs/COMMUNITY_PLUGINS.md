# Optional community analyzer profile

The `community-2026-10` profile adds third-party plugins to the **configured
Volatility environment**, independently of MCP clients and Workbench. It is
operator opt-in; no MCP tool, catalog request, or report installs packages.
Official Volatility 3 remains at 2.28.2. Core runtime requirements stay minimal.

Displayed KB and MB use decimal units (1,000 and 1,000,000 bytes). This includes
binary page sizes: a 4,096-byte page is 4.096 KB. Display conversions do not
change page arithmetic, scan/read/output byte limits, adapter sources or hashes.
The unit-label cleanup retains every command in the configured analyzer.
Compatibility revision 6 adds the [BitLocker, Go and Python runtime batch](RUNTIME_ADDONS.md),
bringing the configured analyzer to 237 commands while preserving the prior 214.
The portable public baseline remains 200 commands.

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

Compatibility revision 2 retains the revision 1 FileScan/PsList updates, removes the extra
legacy Ptenum symbol requirement, and declares PTE-family analysis Intel64-only.
Three adapted files change only their size-limit wording to decimal MB. Their
previous installed hashes are explicitly pinned so an idle repeat install can
upgrade those known bytes; any other local modification remains blocked.
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

## First community3 batch (compatibility revision 3)

Revision 3 adds four commands through this same core inventory. No upstream
implementation is copied into Workbench, and no investigation-mode button is
added. Existing catalog names are checked before installation and must remain
present afterward; import failures roll back plugin changes. Known revision 1
error-message wording may advance to revision 2's decimal MB wording; the
existing algorithms and dependency versions are retained.

| New command | Source pin | Scope and bounds |
| --- | --- | --- |
| `windows.cobaltstrike.CobaltStrike` | Immersive-Labs-Sec/volatility_plugins `032bc053556f529ca4f698c77a12542b0ea58557` | Historical XOR 0x2e/0x69 config signatures in process VADs. Up to 67,108,864 scanned bytes, plus 4,096 bytes per candidate; 64 processes by default, hard cap 1,024. Up to 1,000 rows by default, hard cap 10,000. Layer/virtual offset included. |
| `windows.richheader.RichHeader` | Same Immersive Labs pin | Main executable DOS/Rich header only. Reads 64-byte DOS probe plus at most 65,536 header bytes per process. 64 processes by default, hard cap 1,024. Layer, image base and Rich marker offset included. MD5 is a header fingerprint, not author attribution. |
| `windows.zoneid3.ZoneID3` | kevthehermit/volatility_plugins `0f4f2fbbc93b8b59ead45f82e3287859a5ebc469` | Requires `--start` and `--length` in the selected primary layer. Maximum 67,108,864 scan bytes, 1,024 bytes per candidate; 1,000 rows by default, hard cap 10,000. UTF-8 CRLF ZoneId=3 records only. |
| `windows.pte_resolve.PteResolve` | f-block/volatility-plugins `c4b6ad45ce34f0b7eae9aef80dd6e9594e8c5b84` | Exactly one of `--vaddr`, `--pte-paddr`, `--pte-vaddr`, `--pte-value`; virtual selectors require one PID. Windows Intel64, matching kernel/PTE/PFN symbols, 4.096 KB pages only. Subsection mode and large/huge or unknown states are rejected. |

PteResolve retains the existing pinned Ptenum helper without changing its bytes.
Its own overrides avoid whole-PFN-database reads, bound each request to 65,536
bytes, aggregate nested reads to 16,777,216 bytes and 65,536 calls, VADs to 65,536,
process lookup to 1,024, and text output to 65,536 UTF-8 bytes. A swallowed upstream
read failure is remembered and fails the resolution. These conservative limits
can reject an otherwise valid image; rejection is incomplete analysis, not absence.
Other first-batch reads are strict (no zero padding), with 65,536-byte scan chunks.
The inherited core timeout remains in force.

The profile explicitly pins `yara-python==4.5.4`, already present in the reviewed
analyzer. Per-file dependency/limitation entries, original and adapted SHA-256,
full commits and expected names are in `resources/addons.json`. The two additional
MIT repository LICENSE files are verified and archived alongside originals;
CobaltStrike, RichHeader and PteResolve also retain their inline notices.

Core forces Volatility `--offline` for these four names using the inventory's
`offline_plugins` policy. Missing local symbols must be provisioned separately;
execution does not authorize a download. Direct CLI callers must also specify
`--offline`. Plugins never contact recovered URLs. This policy is enforced by
revision 3 core; a previously packaged Workbench with an older pinned core must
be rebuilt with the new core pin to inherit its attribution and offline policy.
The current signed Workbench application is not modified by `plugins-install`.

ZoneID3 citations now include `Layer`, `Offset` (hexadecimal, in that layer) and
`BytesRead`, alongside the saved command/row provenance. These are raw-memory
locations, not file offsets or proof that an NTFS alternate data stream exists.
URLs after a NUL or a subsequent ZoneTransfer header are not borrowed. A record
without URL fields produces no row; a recognized malformed/truncated record or
an unreadable range fails. RichHeader legitimately returns no row when a valid
DOS header has no Rich marker. CobaltStrike missing fields are unavailable,
not fabricated zero values. PteResolve failures never become empty successes.

```sh
/absolute/path/to/analyzer/bin/python tests/addon_first_batch_smoke.py -v
```

This additional offline suite exercises real YARA chunk-boundary hits, both
Cobalt encodings, Rich hash fixtures, Zone record boundaries/provenance, JSON
rendering, malformed/read/size/row failures, current PsList requirements and call
signatures, selector validation, bounded PFN access, and synthetic hardware/
transition PTE bit decoding. It denies network and subprocess creation before
plugin imports. Synthetic process handles and symbol/PFN corroboration are
isolated in fixtures; this is not an end-to-end kernel-symbol or OS-build test.

## Separately scoped candidates and evaluation gates

These are source evaluations and fixture requirements, not installed commands or
completed OS/build accuracy results. Cost ceilings below are proposed acceptance
budgets to validate before any separate integration.

| Separate change | Symbols/dependencies and remaining work | Representative fixtures and cost gate |
| --- | --- | --- |
| SwapEnumerator | Same f-block pin; `_MMPTE_SOFTWARE`, `_MMPTE_HARDWARE`, `_MMPFN`, kernel and Ptenum. Reconcile redundant `nt_symbols`, restrict Intel64, remove eager PFN reads; pagefile references do not recover missing content. | Synthetic resident/transition/software/compressed/absent-pagefile layouts with known counts, boundary addresses and corrupt entries. Require PID/range, cap one million visited PTEs, 67.108864 MB requested reads, 10,000 rows and 60 seconds initially. Measure actual cost before image evaluation. |
| Parent-spoof checks | orchechik/check_spoof `0a6ee712006f3cac5af38509345aa4710d256ab5`; Windows 8+ source assumptions, `_EPROCESS` and thread owner/parent fields. Port legacy APIs; independently validate PID-minus-one/minus-two logic and AppInfo/conhost exceptions. | Explicit normal, reused PID, terminated parent, spoofed parent, missing thread and benign broker cases. Limit 1,024 processes, 65,536 threads and 60 seconds; inconclusive missing metadata must stay explicit. |
| Docker | community3 `5ae4e232e14667277a0cc74848b87b634b4d8ad1`, Sheffer_Shaked_Docker. Matching Linux kernel ISF for task, namespaces, mount, net and cgroup structures. Port container logic without replacing native PsList/PsTree or other installed commands. | cgroup v1/v2, rootful/rootless, privileged/unprivileged, shared PID/net namespace, no-Docker and malformed/cyclic lists. Cap tasks/namespaces/mounts and traversal depth independently (initial 10,000 nodes, depth 128, 67.108864 MB reads, 60 seconds). No blanket container-inventory claim. |
| Alternate EVTX carver | Same community3 pin, Stelte_Evtx/evtx.py. EVTXtract and its dependencies need separate version/license pins; normal carving need not require kernel symbols. Port old namespace, raw-file/layer handling, Provider/Keywords mapping and exception suppression; avoid nested repeated template rescans. | Synthetic valid chunks/records/templates, deleted fragments, bad checksums, truncated XML, duplicate records, missing templates and layered inputs. Preserve physical offsets and validity. Start with 67.108864 MB input, 10,000 records, one template pass, 67.108864 MB output and 60 seconds. Compare recovery with existing EVTXLog; never replace it. |

PasswordManager is eligible for automatic investigation in revision 7 when
relevant to the authorized case scope; SSHKeys remains manually selected. Both
retain their explicit process scope, offline execution and limits. PFNInfo/P2V/RamMap and WinObj are deferred pending justification for their
larger compatibility and traversal work. CryptoScan detection ideas now inform the independent [CryptoMem](CRYPTOMEM.md)
scanner added in revision 8. Its implementation is maintained separately and
installed unchanged through this profile. No legacy CryptoScan code is executed.

Any later compatibility/accuracy campaign must name each selected OS/build,
architecture, acquisition format, matching symbol hashes, artifact ground truth,
positive/negative controls and per-run byte/time/output budgets. Obtain explicit
authorization for the actual fixture set and executions. This integration grants
no permission to inspect or run existing private cases as fixtures. No broad
compatibility sweep or quick-triage mode is implemented or invoked.


## Sensitive commands (installation revision 4; selection policy revision 7)

Revision 4 installs PasswordManager and SSHKeys through this same inventory.
Revision 7 permits PasswordManager in automatic investigation when relevant to
the authorized case scope (`manual_only: false`). It still requires an explicit
browser PID selected from observed processes; it is not an unconditional scan of
every process. SSHKeys retains `manual_only: true` and requires a direct request,
an explicit PID and one suspected `sshenc` address. Both remain offline and bounded.
No investigation mode is added; installation alone does not authorize a new case scan.

- `windows.passwordmanagers.PasswordManager`: kevthehermit/volatility_plugins,
  `0f4f2fbbc93b8b59ead45f82e3287859a5ebc469`, MIT. Historical LastPass fragments
  from chrome/firefox/iexplore only. Strict JSON string decoding, no recovered
  values in debug logs, layer/offset provenance; default 16.777216 MB scan / 100 rows,
  hard limits 67.108864 MB / 1000 rows and 4096 bytes per matched fragment.
- `linux.openssh_sessionkeys.SSHKeys` comes from the Apache-2.0 repository
  fox-it/OpenSSH-Session-Key-Recovery at upstream commit
  `78f7955b1e1fccb4b1a7e2382e0ed5a7c8becea3`. Installs both pinned
  `openssh32.json` and `openssh64.json` ISFs; matching Linux kernel symbols still
  must be supplied separately. Uses the current Linux PsList API. Targets one
  virtual structure address, with historical 6.1p1/6.1p2 layouts only. Unbounded
  heap scanning and arbitrary `--out` writes are disabled. Key <=64 bytes,
  IV <=32 bytes, cipher name <=64 bytes; nested reads <=16.777216 MB / 65536 calls.
  Missing pages, malformed recognized records and missing PIDs are errors.

Both are forced offline by core; direct CLI callers must pass `--offline`.
Results may contain secrets and are saved through the existing output system.
No endpoint is contacted. Seven synthetic tests exercise parser/JSON/error
contracts and both real 32/64-bit ISFs with known synthetic key/IV bytes.
These checks do not establish real-world credential recovery accuracy.

## Regex and cached-file reconstruction repairs

The pinned compatibility revision 5 binds the cache page's file offset before
reconstructing Prefetch data. Out-of-order pages are placed at their recorded
file offsets, gaps remain explicit, and the 536.87 MB reconstruction bound remains.
An earlier adapter could raise `NameError` before parsing; historical failures
remain failures until a separate, explicitly requested run succeeds.

`windows.dumpfiles.DumpFiles --filter` is a text regular expression, while
`windows.vadregexscan.VadRegExScan --pattern` is a byte regular expression. Their
installed schemas grant these exact fields bounded regex syntax, compiled before
execution. This is not a general string/path bypass: global options, duplicate
options, control bytes and other plugins' strings retain their existing guards.
Arguments go directly to a subprocess argv with no shell.

## Runtime analysis additions (compatibility revision 6)

The same inventory now installs one BitLocker candidate scanner, ten Go runtime
commands and twelve Python runtime commands. They are manually selected, forced
offline by core, and expose their narrow argument/layout requirements through the
catalog. Existing command names, including PasswordManager and SSHKeys, remain.
See [RUNTIME_ADDONS.md](RUNTIME_ADDONS.md) for exact pins, bounds, license notices,
validated fixture scope and remaining real-image accuracy work.

## CryptoMem (compatibility revision 8)

One independently maintained command, `windows.cryptomem.CryptoMem`, adds bounded
offline cryptocurrency address and direct payment-request detection. It requires
one PID, is manual-only, and preserves installed native and community commands.
The detector needs `pycryptodome==3.23.0`; no new core runtime dependency or MCP tool
is introduced. Source and license hashes pin the independent release without an
adapter. See [CRYPTOMEM.md](CRYPTOMEM.md) for installation, examples, limitations,
synthetic validation and Workbench adoption.
