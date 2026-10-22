# BitLocker, Go and Python runtime addons

Compatibility revision 6 extends the single core addon inventory with 23 commands:
one Windows BitLocker candidate scanner, five Go commands for each of Windows and
Linux, and six Python commands for each OS. The configured analyzer grows from
214 to 237 commands without removing any prior name. These counts describe discovery,
not distinct capabilities or established forensic coverage.

All 23 are installed through the existing `plugins-install` workflow and marked
`manual_only`. Core forces offline Volatility dispatch. Workbench discovers their
names, attribution, arguments and limitations from the core catalog; its existing
manual-selection policy excludes them from automatic report/triage collection.
Direct Volatility CLI users must supply `--offline` too. Runtime parsing does not
download symbols, invoke language tools, call a model, or contact recovered endpoints.

Upstream files remain outside Workbench and the core wheel. The versioned
`resources/addons.json` records full Git pins, original/adapted SHA-256 values,
exact targets, dependencies, expected names, limitations and verified license files.
Original files and LICENSE texts remain in the analyzer's installation receipt area.
No additional Python package dependencies are needed by these adapted paths.

## Sources and supported scope

| Source | Pin | Installed commands and scope |
| --- | --- | --- |
| [lorelyai/volatility3-bitlocker](https://github.com/lorelyai/volatility3-bitlocker) | `d2afab51fea4878db8a79cef835176360d19b901` | `windows.bitlocker.BitlockerFVEKScan`; Windows x64, explicit kernel virtual range and local pool-header symbols. |
| [HalaAli198/Go-Memory-Forensics](https://github.com/HalaAli198/Go-Memory-Forensics) | `68c4d93edcdea9f584ad855cf963eb803b4ca328` | `go_strings.Go_Strings`, `go_strings_obfuscated.Go_Strings`, `go_functions.Go_Functions`, `go_goroutines.Go_Goroutines`, `go_entire_heap.Go_Entire_Heap` under both `linux` and `windows`; one AMD64 process. |
| [HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis](https://github.com/HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis) | `d78a705e91a8f5146581e71062ae3e448f91b5de` | `py_class.Py_Class`, `py_module.Py_Module`, `py_function.Py_Function`, `py_code.Py_Code`, `py_stack_call.Py_Stack_Call`, `py_stack_var.Py_Stack_Var` under both OS namespaces; explicit CPython layout/runtime address. |

BitLocker retains GPL attribution to lorelyai and the earlier Marcin Ulikowski
implementation. Go declares Apache-2.0; Python declares AGPL-3.0. These grants and
source/notice obligations are not replaced by this project's license. The public
app's existing bundle allowlist is unchanged; the configured local installation
obtains these sources through the pinned installer. See [LICENSING.md](../LICENSING.md)
for the VSL/MIT integration license map and separate upstream redistribution terms.

## BitLocker candidate scanner

`--start` and `--length` select one contiguous kernel virtual range. Length is at
most 16,777,216 bytes (16.777216 MB). The reviewed x64 `_POOL_HEADER` has size 16 and
its tag at offset 4. Strict reads include both the selected range and symbol-backed
header access. Matching allocations must fit the range and be at most 65,536 bytes;
default limits are 1,024 pools and 100 output rows, with hard ceilings of 4,096 and
1,000. Read calls are capped at 65,536, with an aggregate allowance of twice the
range length plus 65,536 bytes. Core's command timeout also applies.

Each row identifies the layer, pool offset, schedule offset, pool tag, key size and
independently validated AES encryption-schedule candidate. A schedule is not proof
of BitLocker use, a confirmed FVEK/tweak role, a cipher mode, or disk decryptability.
The upstream code's adjacency-based key pairing, mode guesses and Dislocker export
are excluded. Raw keys and decryption-schedule variants are not covered. A complete
range with no schedules is empty; unreadable, malformed or truncated matching
allocations and exceeded bounds fail explicitly.

## Go runtime suite

All commands require exactly one `--pid`. Local kernel symbols and relevant
executable/runtime pages are prerequisites. Version parsing accepts Go 1.16–1.25
layout candidates; this is a parsing gate, not a tested version-support matrix.
Unknown, older and future versions fail instead of falling back to guessed layouts.
An explicit `--go-version` is available for obfuscated version metadata.
Heap-dependent commands, including both string variants, require Go 1.18 or later.

Structured rows identify the process layer and virtual source offset. The adapted
paths recover strings, function metadata, goroutine/frame records and typed heap
objects. They exclude upstream host-specific signature/heap JSON files, third-party
download helpers, OpenAI imports and speculative call-argument reconstruction. The
upstream `go_strings_obfuscated` variant is included separately; it is not a sixth
kind of artifact.

Default budgets are 268,435,456 cumulative read bytes, 20,000 rows, 2,000,000 parser
steps and 60 seconds. Hard ceilings are 1,073,741,824 read bytes, 100,000 rows,
10,000,000 steps and 300 seconds. One read is at most 16,777,216 bytes; emitted
record details total at most 33,554,432 bytes. Recursion and record nesting are
bounded. Missing pages, malformed records and unsupported layouts are incomplete
analysis, even if some rows were already produced. The core retains those as
failed runs, not reusable successful evidence of absence.

## Python runtime suite

The integration requires one `--pid`, `--runtime-address`, `--python-version 3.8`
and `--layout-verified`. The latter records the examiner's verification that the
target matches the exact pinned x64, little-endian research layout with no Py_TRACE_REFS;
it does not automatically establish compatibility. Other versions/build layouts
are unsupported. Automatic cross-process runtime-symbol guessing is excluded.

`Py_Stack_Var` also requires an exact `--target-frame` name. Stack commands can
select a `--thread-address`; they do not invent a thread ID from questionable
upstream offsets. GC traversal, selected object metadata, active frame chains and
local variable slots retain source addresses. Unsupported value or instance layouts
are marked explicitly. Frozen/permanent-generation and untracked objects are
outside this traversal. `Py_Code` emits raw target wordcode and metadata; it does
not construct a host `CodeType`, execute recovered content, or disassemble it using
the host Python version.

Default bounds are 16,777,216 read bytes, 100,000 reads, 10,000 object/traversal steps,
65,536 bytes per value/read, 1,000 data rows and 4,194,304 output bytes. Hard ceilings
are 67,108,864 read bytes, 500,000 reads, 100,000 steps, 1,048,576 bytes per value/read,
10,000 rows and 16,777,216 output bytes. Container counts and recursive decoding are
also bounded. Rows are assembled before rendering; broken chains, unreadable pages,
malformed values and exceeded bounds fail instead of becoming empty success.
An empty status means only that the selected reachable scope contained no matching
records, not that the process had no relevant artifacts.

## Validation and remaining work

Run with the isolated analyzer after installing the pinned profile:

```sh
/path/to/analyzer/bin/python tests/addon_bitlocker_smoke.py -v
/path/to/analyzer/bin/python tests/addon_go_smoke.py -v
/path/to/analyzer/bin/python tests/addon_python_runtime_smoke.py -v
```

Fixtures contain synthetic memory structures and published AES test vectors. They
exercise valid/malformed records, current APIs, arguments, bounds, output/provenance,
JSON rendering and denied network/process creation. Catalog checks verify all prior
214 names, the 23 additions, help, source attribution and installed file hashes.
No private cases, evidence images, saved analyses or reports are fixtures.

The 18 October 2026 staged check on Volatility 2.28.2 discovered 237 names with
zero import failures and retained all prior 214. BitLocker passed 8 fixtures; Go
passed 15; Python's installed suite passed 12 with one preinstallation-only
generation test skipped (that separate generation check passed before staging).
The existing profile smoke, 20 first-batch fixtures and 7 sensitive-extraction
fixtures also passed. Core's installed-wheel run completed 108 tests with one
expected skip, real MCP negotiation, and packaged runtime source-license checks.
These are contract/parser checks, not an OS/build accuracy score.

Real-image accuracy across Windows/Linux builds, Go versions and Python builds
remains unestablished. Representative authorized images with known positive and
negative artifacts, matching symbols, expected offsets and measured resource costs
are required before widening support claims or adding automatic collection.

The earlier candidates remain separate changes: SwapEnumerator needs bounded PTE
traversal and symbol/API repairs; parent-spoof checks need independent validation
of PID heuristics; Docker needs current namespace/cgroup adapters; alternate EVTX
needs corrected layer/offset/error handling and bounded carving. Their proposed
fixtures and budgets remain in [COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md).
