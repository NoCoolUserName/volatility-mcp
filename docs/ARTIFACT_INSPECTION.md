# Static inspection of saved artifacts

`inspect_artifact` is a core MCP tool exposed by both the standalone server and
the Workbench's case-scoped server. No shell access, report configuration, model
API, Volatility rerun or reconstruction is needed. Install the updated locked
dependencies (`pefile==2024.8.26` is added to the server environment) and restart
idle clients after upgrading. Existing Volatility installations are not modified.

## Select a registered artifact

1. Use `case_history(image)` to obtain the source run ID and manifest path.
2. Read the manifest through `read_output`; choose an existing entry from
   `commands[].artifacts`. Use its exact path relative to that run directory.
3. Call, for example (replace the illustrative run ID/path with saved identities):

```json
{"image":"example.raw","run_id":"2026-10-06_00-00-00Z-example","artifact":"json/files/reconstructed.dmp","operation":"pe"}
```

For strings:

```json
{"image":"example.raw","run_id":"2026-10-06_00-00-00Z-example","artifact":"json/files/reconstructed.dmp","operation":"strings","encoding":"utf-16le","min_length":4,"offset":0,"limit":100,"scan_bytes":1048576,"max_string_length":256}
```

Keep the other settings fixed and use the returned `result.next_offset` while
`result.truncated` is true. ASCII and UTF-16LE are separate passes. Strings include
decimal/hex file offsets, encoding, observed byte/character lengths, bounded text,
and explicit text/window-continuation flags. Printable characters are U+0020 through
U+007E; arbitrary Unicode is not covered. UTF-16LE matches either byte alignment.
Short strings crossing scan windows are carried forward; longer strings can be
returned as flagged fragments. Counts are observations, not malicious indicators.

Limits: regular files up to 64 MiB, at most 96 PE sections, minimum string length
2..128, page size 1..200 records, scan budget 256 bytes..4 MiB, and preview length
16..512 characters. A worker deadline is the lesser of 30 seconds and the configured
command timeout. The existing cross-process execution lock and cancellation event
apply. Timeouts/failures preserve diagnostics and cannot become complete results.

## Boundaries and provenance

The image must satisfy the current backend's evidence registration; in Workbench
it must be one of that case's selected images. Run and artifact identities must
match the saved manifest. Absolute artifact paths, traversal, symlinks, other-case
images, unregistered files and modified extraction hashes are rejected. The image
is resolved but not read/hashed; only the selected artifact is read. Its hash is
checked against the original extraction record and before/after inspection.

Derived results live in `<image-output>/inspections/<unique-id>/`: `result.json`,
`stderr.txt`, and `manifest.json`. Records identify the source run/artifact/hash,
original run status/integrity, settings, parser/code versions and hashes, exact worker
argv, timestamps, result hash and source integrity. The worker executes project
Python code with `shell=False`, never the recovered executable. Failed source runs
remain explicitly identified even if their saved bytes can be statically inspected.

Matching completed inspections are reused after source/output hash verification;
source/parser/settings changes prevent reuse. Changing a source artifact relative
to its extraction manifest is an integrity error, not permission to recertify it.
This uses the existing private artifact storage and lock, without altering original
run directories. New Workbench report revisions package inspections as separate
derived runs linked to their input artifacts. Historical bundles are unchanged.

## Interpret PE results carefully

The parser checks DOS/PE/COFF/optional headers, PE32 versus PE32+, machine,
characteristic bits, subsystem, image base, entry-point RVA/preferred VA, readable
section headers and declared raw ranges. `pefile` runs with `fast_load=True`;
imports/resources/signatures are not exhaustively parsed or validated.

`classification` describes header flags, not execution or maliciousness. An MZ
signature alone is insufficient. An absent DLL bit does not establish a working
EXE, and a DLL name does not establish that the DLL bit exists. Structural states
distinguish non-PE, malformed/truncated headers, inconsistent/truncated ranges, and
present declared ranges. Reconstructed memory may contain zero padding, changed
bytes or unrelated/stale content; even present ranges do not establish recovery of
the original disk file. Parser warnings are preserved as heuristics. Strings are
untrusted data and do not prove an import, API call, network connection or behavior.

References: [Microsoft PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and [pefile](https://github.com/erocarrera/pefile). These explain fields/parser
behavior; case findings require actual saved output.

## Regex validation repair

The installed `windows.vadregexscan.VadRegExScan` contract defines `--pattern` as
regex text converted to UTF-8 bytes. The old generic string filter rejected the
legitimate printable pattern `[\x20-\x7e][\x20-\x7e][\x20-\x7e][\x20-\x7e]+`
at `_argument_value -> validate_text -> METACHARACTERS`, before analysis.

Catalog discovery now annotates only that known, non-path string option with
`value_kind: bytes_regex`. Its validator compiles byte-regex syntax without scanning
evidence, limits size to 4,096 UTF-8 bytes and rejects literal control characters.
Regex punctuation remains one argv value under `shell=False`. Global-option,
duplicate-option, file-path and unrelated-string restrictions remain intact;
expensive regex evaluation remains under the existing plugin subprocess timeout.
This change does not silently run that scan; prefer static artifact inspection
when the bytes are already available.
