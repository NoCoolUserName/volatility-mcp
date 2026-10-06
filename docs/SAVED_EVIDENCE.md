# Queries and checked evidence references

`query_output` and `get_evidence` are client-neutral core MCP tools. They only read
saved artifacts and manifests. They never invoke Volatility, discover plugins,
hash a memory image, reconstruct files, or generate reports. Use `case_history`
and `read_output` to find saved run IDs and exact registered run-relative paths.
Missing saved data requires a separate, explicit collection decision.

## Query contract

```json
{"image":"example.raw","run_id":"saved-run-id","artifact":"json/stdout.json","fields":["PID","ImageFileName"],"filters":[{"field":"PID","op":"eq","type":"integer","value":"0x2a"}],"sort":[{"field":"PID","type":"integer","direction":"asc"}],"offset":0,"limit":20}
```

Use the actual field names returned by your saved plugin, not these illustrative
names. Fields may also be relative JSON pointers (e.g. `/entry_point/rva` in a PE
inspection). Omit fields to discover available columns. Filters are ANDed:

- `eq`, `ne`, `lt`, `le`, `gt`, `ge` use an explicit `type`: `integer`, `number`,
  `string`, `boolean`, or `null`. Ordered comparisons require an ordered type.
- `integer` accepts integers, decimal strings, or `0x` strings deliberately.
  `number` accepts JSON numbers. Booleans are never integers. Strings are exact,
  case-sensitive Unicode values; no automatic name/path folding or string coercion.
- `contains` and `starts_with` use literal strings (maximum 1,024 characters),
  not executable patterns or regular expressions.
- `exists` uses a boolean `value` and distinguishes missing fields from null.
  Type-incompatible/missing fields do not match other filters, including `ne`.
- `group_by: ["PID"]` returns distinct value tuples and their counts, in first
  occurrence order after sorting. It does not join processes or claim identities
  across runs. Group keys preserve types; a missing field differs from null.

Every query returns `matching_count`, `returned_count`, `total_rows`, pagination,
`source`, `source_result`, `result_state`, and `rows`. Grouping also returns
`group_count`; its pagination counts groups, while matching_count counts rows.
Counts require no extra analysis. Use `limit:1` if only the count is wanted.
Stable typed sorts retain original tree order on ties, with missing/incompatible
values last. Limits: 32 selected fields, 16 filters, four sort/group fields,
200 returned rows/groups, and approximately 60 KB JSON response. Response-budget
truncation also supplies `next_offset`. A single oversized row requires narrower
field selection; it is not silently clipped.

## Original values and lazy normalization

Volatility's JSON array is traversed in preorder, preserving exact field names,
values, and `__children` parent relationships. `parent_locator` is a tree parent,
not a PID join. JSON null remains null; textual markers such as `N/A` remain text.
Missing fields are listed separately. Integers beyond JavaScript's safe range are
returned as `{"$integer":"18446744073709551600"}`; the source JSON retains its
original integer. This tag is accepted by integer filters/observable checks.

There is deliberately no second persisted evidence store or database. Normalization
is lazy and rebuilt from verified saved JSON on each call. Source files up to
64 MiB, 200,000 JSON nodes, and depth 64 are supported. Tree traversal has a
10-second budget; bounded source reading/JSON decoding/hashing happens separately.
An oversized source is rejected before hashing with a raw-reader instruction.
This favors simplicity and integrity over query speed for large files. Malformed,
duplicate-key, nonfinite-number, over-budget, or unrecognized structures return
`unsupported_format`, unknown matching count, and the existing bounded `read_output`
route. Complete parsing precedes all results: a valid prefix is not a complete table.
No source artifact or historical bundle is modified. Source hashes are verified
against the registered manifest and before/after successful reads.

`source_result` preserves exact collection status, completion, integrity, and
available failure category. Missing runs/artifacts produce explicit errors without
collection. `successful_empty` requires a complete, integrity-verified successful
source with zero rows, not merely zero filter matches. Failed, running, timed-out,
cancelled, unsupported, and output-error statuses remain visible even for valid
empty arrays. Inspection pages are labeled `saved_inspection_only`; their original
source-run status and page/truncation metadata remain visible. None establishes
absence of malicious activity. Explicit coverage is now available through `get_coverage`; see
[COVERAGE_EVALUATION.md](COVERAGE_EVALUATION.md).

## Stable references and deterministic checks

A row reference has this shape (identities/hashes below are placeholders):

```json
{"schema":"saved-evidence/1","source":{"case_id":"image-output-id","namespace":"output-root-identity","image":"example.raw","run_id":"saved-run-id","artifact":"json/stdout.json","sha256":"source-hash","parser":"json-tree/1"},"locator":{"kind":"json","pointer":"/0"}}
```

Copy the returned reference, preserving its source. To cite a field, replace the
locator pointer with the corresponding `field_locators` entry, e.g. `/0/PID` or
`/0/__children/0/PID`. JSON pointers address the **original JSON tree**, not a query
row number, memory address, or invented raw-file offset. `get_evidence` accepts:

```json
{"reference":"<the returned reference object with pointer /0/PID>","observable":{"type":"integer","value":"0x2a"}}
```

The `reference` must be an object in a real request, not the explanatory string
above. The result separates `provenance_validation`, `observable_validation`, and
`interpretation_validation`, and includes the exact resolved value. Invalid,
out-of-range, cross-case, stale, integrity-unverified and value-mismatched
references fail. Without an observable, value validation is `not_declared`.
A matching observable does not validate a narrative, attribution, maliciousness,
or inference. Free-form semantics remain `not_checked` and require analyst review.

References survive restarts and repeated normalization because pointers resolve
against the same hash-bound original bytes. Parser/locator schema changes must
retain v1 semantics or explicitly reject older versions; never redirect them.
Moving live output roots changes namespace and requires explicit rebinding, not
silent reuse. Portable report bundles preserve original source identities and
resolve against their own hashed copies, without the original host paths.

For actual artifact byte ranges use `{"kind":"bytes","offset":528,"length":11,
"encoding":"ascii"}` (also `hex` or `utf-16le`, maximum 4,096 bytes). This offset
is relative to the cited artifact, never the memory image unless that artifact
actually is the image. The exact bytes must decode as requested; partial/out-of-range
ranges fail. Compare with a string observable. JSON row/field citations do not
pretend to be byte citations.

## Existing static inspection results

`inspect_artifact` now includes `evidence_reference` to its saved result without
performing additional inspection. Query `run_id: "inspection-<inspection_id>"`,
`artifact: "result.json"`. PE results are one root row with nested field pointers;
string pages expose `/records/<index>` rows including recorded offset, encoding,
length, and continuation flags. Both derived result and original registered input
hashes are checked. Parser/settings provenance comes from the original inspection.
Use `/records/0/text` for the observed text and `/records/0/offset` for its recorded
source-file offset; a separate byte-range reference can check the extracted input
bytes directly. Bounded string fragments remain fragments, not full-string claims.

## Workbench and reports

Both tools are exposed by the actual case-scoped MCP server. Investigator guidance
requires saved-evidence-first follow-ups/report regeneration and an explicit
collection instruction before missing data becomes a new scan. This is workflow
guidance; `run_plugin` remains separately available to authorized clients.

New bundles package source provenance and deterministic checks. See
[REPORT_SPEC.md](REPORT_SPEC.md#structured-citations-specification-02).
The report viewer's **Inspect evidence citations** control lists citations in
pages of 20. Selecting one resolves its actual value and validation status;
**Open supporting artifact** uses the existing evidence viewer. Invalid citations
show an error. Legacy locators remain readable and explicitly unverified at the
value level. These are on-demand checks, not cached claims of semantic validation.

Restart idle MCP clients/Workbench after upgrading to load the new tools and
investigator instructions. Do not interrupt active investigations.
