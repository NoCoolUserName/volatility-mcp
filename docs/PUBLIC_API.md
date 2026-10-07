# Shared integration API (revision 1)

`volatility_mcp.api` is the supported local interface for companion applications.
It imports no Workbench or model provider. `API_VERSION == 1` defines compatibility;
applications must reject unsupported revisions before opening case state.

| Interface | Responsibility |
| --- | --- |
| `Config`, `load_config` | Existing trusted operator configuration |
| `VolatilityBackend` | Existing ten public tool methods, confinement, reuse, execution |
| `CaseBackend(config, images)` | Restrict those tools to explicitly registered images |
| `create_server`, `decode_result` | Official MCP server integration and result decoding |
| `file_fingerprint`, `SUPPORTED_EXTENSIONS` | Integrity metadata and supported acquisitions |
| `logical_path`, `resolved_path`, `check_components`, `environment` | Administrative relocation with stable historical identities |
| `private_dir`, `safe_file` | Private outputs and confined saved-file paths |
| `check_bundle`, `check_citation`, `source_identity`, `report_spec()` | Headless report/citation validation and the installed authoritative contract |
| `snapshot`, `set_plan`, `job_view`, `request_failures`, `report_summary` | Reusable coverage projection and deterministic summaries |
| `utc_now`, `timestamped_id` | Existing metadata timestamps and unique identifiers |

Backend public method signatures and MCP contracts remain documented in README,
SAVED_EVIDENCE, RESULT_REUSE, ARTIFACT_INSPECTION, and COVERAGE_EVALUATION. Private
underscore methods are not integration APIs. No analysis occurs merely by importing
this module or reading the contract. `python -m volatility_mcp.scoped scope.json`
provides the same case-confined stdio tools with `{config: ..., images: [...]}`.
Operator-supplied scope files are private, trusted configuration, never tool input.

Core retains report validation and useful headless tools. Report packaging,
model orchestration, artwork, and presentation belong to
[Workbench](https://github.com/NoCoolUserName/volatility-workbench).

A distribution release is identified by its Git release tag and immutable commit.
The extraction retains core version 0.1.0 and all execution identity bytes; future
execution changes retain the normal conservative cache invalidation rules.
