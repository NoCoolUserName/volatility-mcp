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
| `symbol_pack_config`, `install_symbol_packs` | Operator-driven official symbol provisioning; see [SYMBOLS.md](SYMBOLS.md) |

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
Core 0.1.1 retains API revision 1 and adds release-bundled symbol data. Execution
changes retain the normal conservative cache invalidation rules.

## Plugin catalog

`VolatilityBackend.list_plugins(query='', refresh=False)` and the MCP tool of the
same name return the configured analyzer's discovered inventory. `refresh=True`
repeats import/discovery only; it never reads or hashes memory images, runs an
analysis plugin, or starts a model. Successful discovery includes `discovered_at`.
The process-local cache is retained if refreshing fails, but the refresh request
returns an error; callers must label any retained display as stale.

Each plugin adds `target_os` (`windows`, `linux`, `mac`, `other`) and `source`:
`{kind, label, url, basis}`. Kinds are `native`, `third_party`, `local`, `unknown`.
Official attribution requires matching SHA-256 bytes in the installed volatility3
distribution RECORD, not merely a module prefix or installation directory. Missing
records (including some editable installs), unrecorded files, and modified files
remain unknown. This is not independent supply-chain verification. Registered addon
identities provide project attribution (currently pypykatz); their local bytes are
not claimed to match upstream. The bundled xpnet addon is identified separately.
Unknown sources have no invented author or repository URL. Extend the registry in
`catalog.py` when adding a verified project attribution. No network lookup occurs.

Legacy `origin` and count fields retain their original location semantics:
`installed_volatility` can include third-party addons. Descriptions and metadata are
untrusted text. Discovery/import success does not establish runtime image support.

Core 0.1.2 also exports `linux_symbol_catalog(banner=None)` and the operator-only
`install_linux_symbols(config, *, banner=None, source_dir=None, workers=4)`.
These use the configured shared symbol store and existing offline index; see
[Linux symbol provisioning](SYMBOLS.md). They never run as analysis side effects.
