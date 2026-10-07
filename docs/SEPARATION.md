# Repository separation — 2026-10-07

Source checkpoint: `3ecc22e1275467879005556f5340fbc863bc3281` in
[volatility-mcp](https://github.com/NoCoolUserName/volatility-mcp).
The snapshot extraction preserves MIT attribution; the original repository retains
all development history. Published core history is advanced by ordinary commits.
No history filtering or force push is used.

| Owner | Components |
| --- | --- |
| Core | backend, catalog, execution/reuse, inspection, saved-evidence queries/references, coverage/evaluation, configuration/relocation, report validation and packaged report contract |
| Core | `scoped.py` (case confinement), `files.py` (saved-file confinement), `api.py` (supported integration surface) |
| Workbench | app/controller, HTTP, Codex adapter, storage/report packaging, coins, static assets, presentation template, app fixtures/tests and documentation |

No data migration is needed. Keep the same `--config`, `--state-dir`, and
`VOLATILITY_MCP_RELOCATION` when present. Keep an existing administrative old-root
symlink while historical manifests depend on it. Case IDs, thread IDs, report paths,
run namespaces and manifests retain their existing meanings. Workbench's optional
legacy `--project` argument only excludes case storage under that source directory;
the report contract now comes from the installed core package.

The old `python -m volatility_mcp.ui.http` and `.ui.coins` commands are thin bridges
when Workbench is installed, and otherwise give an explicit migration message.
The old `.ui.scoped_mcp` module delegates to core `.scoped` for saved integrations.
Core does not install Workbench or expose its console script. Internal `.ui.app`
and `.ui.storage` imports have moved to `volatility_workbench`.

Recovery: preserve configuration backups and the source checkpoint before changing
launchers. To roll back software, install the prior tested Git commit in a separate
environment and point the launcher at it while idle. Keep the same data roots;
never reset, move, or rewrite evidence or sealed bundles as part of rollback.
A private Git bundle and launcher/configuration/state backups were recorded locally;
these are deliberately excluded from both public repositories.

Validation results are recorded in each product's validation documentation.
