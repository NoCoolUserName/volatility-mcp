# Linux kernel keyring addon

The optional community profile includes experimental linux.keyring.Keyring
from [mischw/volatility3_plugins](https://github.com/mischw/volatility3_plugins),
pinned to commit 2e733c847e7cd2a2fab34bf81205c2e004dd755b.
It adds kernel key inventory and selected payload recovery alongside the existing
process-oriented SSH and Windows encryption-key plugins.

## Assessment

The upstream [README](https://github.com/mischw/volatility3_plugins/blob/2e733c847e7cd2a2fab34bf81205c2e004dd755b/README.md)
reports Debian/Ubuntu VM testing and includes an Ubuntu example. The reviewed
repository has a small implementation and no automated test suite. That is useful
initial evidence, but not a compatibility matrix or independent validation.

The [source](https://github.com/mischw/volatility3_plugins/blob/2e733c847e7cd2a2fab34bf81205c2e004dd755b/linux/keyring.py)
walks the kernel's serial-number tree. It decodes user/logon and asymmetric key
payloads; keyrings are containers, and other key types remain unsupported.
Consequently, the README's broad all-keys language is not a coverage guarantee.
Recovering a candidate key does not demonstrate that it decrypts a LUKS volume.
There is no disk decryption, process-keyring association or freed-key carving.

The original source fails import under the pinned Python 3.12 analyzer because
List is not imported. It also eagerly enumerates an unbounded recursive tree,
trusts payload lengths, and formats last-used time in the host timezone.
Volatility 2.28.2's inherited tree walker skips unreadable branches. Those behaviors
are unsuitable for unattended forensic use without adaptation.

## Installation and integration

Use the existing explicit installer with a configuration pointing to an isolated
Volatility 2.28.2 environment:

    volatility-mcp plugins-install --config /absolute/path/to/config.json

This installs the entire configured community profile, including its existing
dependencies; it is not a keyring-only installer. No ordinary MCP call downloads
or installs code. Original source, adapted source hashes, upstream commit and the
verified MIT license are retained by the installer. No upstream keyring source is
vendored into the core wheel.

Core catalog discovery exposes the plugin, attribution and limitations through
list_plugins; run_plugin and queued jobs use the existing execution and saved
evidence paths. Core forces offline execution for this plugin. Workbench consumes
that catalog without a second forensic implementation. Its existing manual-only
filter and extraction consent middleware apply. It is excluded from automatic
report suggestions. Core's manual-only field is selection guidance, not a separate
authorization gate for direct MCP clients.

The MCP runtime must contain this updated profile, and the configured analyzer
must contain the adapted plugin. An already packaged Workbench has its own pinned
core: installing the analyzer alone does not update that core. Adopt a reviewed
core revision and rebuild/update the app through its normal release process.
Do not modify a signed app bundle in place or float its dependency on main.

## Adapted scope and failure behavior

- Linux Intel64 only, with exact matching local kernel symbols and the expected
  key, red-black tree and payload structure members. Intel32 and ARM64 are not
  enabled by this adaptation.
- At most 4,096 tree nodes, 65,536 bytes per payload and 4 MiB aggregate payload
  bytes. The normal core execution timeout still applies.
- Strict tree traversal detects repeated nodes and rejects unreadable branches.
  Metadata strings have bounded, non-padded reads through a required terminator.
- Only positively instantiated, non-dead/non-revoked/non-invalidated keys have
  their payload union decoded. Other states, unsupported types and null payloads
  produce explicit status text. Empty payload bytes are rendered unavailable by
  the original output contract.
- Output includes the kernel layer, key address, payload pointer, serial,
  ownership/permission fields and UTC last-used time. Expiry remains the raw
  kernel value, except the permanent sentinel.
- A malformed structure, missing symbol, unreadable data or exhausted budget
  fails the scan; saved partial output is not a complete inventory or a negative
  finding. Unsupported payload statuses likewise do not establish absence.
- Payloads can contain live secrets. Keep results in the configured case output
  and apply the same access controls as the memory image.

## License

Upstream is [MIT, copyright (c) 2026 mischw](https://github.com/mischw/volatility3_plugins/blob/2e733c847e7cd2a2fab34bf81205c2e004dd755b/LICENSE).
Modification does not remove its notice requirements. The installer preserves
the full upstream LICENSE with the original source; generated code identifies
the adaptation. Project licensing does not relicense upstream material.
Any redistributed analyzer must retain the upstream notice and comply separately
with Volatility's license and the project's distribution requirements.

## Validation

tests/addon_keyring_smoke.py runs against the installed adapted plugin with
network and subprocess creation denied. It exercises real TreeGrid JSON rendering
over synthetic objects: user/logon/asymmetric payloads, provenance, UTC,
unsupported and unsafe states, empty trees, missing symbols, unreadable branches,
cycles, long trees, short reads and payload/string limits. Community-addon CI runs
it after the real pinned installer.

Core profile/installer tests cover pins, hashes, rollback, manual/offline policy
and source attribution. These are synthetic integration contracts, not proof of
key recovery from a real Linux acquisition. Real-image accuracy and a kernel-build
matrix remain outstanding.
