# Third-party notices

The existing MIT license applies to original project material, subject to the
unresolved integration scope described in [LICENSING.md](LICENSING.md). It does not
relicense separately installed dependencies, upstream Volatility material,
symbols, acquired evidence, reference publications, or other third-party works.

- **Official MCP Python SDK:** installed as a dependency, not vendored here.
  Preserve its [upstream license](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE)
  and those of its transitive dependencies in redistributed environments.
- **Volatility 3:** installed in its own environment, not bundled in this repository.
  Its [Volatility Software License](https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt)
  and notices remain applicable to upstream code and symbol material.
- **pefile:** pinned dependency for static inspection of saved PE artifacts,
  not vendored or used to execute recovered code. Preserve its
  [upstream MIT license](https://github.com/erocarrera/pefile/blob/master/LICENSE).
- **Historical XP structure references:** the local `xpnet.XpNetScan` addon retains
  its source links to official Volatility 2
  [TCP/IP layouts](https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/overlays/windows/tcpip_vtypes.py),
  [connection pool checks](https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/connscan.py),
  and [socket pool checks](https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/sockscan.py).
  The upstream project has its own
  [license](https://github.com/volatilityfoundation/volatility/blob/master/LICENSE.txt).
  This addon is an independent local compatibility implementation and is not an
  upstream plugin or an endorsement by the Volatility Foundation.

No memory images, malware samples, symbol archives, commercial reference books,
or real investigation reports are distributed here. The example is original,
synthetic text. Product and organization names identify compatibility and context;
they do not imply sponsorship or endorsement.
## Optional downloaded analyzer addons

The opt-in installer downloads pinned third-party sources into the operator's
Volatility environment, not this repository or its wheel. See
[COMMUNITY_PLUGINS.md](docs/COMMUNITY_PLUGINS.md) for sources, original notices,
mixed MIT/BSD/GPL-derived code, and unresolved redistribution licensing for two
upstream repositories. Original notices and available license files are retained
locally with the installation receipt. This project's MIT license does not grant
rights to redistribute those upstream sources.

Optional installation is not evidence of upstream reuse or redistribution permission. See LICENSING.md before shipping integrated software or plugin bundles.

The runtime batch also downloads pinned sources from lorelyai/volatility3-bitlocker
(GPL-3.0, including its earlier Marcin Ulikowski attribution),
HalaAli198/Go-Memory-Forensics (Apache-2.0), and
HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis (AGPL-3.0).
Generated adapters retain source identity and license context; installer receipts
retain the original files and verified LICENSE texts. See
[runtime addon scope](docs/RUNTIME_ADDONS.md). No project-wide license statement
relicenses those upstream works.

## Dependency evidence — 2026-10-18

[Dependency inventory](licenses/DEPENDENCIES.json) records exact versions, source commits, archive URLs/hashes, dependency context and review items. [Collected license texts](licenses/DEPENDENCY_LICENSES.txt) preserve upstream notices, including recovered omissions. This snapshot includes build/test and optional packages; it is not a claim that all listed components ship together or that a finished release has been cleared. Unlocked requirements are labeled audit-time resolutions, not new project pins. Refresh the inventory and verify actual release contents when dependencies change.
