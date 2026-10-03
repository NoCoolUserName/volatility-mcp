# Third-party notices

The MIT license in this repository covers original project material. It does not
relicense separately installed dependencies, upstream Volatility material,
symbols, acquired evidence, reference publications, or other third-party works.

- **Official MCP Python SDK:** installed as a dependency, not vendored here.
  Preserve its [upstream license](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE)
  and those of its transitive dependencies in redistributed environments.
- **Volatility 3:** installed in its own environment, not bundled in this repository.
  Its [Volatility Software License](https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt)
  and notices remain applicable to upstream code and symbol material.
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
