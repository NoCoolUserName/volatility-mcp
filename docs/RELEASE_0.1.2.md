# volatility-mcp 0.1.2

Adds the pinned CryptoMem 0.3.0 Linux x86-64 adapter to existing discovery and
execution. Windows command/output schema, ten MCP tools, manual selection,
forced offline analysis, evidence handling and timeout/cancellation remain intact.
Linux symbols must match the captured kernel; other Linux architectures remain
unsupported until tested. Synthetic validation is documented in VALIDATION.md;
real-memory Linux validation remains outstanding.

The full release wheel contains the same four verified official starter symbol
packs, plus a pinned catalog/installer for 10,255 community Linux x86-64 tables
(20,974,550,776 compressed bytes). Explicit `symbols-install --linux-all` or
`--linux-banner` provisions the shared symbol store with SHA-256, size, ISF and
banner verification, resumable installation, and offline indexing. Analysis
never downloads these tables. The 19.53 GiB community data is not embedded in
the wheel. No universal kernel coverage or real-memory validation is claimed.

Workbench must adopt this release's source commit and full-wheel digest in its
backend and distribution pins, then pass its package/native validation and rebuild.
No UI redesign or Linux desktop package is included.
