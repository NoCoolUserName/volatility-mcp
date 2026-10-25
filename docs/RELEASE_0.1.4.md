# volatility-mcp 0.1.4

Pins CryptoMem 0.5.0 with independently opt-in English BIP-39 checksum validation,
Bitcoin WIF and BIP-32 xprv/tprv validation, and ambiguous transaction-ID candidates.
Existing Windows/Linux/legacy Intel64 Mac commands, address defaults and renderer
columns remain. New richer artifacts are versioned separately. No MCP tool,
framework, Workbench code or runtime dependency is added. Manual selection,
forced offline execution and XP-independent discovery remain.

Secret values stay masked in ordinary output. Explicit extraction requires an
enabled secret detector and private output root. All MCP saved-output routes block
full extraction and unclassified/temporary extraction output; masked findings are
readable. Process output files use umask 077. No recovered secrets, endpoints,
balances, wallet software or transactions are contacted or used during validation.

Synthetic/public-vector validation only; captured-kernel Linux/macOS testing,
modern Mac/Apple-silicon support and nested-submap handling remain outstanding.
Linux symbols must match the captured kernel exactly. A running symbol index is
independent of this release; only its final exit status and complete receipt can
establish readiness.

Workbench 0.1.2 pins core 0.1.3 and embeds the earlier inventory. Adopting this
release requires a tested backend source/wheel pin update, analyzer add-on update,
native rebuild and repackage; it does not inherit these changes automatically.
No UI redesign or Linux desktop packaging is part of this increment. Existing
Developer ID signing/notarization remains outstanding.
