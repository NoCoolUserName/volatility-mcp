# volatility-mcp 0.1.3

Pins CryptoMem 0.4.0 and adds experimental legacy Intel64 `mac.cryptomem.CryptoMem`
to the established add-on installation, discovery and manual/offline execution
policy. Ten MCP tools, Windows/Linux behavior, XP-independent discovery and the
client-neutral architecture are preserved. No Workbench implementation or runtime
dependency is added. Reviewed 0.3.0 hashes permit upgrading the installed adapter.

Use the existing Mac symbol pack only for an exactly matching captured Darwin
kernel. Nested submaps fail explicitly as incomplete; this can affect ordinary
shared-region processes. Apple silicon, Intel32 Mac and modern macOS are
unsupported. No real-memory macOS or Linux validation is claimed.

Workbench must update its backend source/wheel pins and repackage to embed this
inventory. Source users can install this core version and run `plugins-install`
with clients idle. The existing full Linux symbol download/index is independent.
