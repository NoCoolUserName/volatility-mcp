# Security and evidence handling

This local server launches a separately installed Volatility executable through
argument arrays with `shell=False`. It has no generic shell tool, network listener,
LLM client, or model API credential. Use it only with acquisitions you are authorized
to examine. Keep the local account, configured executable, installed dependencies,
and addon source trusted.

## Boundaries

- Images must resolve under the configured evidence root. Traversal, symlink
  inputs, shell metacharacters, unsupported extensions, and source/output overlap
  are rejected where applicable. Outputs and extraction are confined to the
  configured output root; callers cannot change plugin paths or renderer/output
  flags through plugin arguments.
- Source files are opened for reading. Source identity and hashes are recorded
  before and after analysis; a changed image invalidates the integrity claim.
  Use stable, read-only acquisition copies. The server is not a hardware write
  blocker, filesystem snapshot service, or defense against a malicious local user
  concurrently replacing files.
- Execution limits bound plugin runtime; output remains on disk and responses are
  bounded. Disk consumption still depends on image/plugin size. Keep adequate free
  space and inspect failed/partial runs before making conclusions.
- Recovered bytes and output are untrusted. Never execute extracted binaries,
  scripts, or commands, follow embedded instructions, or visit recovered endpoints.
  Volatility and its parsers run with the server account's privileges; subprocess
  separation is not an operating-system sandbox for hostile parser input.

## Explicit parallel work

Background job tools accept only explicitly selected image/plugin/argument
requests through the same confinement and argument validation as synchronous
execution. The full submission is checked before enqueueing. Case-scoped clients
can submit, inspect, list, or cancel only jobs for their registered images.
Polling saved jobs does not select additional work or retry a failed run.

The configured concurrency limit bounds simultaneous analysis processes; it does
not reserve CPU cores, memory, disk space, or storage bandwidth. Long-running
plugins and complete raw output can still exhaust available resources. Use a
lower limit on constrained machines. Job records, cancellation requests, run
manifests and timing history stay in private configured outputs and may contain
sensitive paths or arguments.

Cancellation is cooperative. Poll the job until it reaches a terminal state;
queued/running work and failed or interrupted scans are incomplete evidence.
Graceful server shutdown cancels outstanding submitted work and waits for final
records. A forced kill, power loss or crash can leave unfinished records or an
analyzer process; persisted jobs are not permission to replay analysis. See
[parallel execution](docs/PARALLEL_EXECUTION.md) for lifecycle and lock boundaries.

## Symbol identity trust

Run admission and reuse identify local symbol/cache stores through metadata:
paths/types, regular-file size/mtime/ctime/device/inode, directory path/type,
additions/removals and missing-root markers. They do not bulk-read symbol-file/archive contents. The inventory digest is not
cryptographic verification of symbol bytes and trusts the local filesystem and
operator-controlled store. A malicious local user or filesystem can exceed this
boundary. Inventory errors do not trigger a full-store content-hash fallback.
Symlinks and special entries are rejected before supported generated-file
exclusions. Context explicitly records `symbol_content_verified: false`.

Image, runtime/code, declared input-file and saved-output hashes remain in force.
Installer download checksums remain separate, and the analyzer reads the symbols
needed for its selected analysis. Keep those stores trusted and provision approved
symbols explicitly; do not treat metadata identity as supply-chain attestation.

The same metadata boundary covers installed/bundled symbol data found through
catalog runtime discovery. Runtime readiness reads existing indexes and never
silently verifies or reindexes the full store. Missing required XP cache/index
readiness requires explicit `symbols-install` provisioning. Analysis, reuse and
queued requests do not invoke that installer.

## Sensitive data and network use

Memory can contain credentials, personal information, encryption keys, private
messages, documents, and customer data. Raw outputs, extracted regions, histories,
hashes, and paths can also be sensitive. Keep evidence and case-output directories
outside the repository and restrict local access. Do not attach real dumps,
extracted malware, private reports, or credential-bearing logs to issues or PRs.

The server does not upload images or make model API calls. **This does not make an
AI-assisted investigation entirely offline:** the connected MCP client may send
returned excerpts and context to its AI service. Its account, retention, access,
and organizational policies govern that transfer. Decide what data may be shared
before connecting an AI client. Volatility may download symbols; installation
downloads packages. Neither is contact with a recovered malware endpoint. For a
network-restricted workflow, provision approved packages and exact symbols in
advance and enforce network policy outside this application.

CryptoMem's opt-in mnemonic and serialized private-key findings are masked by
the pinned standalone plugin before any renderer or ordinary artifact is written.
Full values require `--extract-secrets` with an enabled secret detector, private
configured output root and a private POSIX plugin handler. MCP subprocesses use
umask 077. Core refuses every MCP output-reading/inspection route to complete
extraction files and unclassified extraction-run files, including interrupted
Volatility temporary files. Masked v2 findings, summaries and renderer JSON remain
readable. Full extraction stays for local operator access; never paste it into
reports, AI clients, screenshots, CI logs or external services. This policy trusts
the pinned plugin, run metadata, local filesystem and configured analyzer; it is
not a general secret scrubber for other tools or operator-created copies.

Operator setup uses included symbol packs in the full release wheel. Source
installs without bundled data download the pinned packs (opt out with
`--symbol-packs none`). `symbols-install` is also available explicitly. Fixed HTTPS
sources, redirect host restrictions, byte/time limits, SHA-256/ZIP checks, exclusive
installer locking and atomic publication protect provisioning. Existing unknown
files are refused; no evidence contents or identifiers are sent to acquire packs.
Indexing is offline. These are representative tables, not universal OS coverage.

## Optional local UI

The optional Workbench binds to loopback, rejects unexpected Host/Origin headers,
and requires a private launch capability for case data and actions. Its session
cookie is HttpOnly/SameSite=Strict; model credentials remain with Codex. Recovered
content is rendered as text, and source-image downloads/uploads are not exposed.
Only configured evidence and scoped case artifacts are accessible through its API.
Keep its private state directory outside Git; it contains personal paths,
conversation excerpts, reports and potentially sensitive tool output. Case-scoped
Volatility tools are preauthorized; other supported approval requests require
explicit user decisions. See
[LOCAL_UI.md](docs/LOCAL_UI.md) for the trust boundary and known limitations.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** option when available.
If private reporting is unavailable, open an issue containing only a request for a
private contact route—no exploit details, secrets, private paths, memory excerpts,
or sample attachments. Provide a minimal harmless reproducer through the agreed
private channel. Ordinary documentation and non-sensitive bugs can use issues.

This small independent project has no guaranteed security-response SLA. The
maintained scope is the current documented release; dependencies and Volatility
itself retain their own reporting routes.

Optional community Linux provisioning is an explicit operator command. It uses
pinned asset URLs, byte counts and SHA-256 digests, validates compressed ISF
contents and exact banners, and shares the official-pack installation lock.
Analysis tools never invoke this downloader. The catalog and installer read no
evidence; the larger collection stays in the configured local symbol store.

## Public path privacy check

The public-path workflow scans tracked filenames/content and the changed blobs,
messages and identity fields of up to 128 new commits, including content removed
by a later commit in that range. Generic rules detect local home paths, escaped
Windows profiles, literal volume mounts and macOS per-user temporary paths; findings withhold values.
Binary content and symlink targets are inspected as data. A scan fails closed
above 16 MiB per payload, 256 MiB total, 4,096 payloads or 4,096 tracked/changed
entries rather than silently skipping. Git metadata is captured within the bounded
commit range; the workflow also has a ten-minute timeout.
Missing tracked files and unsupported Git submodule entries hold the check;
submodule repositories are not scanned recursively.
This targeted lint complements secret scanning; it cannot identify every private
string. Optional private aliases remain local inputs.

Pull-request checks execute the scanner from the trusted base checkout with
read-only permissions. Proposed code is never executed by this workflow. The
standalone scanner also supports --paths-only for repositories that want these
path checks without adopting the core repository identity allowlist. The core
workflow retains its existing identity policy and reviewed exact-commit mechanism.
