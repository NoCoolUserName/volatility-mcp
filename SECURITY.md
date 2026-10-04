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
