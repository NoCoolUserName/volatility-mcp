# GitHub access checks

GitHub connectivity is separate from Volatility/MCP health. A restricted agent
session can produce different results from ordinary Terminal, and different
commands can have different access. Do not infer that credentials are invalid
from a DNS error or `gh auth status` alone.

Before repository publication, run these read-only checks separately:

```sh
curl --silent --show-error --connect-timeout 5 --max-time 10 --output /dev/null --write-out 'API HTTP %{http_code}\n' https://api.github.com
gh api user --jq .login
git ls-remote https://github.com/modelcontextprotocol/python-sdk.git HEAD
```

The first tests public API HTTPS, the second tests an actual authenticated API
request, and the third tests Git HTTPS reads using a public upstream repository.
None proves permission to create a repository or push. Check the intended
destination separately before publication; retain the project's privacy audit.
Never use an evidence file as a connectivity probe.

For an existing checkout, also inspect `git remote -v` and use
`git ls-remote --exit-code origin refs/heads/main` to check the actual configured
transport and branch (substitute the intended branch if different). Compare the
returned SHA with `git rev-parse HEAD`; local `origin/main` can be stale. Inspect
the repository and branch through `gh api repos/OWNER/REPO` and
`gh api repos/OWNER/REPO/branches/main` when verifying visibility and permissions.

- If `gh api user` returns a login, authentication works for that request. An
  inconsistent `gh auth status` result needs investigation, not automatic logout
  or token replacement.
- DNS failures and connection timeouts occur before an HTTP authentication
  decision. They do not establish an invalid token. Compare the same command in
  ordinary Terminal to distinguish session restrictions from host-wide trouble.
- If a reachable API returns HTTP 401 for the authenticated request, use
  `gh auth login --hostname github.com --web` in Terminal, then repeat the request.
  HTTP 403 can instead indicate authorization, organization policy, or rate limits;
  inspect the error before replacing credentials.
- If commands work in Terminal but fail in the agent, configure the client's
  supported network permissions for `api.github.com` and `github.com` and start a
  fresh session. Managed policy may require an administrator. Do not disable the
  sandbox, change system DNS, or weaken TLS verification to conceal the failure.

Codex network permission and proxy enforcement are separate settings; consult
the [official permissions documentation](https://learn.chatgpt.com/docs/permissions)
for the installed client and managed policy. This project does not change global
client settings. A successful web-search tool is not proof of shell connectivity.

## Earlier conflicting results, 2026-10-03

In the follow-up managed session, API HTTPS returned HTTP 200 twice,
`gh api user --jq .login` returned the authenticated account twice, and
`git ls-remote` returned the upstream HEAD. However, `gh auth status` reported an
invalid token, direct Python DNS lookups failed, and direct website HTTPS failed
DNS resolution. This establishes working API authentication and Git read access
through those commands, not universal network access. The exact cause of the
command-dependent discrepancy was not established; no credential or OS network
change was justified. Earlier blanket claims that GitHub was unreachable are
superseded for these tested operations. Repository creation and push were not
tested by these read-only checks.

The commands above were recorded with the same declared `workspace-write`
sandbox, `network_access: false`, and approval policy `never`. No explicit
escalation was requested. Those records do not establish whether an underlying
execution layer handled individual commands differently. Direct DNS failure alone
does not justify a blanket network-block diagnosis.

## Latest verified access, 2026-10-03

The later session recorded `workspace-write`, `network_access: true`, and
approval policy `on-request`. Seatbelt remained active and the network-disabled
environment marker was absent. Full-access mode was not active, and no enforced
policy override was reported. Existing command approvals can affect execution;
the records do not prove the OS sandbox applied identically to every subprocess.

Actual authenticated `gh api user --jq .login` succeeded. Repository API metadata
confirmed this project's existing public repository and account push/admin
permissions. `git ls-remote --exit-code origin refs/heads/main` succeeded using
the configured SSH remote; an API branch lookup agreed. Local HEAD and remote
`main` matched at `0b904c7f420670eca6e5834feb186dd3a69c23d5`, before this documentation
follow-up. These checks required no new approval request. A repository permission
response establishes granted rights, not proof that a particular push succeeded.

GitHub access is working for these verified operations. The precise cause of the
earlier discrepancy remains unknown; no credential reset, system DNS change, or
full-access sandbox mode was needed for this verification.
