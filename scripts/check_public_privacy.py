#!/usr/bin/env python3
"""Check tracked content and bounded new Git blobs/metadata before publication.

CI needs no private data. Optional local aliases never enter diagnostics.
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys

# Match literal and JSON-escaped separators, including terminal home directories.
END_PATH = rb"(?=[/\\]|$|[\s\"'<>])"
HOME_PATHS = (
    re.compile(rb"/Users[/\\]+[A-Za-z0-9._-]+" + END_PATH),
    re.compile(rb"/home[/\\]+[A-Za-z0-9._-]+" + END_PATH),
    re.compile(rb"/Volumes/[A-Za-z0-9._-]+" + END_PATH),
    re.compile(rb"[A-Za-z]:[/\\]+Users[/\\]+(?!Public(?:[/\\]|$)|Default(?:[/\\]|$))[A-Za-z0-9._-]+" + END_PATH, re.I),
    re.compile(rb"/(?:private/)?var/folders/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+" + END_PATH),
)
TRAILER = re.compile(r"^Co-authored-by:\s*(.*?)\s*<([^<>]+)>\s*$", re.I | re.M)
MAX_COMMITS = 128
MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_SCAN_ITEMS = 4096


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def owner_email(email, login, user_id):
    local, sep, domain = email.casefold().partition("@")
    if not sep or domain != "users.noreply.github.com":
        return False
    return local in (login.casefold(), f"{user_id}+{login}".casefold())


def load_aliases(args):
    if not args.aliases_file:
        return []
    content = pathlib.Path(args.aliases_file).read_text(encoding="utf-8")
    aliases = [line.strip().casefold() for line in content.splitlines() if line.strip()]
    if not aliases or any(len(alias) < 4 or "\x00" in alias for alias in aliases):
        raise ValueError("invalid optional local aliases")
    return aliases


def allowed_identity(name, email, login, user_id, role):
    if name == login and owner_email(email, login, user_id):
        return True
    if name == "dependabot[bot]" and email.casefold() in (
        "49699333+dependabot[bot]@users.noreply.github.com",
        "dependabot[bot]@users.noreply.github.com",
    ):
        return True
    return role == "committer" and name == "GitHub" and email == "noreply@github.com"


def contains_alias(value, aliases):
    folded = value.casefold()
    return any(alias in folded for alias in aliases)


def private_path(data):
    return any(pattern.search(data) for pattern in HOME_PATHS)


def scan_data(data, aliases, label):
    return [f"{label}, line {number}" for number, line in enumerate(data.splitlines(), 1)
            if private_path(line) or contains_alias(line.decode("utf-8", "replace"), aliases)]


class ScanBudget:
    def __init__(self):
        self.items = 0
        self.entries = 0
        self.bytes = 0

    def entry(self):
        self.entries += 1
        if self.entries > MAX_SCAN_ITEMS:
            raise ValueError("privacy scan entry limit exceeded")

    def admit(self, size):
        self.items += 1
        self.bytes += size
        if size > MAX_BLOB_BYTES or self.bytes > MAX_SCAN_BYTES or self.items > MAX_SCAN_ITEMS:
            raise ValueError("privacy scan resource limit exceeded")


def scan_files(aliases, budget=None):
    findings = []
    budget = budget or ScanBudget()
    for index, raw in enumerate(git("ls-files", "-z").split(b"\0"), 1):
        if not raw:
            continue
        budget.entry()
        label = f"tracked file #{index}"
        if private_path(raw) or contains_alias(os.fsdecode(raw), aliases):
            findings.append(f"{label}: path contains private data")
        path = pathlib.Path(os.fsdecode(raw))
        if path.is_symlink():
            data = os.fsencode(os.readlink(path))
        elif path.is_file():
            with path.open("rb") as stream:
                data = stream.read(MAX_BLOB_BYTES + 1)
        else:
            raise ValueError("tracked entry is unavailable or unsupported")
        budget.admit(len(data))
        findings.extend(scan_data(data, aliases, label))
    return findings


def scan_commit_content(commits, aliases, budget):
    """Read bounded new Git blobs as data, including changes later removed."""
    findings, seen = [], set()
    for sha in commits:
        fields = git("diff-tree", "--root", "-m", "--no-commit-id", "--raw", "-r",
                     "--no-renames", "--no-abbrev", "-z", sha).split(b"\0")
        if fields[-1] != b"" or len(fields[:-1]) % 2:
            raise ValueError("cannot parse changed Git blobs")
        for index in range(0, len(fields) - 1, 2):
            budget.entry()
            header, path = fields[index:index + 2]
            parts = header.split()
            if len(parts) != 5 or not parts[0].startswith(b":"):
                raise ValueError("cannot parse changed Git blob metadata")
            label = f"{sha[:12]}: changed file #{index // 2 + 1}"
            if private_path(path) or contains_alias(os.fsdecode(path), aliases):
                findings.append(f"{label}: path contains private data")
            mode, oid = parts[1], parts[3]
            if mode == b"000000" or oid in seen:
                continue
            if mode not in (b"100644", b"100755", b"120000") or not re.fullmatch(rb"[0-9a-f]{40}", oid):
                raise ValueError("unsupported changed Git entry")
            seen.add(oid)
            object_id = oid.decode("ascii")
            size = int(git("cat-file", "-s", object_id))
            budget.admit(size)
            data = git("cat-file", "blob", object_id)
            if len(data) != size:
                raise ValueError("changed Git blob size mismatch")
            findings.extend(scan_data(data, aliases, label))
    return findings


def commit_range(base, head, mode):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        raise ValueError("head must be a full commit SHA")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", base) or int(base, 16) == 0:
        raise ValueError("base must be a nonzero full commit SHA")
    git("cat-file", "-e", f"{base}^{{commit}}")
    git("cat-file", "-e", f"{head}^{{commit}}")
    if mode == "merge-base":
        base = git("merge-base", base, head).decode().strip()
    else:
        git("merge-base", "--is-ancestor", base, head)
    commits = git("rev-list", "--reverse", f"{base}..{head}").decode().splitlines()
    if len(commits) > MAX_COMMITS:
        raise ValueError("commit range exceeds the 128-commit limit")
    return commits


def metadata(sha):
    # NUL framing keeps fields separate even when a message contains newlines.
    fields = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha).split(b"\0", 4)
    if len(fields) != 5:
        raise ValueError("cannot parse commit metadata")
    return [field.decode("utf-8", "replace") for field in fields]


def scan_metadata(commits, login, user_id, aliases, preserved=(), paths_only=False):
    findings = []
    if any(not re.fullmatch(r"[0-9a-f]{40}", sha) or sha not in commits for sha in preserved):
        raise ValueError("third-party approvals must name exact commits in the range")
    for sha in commits:
        author, author_email, committer, committer_email, message = metadata(sha)
        short = sha[:12]
        for role, name, email in (
            ("author", author, author_email),
            ("committer", committer, committer_email),
        ):
            if any(private_path(part.encode("utf-8")) for part in (name, email)):
                findings.append(f"{short}: {role} contains a machine-specific path")
            if contains_alias(name, aliases) or contains_alias(email, aliases):
                findings.append(f"{short}: {role} contains a private owner alias")
            if not paths_only and sha not in preserved and not allowed_identity(name, email, login, user_id, role):
                findings.append(f"{short}: unapproved {role} identity")
        if private_path(message.encode("utf-8")):
            findings.append(f"{short}: message contains a machine-specific path")
        if contains_alias(message, aliases):
            findings.append(f"{short}: message contains a private owner alias")
        for line in message.splitlines():
            if not paths_only and re.match(r"\s*co-authored-by\s*:", line, re.I):
                match = TRAILER.fullmatch(line.strip())
                if not match:
                    findings.append(f"{short}: malformed co-author trailer")
                elif sha not in preserved and not allowed_identity(
                    *match.groups(), login, user_id, "co-author"
                ):
                    findings.append(f"{short}: unapproved co-author identity")
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner")
    parser.add_argument("--owner-id", type=int)
    parser.add_argument("--paths-only", action="store_true", help="check paths without imposing an identity allowlist")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--base-mode", choices=("direct", "merge-base"), default="direct")
    parser.add_argument("--aliases-file", help="optional private local file; never required in CI")
    parser.add_argument("--preserve-third-party", action="append", default=[], metavar="SHA",
                        help="retain attribution of an independently reviewed exact commit")
    args = parser.parse_args()
    if not args.paths_only and (args.owner is None or args.owner_id is None):
        parser.error("--owner and --owner-id are required unless --paths-only is selected")
    try:
        aliases = load_aliases(args)
        head = git("rev-parse", "--verify", args.head).decode().strip()
        commits = commit_range(args.base, head, args.base_mode)
        budget = ScanBudget()
        findings = (scan_files(aliases, budget) + scan_commit_content(commits, aliases, budget) +
                    scan_metadata(commits, args.owner, args.owner_id, aliases,
                                  args.preserve_third_party, args.paths_only))
    except (OSError, subprocess.CalledProcessError, ValueError):
        print("Privacy check could not complete; verify bounded Git refs and optional local inputs (values withheld).")
        return 2
    if findings:
        print("Privacy check failed (values withheld):")
        print("\n".join(findings))
        return 1
    print(f"Privacy check passed: tracked files and content/metadata of {len(commits)} new commits.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
