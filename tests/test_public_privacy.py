"""Synthetic Git history tests; fixtures never contain a real identity."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scripts/check_public_privacy.py"
HANDLE = "ExampleHandle"
OWNER_ID = "123456"
ALIAS_NAME = "Avery" + " Example"
ALIAS_EMAIL = "avery" + "@example.invalid"
GOOD_EMAIL = f"{OWNER_ID}+{HANDLE}@users.noreply.github.com"


class PrivacyCheck(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", HANDLE)
        self.git("config", "user.email", GOOD_EMAIL)
        (self.repo / "sample.txt").write_text("safe\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.aliases = self.repo / "private-aliases"
        self.aliases.write_text(ALIAS_NAME + "\n" + ALIAS_EMAIL + "\n")

    def git(self, *args, env=None):
        return subprocess.run(["git", *args], cwd=self.repo, text=True,
                              capture_output=True, check=True, env=env)

    def commit(self, subject, body="", author_name=HANDLE, author_email=GOOD_EMAIL,
               committer_name=HANDLE, committer_email=GOOD_EMAIL, merge=False):
        env = dict(os.environ, GIT_AUTHOR_NAME=author_name, GIT_AUTHOR_EMAIL=author_email,
                   GIT_COMMITTER_NAME=committer_name, GIT_COMMITTER_EMAIL=committer_email)
        if merge:
            self.git("branch", "side")
            self.git("commit", "-qm", "main side", "--allow-empty")
            self.git("switch", "-q", "side")
            self.git("commit", "-qm", "other side", "--allow-empty")
            self.git("switch", "-q", "main")
            self.git("merge", "--no-ff", "side", "-m", subject, "-m", body, env=env)
        else:
            self.git("commit", "--allow-empty", "-qm", subject, "-m", body, env=env)

    def check(self, base=None, aliases=False, mode="direct", preserved=(), paths_only=False):
        return subprocess.run(
            [sys.executable, str(SCANNER), "--base", base or self.base, "--base-mode", mode]
            + (["--paths-only"] if paths_only else ["--owner", HANDLE, "--owner-id", OWNER_ID])
            + (["--aliases-file", str(self.aliases)] if aliases else [])
            + [arg for sha in preserved for arg in ("--preserve-third-party", sha)],
            cwd=self.repo, text=True, capture_output=True,
        )

    def test_allowed_owner_forms_github_and_dependabot(self):
        self.commit("ordinary", "Co-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
                    committer_name="GitHub", committer_email="noreply@github.com")
        self.commit("legacy noreply", author_email=f"{HANDLE}@users.noreply.github.com")
        self.assertEqual(self.check().returncode, 0)

    def test_unapproved_author_committer_and_coauthor_without_secrets(self):
        for kwargs in (
            {"author_name": ALIAS_NAME, "author_email": ALIAS_EMAIL},
            {"committer_name": ALIAS_NAME, "committer_email": ALIAS_EMAIL},
            {"body": f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>"},
        ):
            with self.subTest(kwargs=kwargs):
                self.commit("synthetic", **kwargs)
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(ALIAS_NAME, result.stdout + result.stderr)
                self.assertNotIn(ALIAS_EMAIL, result.stdout + result.stderr)
                self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def test_noncanonical_owner_and_malformed_trailer(self):
        self.commit("bad", "Co-authored-by: ExampleHandle <other@example.invalid>",
                    author_email="other@example.invalid")
        self.assertEqual(self.check().returncode, 1)
        self.commit("bad trailer", "Co-authored-by: ExampleHandle with no email")
        self.assertEqual(self.check(base=self.git("rev-parse", "HEAD^").stdout.strip()).returncode, 1)

    def test_merge_and_squash_messages(self):
        self.commit("Merge branch 'topic'", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>", merge=True)
        self.assertEqual(self.check().returncode, 1)
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.commit("Squash merged change", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>")
        self.assertEqual(self.check().returncode, 1)

    def test_range_only_new_commits_and_bounded_selection(self):
        self.commit("old", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>")
        old = self.git("rev-parse", "HEAD").stdout.strip()
        self.commit("new safe")
        self.assertEqual(self.check(base=old).returncode, 0)
        self.assertEqual(self.check().returncode, 1)
        self.assertEqual(self.check(base="0" * 40).returncode, 2)
        for _ in range(128):
            self.commit("more")
        self.assertEqual(self.check(base=old).returncode, 2)

    def test_pull_request_divergence_uses_merge_base(self):
        self.git("branch", "topic")
        self.commit("base branch moved")
        moved = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("switch", "-q", "topic")
        self.commit("topic change")
        self.assertEqual(self.check(base=moved).returncode, 2)
        self.assertEqual(self.check(base=moved, mode="merge-base").returncode, 0)

    def test_commit_message_home_path_redacted(self):
        self.commit("message", "See /" + "home/FabricatedPerson/private")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("FabricatedPerson", result.stdout + result.stderr)

    def test_proposed_checkout_cannot_replace_trusted_scanner(self):
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/check_public_privacy.py").write_text("raise SystemExit(0)\n")
        self.git("add", "scripts/check_public_privacy.py")
        self.commit("proposed scanner replacement", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>")
        self.assertEqual(self.check().returncode, 1)

    def test_reviewed_third_party_commit_preserves_original_metadata(self):
        self.commit("upstream", "Co-authored-by: Dana Contributor <dana@example.invalid>",
                    author_name="Dana Contributor", author_email="dana@example.invalid")
        sha = self.git("rev-parse", "HEAD").stdout.strip()
        before = self.git("cat-file", "commit", sha).stdout
        self.assertEqual(self.check().returncode, 1)
        self.assertEqual(self.check(preserved=[sha]).returncode, 0)
        self.assertEqual(self.git("cat-file", "commit", sha).stdout, before)
        self.assertEqual(self.check(preserved=["0" * 40]).returncode, 2)

    def test_optional_local_alias_file(self):
        self.commit("mention", ALIAS_NAME)
        self.assertEqual(self.check().returncode, 0)
        self.assertEqual(self.check(aliases=True).returncode, 1)

    def test_tracked_paths_redacted(self):
        (self.repo / "sample.txt").write_text("/" + "Users/FabricatedPerson/private\n")
        self.git("add", "sample.txt")
        self.commit("tracked")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("FabricatedPerson", result.stdout + result.stderr)
        self.assertNotIn("sample.txt", result.stdout + result.stderr)


    def test_terminal_home_json_windows_and_mac_temp_paths_are_redacted(self):
        slash = bytes([92])
        cases = [
            b"/" + b"Users/SyntheticProfile",
            b"/" + b"home/SyntheticProfile",
            b"/" + b"Volumes/SyntheticMount/case.raw",
            b"C:" + slash + b"Users" + slash + b"SyntheticProfile" + slash + b"file.txt",
            b"C:" + slash * 2 + b"Users" + slash * 2 + b"SyntheticProfile" + slash * 2 + b"file.txt",
            b"D:" + b"/" + b"Users/SyntheticProfile/file.txt",
            b"/private/" + b"var/folders/ab/SyntheticMachine/T/file.txt",
            b"/" + b"var/folders/cd/AnotherSynthetic/T/file.txt",
        ]
        for value in cases:
            with self.subTest(value=value):
                (self.repo / "sample.txt").write_bytes(value)
                self.git("add", "sample.txt")
                self.commit("synthetic path fixture")
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("SyntheticProfile", result.stdout + result.stderr)
                self.assertNotIn("SyntheticMachine", result.stdout + result.stderr)
                self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def test_new_blob_is_checked_even_when_a_later_commit_removes_it(self):
        (self.repo / "sample.txt").write_text("/" + "home/SyntheticProfile/private")
        self.git("add", "sample.txt")
        self.commit("temporary content")
        (self.repo / "sample.txt").write_text("safe\n")
        self.git("add", "sample.txt")
        self.commit("remove temporary content")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("changed file", result.stdout)
        self.assertNotIn("SyntheticProfile", result.stdout + result.stderr)

    def test_paths_in_binary_symlink_target_and_filename_are_checked(self):
        link = self.repo / "link"
        link.symlink_to("/" + "home/SyntheticProfile/private")
        (self.repo / "binary.dat").write_bytes(b"\0" + b"/" + b"home/SyntheticProfile/private")
        filename = "D:" + chr(92) + "Users" + chr(92) + "SyntheticProfile" + chr(92) + "file.txt"
        (self.repo / filename).write_text("safe\n")
        self.git("add", "link", "binary.dat", filename)
        self.commit("synthetic entry kinds")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("SyntheticProfile", result.stdout + result.stderr)
        self.assertNotIn("binary.dat", result.stdout + result.stderr)

    def test_paths_only_accepts_contributors_but_still_checks_metadata_and_messages(self):
        self.commit("community change", "Co-authored-by: Public Contributor <public@example.invalid>",
                    author_name="Public Contributor", author_email="public@example.invalid")
        self.assertEqual(self.check(paths_only=True).returncode, 0)
        self.assertEqual(self.check().returncode, 1)
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.commit("synthetic metadata path", author_name="/" + "home/SyntheticProfile")
        self.assertEqual(self.check(paths_only=True).returncode, 1)
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.commit("synthetic message", "/" + "home/SyntheticProfile")
        self.assertEqual(self.check(paths_only=True).returncode, 1)

    def test_blob_limit_fails_closed_without_exposing_content(self):
        (self.repo / "sample.txt").write_bytes(b"x" * (16 * 1024 * 1024 + 1))
        self.git("add", "sample.txt")
        self.commit("bounded synthetic data")
        result = self.check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not complete", result.stdout)
        self.assertNotIn("sample.txt", result.stdout + result.stderr)


    def test_removed_repeated_blobs_still_obey_changed_entry_limit(self):
        folder = self.repo / "entries"
        folder.mkdir()
        for index in range(4096):
            (folder / str(index)).write_bytes(b"")
        self.git("add", "entries")
        self.commit("many identical synthetic blobs")
        self.git("rm", "-qr", "entries")
        self.commit("remove synthetic entries")
        result = self.check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not complete", result.stdout)

    def test_missing_tracked_file_fails_closed(self):
        (self.repo / "sample.txt").unlink()
        self.assertEqual(self.check().returncode, 2)


    def test_removed_gitlink_fails_closed_without_recursive_scan(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.base},synthetic-submodule")
        self.commit("synthetic gitlink")
        self.git("update-index", "--force-remove", "synthetic-submodule")
        self.commit("remove synthetic gitlink")
        self.assertEqual(self.check().returncode, 2)


if __name__ == "__main__":
    unittest.main()
