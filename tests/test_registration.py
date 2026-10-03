"""Registration rollback tests use only temporary files and a simulated Codex CLI."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from volatility_mcp import cli
from volatility_mcp.config import Config, ConfigurationError


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="volatility-registration-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.client_root = self.root / "client"
        self.client_root.mkdir()
        self.path = self.client_root / "config.toml"
        self.original = (b'model = "keep-model"\n[mcp_servers.other]\ncommand = "keep-other"\n'
                         b'[mcp_servers.volatility]\ncommand = "old-command"\n')
        self.path.write_bytes(self.original)
        self.args = SimpleNamespace(config=str(self.root / "server.json"), backup_dir=str(self.root / "backups"))
        self.added = False
        self.failure = None
        self.command = []
        self.actual_absolute = cli.absolute_path
        self.real_client_home = os.environ.get("CODEX_HOME") or Path.home() / ".codex"

    def isolated_absolute(self, value):
        # Redirect this helper's filesystem lookup only. Never change HOME or
        # CODEX_HOME, and never invoke a real client or touch its configuration.
        return self.client_root if str(value) == str(self.real_client_home) else self.actual_absolute(value)

    def fake_run(self, argv, timeout=60):
        stdout, stderr, returncode = "{}", "", 0
        if argv[1:3] == ["mcp", "add"]:
            self.added = True
            self.command = argv[5:]
            model = "unexpected-model" if self.failure == "unrelated" else "keep-model"
            self.path.write_text(
                f'model = "{model}"\n[mcp_servers.other]\ncommand = "keep-other"\n'
                f'[mcp_servers.volatility]\ncommand = {json.dumps(self.command[0])}\n'
                f'args = {json.dumps(self.command[1:])}\n')
            if self.failure == "partial_add":
                returncode, stderr = 1, "simulated CLI error after partial change"
        elif argv[1:3] == ["mcp", "get"] and self.added:
            stdout = json.dumps({"enabled": True, "transport": {"type": "stdio",
                "command": "unexpected" if self.failure == "wrong_command" else self.command[0],
                "args": self.command[1:]}})
            if self.failure == "verification":
                returncode, stderr = 1, "simulated verification error"
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    def mocks(self):
        stack = ExitStack()
        stack.enter_context(patch.object(cli, "load_config", return_value=SimpleNamespace(catalog_timeout=60, command_timeout=300)))
        stack.enter_context(patch.object(cli.shutil, "which", return_value="fake-codex"))
        stack.enter_context(patch.object(cli, "absolute_path", side_effect=self.isolated_absolute))
        stack.enter_context(patch.object(cli, "run", side_effect=self.fake_run))
        return stack

    def test_unrelated_cli_change_restores_exact_original_and_keeps_private_backup(self):
        self.failure = "unrelated"
        with self.mocks(), self.assertRaisesRegex(ConfigurationError, "Original Codex configuration restored"):
            cli.register_codex(self.args)
        self.assertEqual(self.path.read_bytes(), self.original)
        backup = next((self.root / "backups").glob("*/config.toml"))
        self.assertEqual(backup.read_bytes(), self.original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_concurrent_change_guard_does_not_overwrite_newer_contents(self):
        self.failure = "unrelated"
        newer = b'model = "written-by-another-editor"\n'
        original_write = cli._guarded_client_write

        def concurrent_write(path, replacement, expected):
            path.write_bytes(newer)
            return original_write(path, replacement, expected)

        with self.mocks(), patch.object(cli, "_guarded_client_write", side_effect=concurrent_write), \
                self.assertRaisesRegex(ConfigurationError, "restoration was withheld or failed.*concurrently"):
            cli.register_codex(self.args)
        self.assertEqual(self.path.read_bytes(), newer)

    def test_failed_post_add_checks_restore_original(self):
        for failure in ("partial_add", "verification", "wrong_command"):
            with self.subTest(failure=failure):
                self.failure, self.added = failure, False
                self.path.write_bytes(self.original)
                with self.mocks(), self.assertRaisesRegex(ConfigurationError, "Original Codex configuration restored"):
                    cli.register_codex(self.args)
                self.assertEqual(self.path.read_bytes(), self.original)

    def test_failed_initial_registration_restores_absent_file(self):
        self.path.unlink()
        self.failure = "partial_add"
        with self.mocks(), self.assertRaisesRegex(ConfigurationError, "Original Codex configuration restored"):
            cli.register_codex(self.args)
        self.assertFalse(self.path.exists())

    def test_success_verifies_command_and_preserves_other_configuration(self):
        with self.mocks():
            result = cli.register_codex(self.args)
        self.assertEqual(result["status"], "registered")
        parsed = cli.tomllib.loads(self.path.read_text())
        self.assertEqual(parsed["model"], "keep-model")
        self.assertEqual(parsed["mcp_servers"]["other"]["command"], "keep-other")
        self.assertEqual(parsed["mcp_servers"]["volatility"]["startup_timeout_sec"], 90)
        self.assertEqual(parsed["mcp_servers"]["volatility"]["tool_timeout_sec"], 1800)
        self.assertEqual(result["command"], self.command)

    def test_new_setup_directories_private_existing_permissions_preserved(self):
        values = {"evidence_root": self.root / "evidence", "output_root": self.root / "output",
                  "cache_path": self.root / "cache", "vol_python": self.root / "env/bin/python",
                  "vol_executable": self.root / "env/bin/vol"}
        config = self.root / "server.json"
        cli.write_config(config, Config(**values))
        values["evidence_root"].mkdir(mode=0o755)
        values["evidence_root"].chmod(0o755)
        args = cli.parser().parse_args(["setup", "--config", str(config)])
        with patch.object(cli, "validate_vol", return_value={}):
            cli.setup(args)
        self.assertEqual(values["output_root"].stat().st_mode & 0o777, 0o700)
        self.assertEqual(values["cache_path"].stat().st_mode & 0o777, 0o700)
        self.assertEqual(values["evidence_root"].stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
