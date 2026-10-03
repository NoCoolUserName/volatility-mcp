"""Harmless configuration/setup tests: no network, user config, or real evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from volatility_mcp.config import Config, ConfigurationError, config_path, load_config
from volatility_mcp import cli


class ConfigAndSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.values = {
            "evidence_root": self.root / "evidence", "output_root": self.root / "outputs",
            "cache_path": self.root / "cache", "vol_python": self.root / "venv/bin/python",
            "vol_executable": self.root / "venv/bin/vol",
        }

    def test_config_does_not_require_reporting_fields(self):
        config = Config(**self.values)
        self.assertEqual(config.command_timeout, 300)
        self.assertEqual(config, Config.from_dict(config.to_dict()))
        self.assertNotIn("report", json.dumps(config.to_dict()))

    def test_python_symlink_keeps_venv_path(self):
        python = self.values["vol_python"]
        python.parent.mkdir(parents=True)
        python.symlink_to(Path(os.sys.executable))
        self.assertEqual(Config(**self.values).vol_python, python)
        self.assertNotEqual(Config(**self.values).vol_python, python.resolve())

    def test_root_symlinks_are_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        for field in ("evidence_root", "output_root", "cache_path"):
            with self.subTest(field=field):
                self.values[field].symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ConfigurationError, "symlink"):
                    Config(**self.values)
                self.values[field].unlink()

    def test_output_cannot_contain_evidence(self):
        for output in (self.values["evidence_root"], self.root):
            with self.subTest(output=output), self.assertRaisesRegex(ConfigurationError, "equal or contain"):
                Config(**{**self.values, "output_root": output})

    def test_legacy_output_beneath_evidence_is_supported(self):
        config = Config(**{**self.values, "output_root": self.values["evidence_root"] / "_outputs"})
        self.assertTrue(config.output_root.is_relative_to(config.evidence_root))

    def test_invalid_timeout_and_unrecognized_fields_rejected(self):
        for value in (0, -1, True, 1.5, 86401):
            with self.subTest(timeout=value), self.assertRaises(ConfigurationError):
                Config(**self.values, command_timeout=value)
        with self.assertRaisesRegex(ConfigurationError, "Unknown configuration"):
            Config.from_dict({**self.values, "plugin_directory": "/arbitrary"})

    def test_missing_configuration_is_actionable(self):
        with self.assertRaisesRegex(ConfigurationError, "setup --help"):
            load_config(self.root / "missing.json")

    def test_environment_config_and_explicit_override(self):
        with patch.dict(os.environ, {"VOLATILITY_MCP_CONFIG": str(self.root / "environment.json")}):
            self.assertEqual(config_path(), self.root / "environment.json")
            self.assertEqual(config_path(self.root / "explicit.json"), self.root / "explicit.json")

    def test_atomic_config_is_private_and_idempotent(self):
        path = self.root / "private.json"
        config = Config(**self.values)
        self.assertTrue(cli.write_config(path, config))
        before = path.stat().st_mtime_ns
        self.assertFalse(cli.write_config(path, config))
        self.assertEqual(before, path.stat().st_mtime_ns)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_config(path), config)

    def test_config_symlink_write_rejected(self):
        original = self.root / "original.json"
        original.write_text("{}")
        link = self.root / "config.json"
        link.symlink_to(original)
        with self.assertRaises(ConfigurationError):
            cli.write_config(link, Config(**self.values))
        self.assertEqual(original.read_text(), "{}")

    def test_setup_reuses_existing_config_without_install(self):
        path = self.root / "config.json"
        cli.write_config(path, Config(**self.values))
        args = cli.parser().parse_args(["setup", "--config", str(path)])
        with patch.object(cli, "validate_vol", return_value={"architecture": "arm64"}), \
             patch.object(cli, "install_volatility") as install:
            outcome = cli.setup(args)
        install.assert_not_called()
        self.assertEqual(outcome["status"], "already_configured")
        self.assertTrue(self.values["evidence_root"].is_dir())
        self.assertTrue(self.values["output_root"].is_dir())

    def test_explicit_install_does_not_overwrite_existing_directory(self):
        target = self.root / "existing"
        target.mkdir()
        marker = target / "keep.txt"
        marker.write_text("keep")
        with self.assertRaisesRegex(ConfigurationError, "Refusing to overwrite"):
            cli.install_volatility(target)
        self.assertEqual(marker.read_text(), "keep")

    def test_subprocess_always_uses_argument_array_and_no_shell(self):
        with patch.object(subprocess, "run") as execute:
            cli.run(["executable with spaces", "argument with spaces"])
        self.assertEqual(execute.call_args.args[0], ["executable with spaces", "argument with spaces"])
        self.assertIs(execute.call_args.kwargs["shell"], False)
        self.assertEqual(execute.call_args.kwargs["timeout"], 60)

    def test_codex_timeout_update_preserves_other_tables(self):
        source = ('model = "keep-model"\n[mcp_servers.volatility]\ncommand = "python"\n'
                  'args = ["-m", "volatility_mcp"]\ntool_timeout_sec = 1800\n'
                  '[mcp_servers.other]\ncommand = "keep-command"\n')
        updated = tomllib.loads(cli._timeout_configuration(source, 90, 1800))
        self.assertEqual(updated["model"], "keep-model")
        self.assertEqual(updated["mcp_servers"]["other"]["command"], "keep-command")
        self.assertEqual(updated["mcp_servers"]["volatility"]["startup_timeout_sec"], 90)
        self.assertEqual(updated["mcp_servers"]["volatility"]["tool_timeout_sec"], 1800)


if __name__ == "__main__":
    unittest.main()
