"""Synthetic pack provisioning; no network, real memory, or user configuration."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from volatility_mcp import cli, symbol_packs as packs
from volatility_mcp.config import Config, ConfigurationError, load_config


class SymbolPackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = Config(self.root/'evidence', self.root/'outputs', self.root/'python',
                             self.root/'vol', cache_path=self.root/'cache')
        self.source = self.root/'downloaded'
        self.source.mkdir()
        self.manifest = {}
        for name in ('windows.zip', 'symbols_win-10_19041-2025_03.zip', 'mac.zip', 'linux.zip'):
            path = self.source/name
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('test.json', json.dumps({'synthetic': name}))
            data = path.read_bytes()
            self.manifest[name] = (len(data), hashlib.sha256(data).hexdigest())
        self.addCleanup(patch.stopall)
        patch.object(packs, 'PACKS', self.manifest).start()
        self.index = patch.object(packs.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"unique_identifiers":{"windows":2}}', '')).start()
        self.download = packs._download
        self.network = patch.object(packs, '_download', side_effect=AssertionError('Unexpected network')).start()

    def install(self, **kwargs):
        return packs.install(self.config, source_dir=self.source, **kwargs)

    def test_offline_install_and_idempotence(self):
        result = self.install()
        self.assertEqual(result['status'], 'ready')
        target = packs.configured(self.config).symbols
        before = {p.name: p.stat().st_mtime_ns for p in target.glob('*.zip')}
        second = self.install()
        self.assertEqual(before, {p.name: p.stat().st_mtime_ns for p in target.glob('*.zip')})
        self.assertTrue(all(p['status'] == 'verified' for p in second['packs']))
        self.assertEqual(result['index']['unique_identifiers'], {'windows': 2})
        self.assertEqual(json.loads((target/'official-symbol-packs.receipt.txt').read_text())['status'], 'ready')
        self.assertFalse(self.config.evidence_root.exists())
        self.assertFalse(self.config.output_root.exists())
        self.network.assert_not_called()
        self.assertEqual(self.index.call_args.kwargs['timeout'], 1800)
        self.assertFalse(self.index.call_args.kwargs['shell'])
        self.assertEqual(self.index.call_args.args[0][-1], '--index-all')

    def test_windows_selection(self):
        result = self.install(packs='windows')
        self.assertEqual(len(result['packs']), 2)
        with self.assertRaises(ConfigurationError):
            self.install(packs='../windows')

    def test_corrupt_existing_file_preserved(self):
        target = packs.configured(self.config).symbols
        target.mkdir(parents=True)
        (target/'windows.zip').write_bytes(b'operator data')
        with self.assertRaisesRegex(ConfigurationError, 'size mismatch'):
            self.install()
        self.assertEqual((target/'windows.zip').read_bytes(), b'operator data')
        self.index.assert_not_called()

    def test_wrong_hash_and_invalid_archive_rejected(self):
        target = self.source/'windows.zip'
        target.write_bytes(b'x' * self.manifest['windows.zip'][0])
        with self.assertRaisesRegex(ConfigurationError, 'SHA-256 mismatch'):
            self.install()
        self.manifest['windows.zip'] = (target.stat().st_size, hashlib.sha256(target.read_bytes()).hexdigest())
        with self.assertRaisesRegex(ConfigurationError, 'Invalid symbol archive'):
            self.install()
        self.assertFalse((packs.configured(self.config).symbols/'windows.zip').exists())

    def test_symlink_pack_and_source_rejected(self):
        target = packs.configured(self.config).symbols
        target.mkdir(parents=True)
        (target/'windows.zip').symlink_to(self.source/'windows.zip')
        with self.assertRaisesRegex(ConfigurationError, 'symlink'):
            self.install()
        (target/'windows.zip').unlink()
        alias = self.root/'alias'
        alias.symlink_to(self.source)
        with self.assertRaisesRegex(ConfigurationError, 'symlink'):
            packs.install(self.config, source_dir=alias)

    def test_evidence_and_output_overlap_rejected(self):
        for protected in (self.config.evidence_root, self.config.output_root):
            for directory in (protected, protected/'symbols', self.root):
                config = packs.replace(self.config, symbols=directory)
                with self.subTest(directory=directory), self.assertRaisesRegex(ConfigurationError, 'separate'):
                    packs.install(config, source_dir=self.source)

    def test_index_failure_retry_preserves_verified_packs(self):
        self.index.return_value = subprocess.CompletedProcess([], 1, '', 'dependency missing')
        with self.assertRaisesRegex(ConfigurationError, 'dependency missing'):
            self.install()
        target = packs.configured(self.config).symbols
        self.assertEqual(len(list(target.glob('*.zip'))), 4)
        self.assertFalse((target/'.symbol-packs.lock').exists())
        self.index.return_value = subprocess.CompletedProcess([], 0, '{}', '')
        self.assertTrue(all(x['status']=='verified' for x in self.install()['packs']))

    def test_interruption_removes_partial_download_and_lock(self):
        def interrupted(name, target, size):
            target.write_bytes(b'partial')
            raise KeyboardInterrupt
        self.network.side_effect = interrupted
        with self.assertRaises(KeyboardInterrupt):
            packs.install(self.config)
        self.assertEqual(list(packs.configured(self.config).symbols.iterdir()), [])

    def test_lock_prevents_second_installer(self):
        target = packs.configured(self.config).symbols
        target.mkdir(parents=True)
        (target/'.symbol-packs.lock').write_text('other installer')
        with self.assertRaisesRegex(ConfigurationError, 'already locked'):
            self.install()
        self.index.assert_not_called()

    def test_timeout_releases_lock(self):
        self.index.side_effect = subprocess.TimeoutExpired('index', 1800)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.install()
        self.assertFalse((packs.configured(self.config).symbols/'.symbol-packs.lock').exists())

    def test_download_size_and_https_redirect_bounds(self):
        for url in ('http://github.com/data', 'https://attacker.example/data', 'https://github.com@attacker.example/data'):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                packs._Redirect().redirect_request(None, None, 302, '', {}, url)
        # Exercise the real streaming downloader, not the network stub.
        response = io.BytesIO(b'too many bytes')
        response.geturl = lambda: 'https://release-assets.githubusercontent.com/asset'
        with patch.object(packs.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(ConfigurationError, 'size/time'):
                self.download('windows.zip', self.root/'partial', 2)

    def test_default_setup_provisions_and_saves_symbols(self):
        path = self.root/'config.json'
        cli.write_config(path, self.config)
        args = cli.parser().parse_args(['setup', '--config', str(path), '--symbol-source', str(self.source)])
        self.assertEqual(args.symbol_packs, 'all')
        with patch.object(cli, 'validate_vol', return_value={}):
            result = cli.setup(args)
        self.assertEqual(result['symbol_packs']['status'], 'ready')
        self.assertEqual(load_config(path).symbols, self.config.cache_path/'tables')

    def test_failed_symbols_command_leaves_config_unchanged(self):
        path = self.root/'config.json'
        cli.write_config(path, self.config)
        before = path.read_bytes()
        self.index.return_value = subprocess.CompletedProcess([], 1, '', 'failed')
        args = cli.parser().parse_args(['symbols-install', '--config', str(path), '--symbol-source', str(self.source)])
        with self.assertRaises(ConfigurationError):
            cli.symbols_install(args)
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
