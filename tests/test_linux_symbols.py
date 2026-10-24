"""Synthetic operator provisioning; no capture files or network access."""
import base64
from dataclasses import replace
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from volatility_mcp import cli, linux_symbols as linux
from volatility_mcp.config import Config, ConfigurationError, load_config


class LinuxSymbolsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.config = Config(self.root/'evidence', self.root/'outputs', self.root/'python',
                             self.root/'vol', cache_path=self.root/'cache')
        self.source = self.root/'source'
        self.source.mkdir()
        self.banner = 'Linux version 6.1.0-test (synthetic) #1 SMP test'
        self.isf = {'metadata': {'linux': {}}, 'base_types': {'pointer': {'size': 8, 'endian': 'little'}},
                    'user_types': {'task_struct': {}}, 'symbols': {'linux_banner': {
                        'constant_data': base64.b64encode((self.banner+'\n\x00').encode()).decode()}}}
        self.entry = {'path': 'Test/amd64/test.json.xz', 'banner': self.banner,
                      'url': linux.SOURCE+'/releases/download/test/test.json.xz'}
        self.write_isf()
        self.data = {'source': linux.SOURCE, 'revision': 'synthetic', 'architecture': 'x86_64', 'entries': [self.entry]}
        self.addCleanup(patch.stopall)
        patch.object(linux, 'catalog', return_value=self.data).start()
        self.index = patch.object(linux.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"unique_identifiers":{"linux":1}}', '')).start()
        self.network = patch.object(linux, '_download', side_effect=AssertionError('Unexpected network')).start()

    def write_isf(self):
        payload = lzma.compress(json.dumps(self.isf).encode())
        self.entry.update(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
        path = self.source/self.entry['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def install(self, **kwargs):
        return linux.install(self.config, source_dir=self.source, **kwargs)

    def target(self):
        return linux.configured(self.config).symbols/'linux/community'/self.entry['path']

    def test_exact_banner_install_resume_and_offline_index(self):
        first = self.install(banner=self.banner+'\n\x00')
        self.assertEqual(first['status'], 'ready')
        before = self.target().stat().st_mtime_ns
        second = self.install()
        self.assertEqual(second['tables'][0]['status'], 'verified')
        self.assertEqual(self.target().stat().st_mtime_ns, before)
        self.assertIn('--index-all', self.index.call_args.args[0])
        self.assertIn('--linux-catalog', self.index.call_args.args[0])
        self.assertEqual(self.index.call_args.kwargs['timeout'], 21600)
        self.assertFalse(self.config.evidence_root.exists())
        self.assertFalse(self.config.output_root.exists())
        self.network.assert_not_called()

    def test_no_nearest_kernel_or_empty_match(self):
        for banner in ('', '6.1.0-test', self.banner.replace('#1', '#2')):
            with self.subTest(banner=banner), self.assertRaisesRegex(ConfigurationError, 'No exact'):
                self.install(banner=banner)
        self.index.assert_not_called()

    def test_bad_contents_and_decompression_limit(self):
        for kind in ('width', 'banner', 'types', 'limit'):
            with self.subTest(kind=kind):
                original = json.loads(json.dumps(self.isf))
                if kind == 'width': self.isf['base_types']['pointer']['size'] = 4
                if kind == 'banner': self.isf['symbols']['linux_banner']['constant_data'] = base64.b64encode(b'wrong').decode()
                if kind == 'types': self.isf['user_types'] = {}
                self.write_isf()
                with patch.object(linux, 'MAX_EXPANDED_BYTES', 4 if kind == 'limit' else 100000), self.assertRaisesRegex(ConfigurationError, 'Invalid Linux ISF'):
                    self.install()
                self.assertFalse(self.target().exists())
                self.isf = original
        self.index.assert_not_called()

    def test_corrupt_existing_and_source_never_overwritten(self):
        self.install()
        self.target().write_bytes(b'x'*self.entry['bytes'])
        with self.assertRaisesRegex(ConfigurationError, 'SHA-256'):
            self.install()
        self.assertEqual(self.target().read_bytes(), b'x'*self.entry['bytes'])
        self.target().unlink()
        (self.source/self.entry['path']).write_bytes(b'bad')
        with self.assertRaisesRegex(ConfigurationError, 'size mismatch'):
            self.install()

    def test_symlink_overlap_lock_and_workers(self):
        target = self.target()
        target.parent.mkdir(parents=True)
        target.symlink_to(self.source/self.entry['path'])
        with self.assertRaisesRegex(ConfigurationError, 'symlink'): self.install()
        target.unlink()
        for protected in (self.config.evidence_root, self.config.output_root):
            with self.assertRaisesRegex(ConfigurationError, 'separate'):
                linux.install(replace(self.config, symbols=protected))
        lock = linux.configured(self.config).symbols/'.symbol-packs.lock'
        lock.write_text('other installer')
        with self.assertRaisesRegex(ConfigurationError, 'locked'): self.install()
        for workers in (0, 9):
            with self.assertRaisesRegex(ConfigurationError, 'workers'): self.install(workers=workers)

    def test_failure_and_interruption_no_ready_receipt_and_retry(self):
        self.index.return_value = subprocess.CompletedProcess([], 1, '', 'synthetic index failure')
        with self.assertRaisesRegex(ConfigurationError, 'index failure'): self.install()
        root = linux.configured(self.config).symbols
        self.assertTrue(self.target().exists())
        self.assertFalse((root/'linux-community-symbols.receipt.json').exists())
        self.index.side_effect = subprocess.TimeoutExpired('synthetic', 1)
        with self.assertRaises(subprocess.TimeoutExpired): self.install()
        self.assertFalse((root/'.symbol-packs.lock').exists())
        self.target().unlink()
        def interrupt(entry, target, stop):
            target.write_bytes(b'partial')
            raise KeyboardInterrupt
        self.network.side_effect = interrupt
        with self.assertRaises(KeyboardInterrupt): linux.install(self.config, workers=1)
        self.assertFalse(self.target().exists())
        self.assertEqual(list(root.rglob('.linux-download-*')), [])
        self.assertFalse((root/'.symbol-packs.lock').exists())

    def test_cli_persists_configuration_and_selection(self):
        path = self.root/'config.json'
        path.write_text(json.dumps(self.config.to_dict()))
        with patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(cli.main(['symbols-install', '--config', str(path), '--linux-all', '--symbol-source', str(self.source)]), 0)
            self.assertEqual(cli.main(['symbols-catalog', '--linux-banner', self.banner]), 0)
        self.assertEqual(load_config(path).symbols, linux.configured(self.config).symbols)
        with patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            cli.parser().parse_args(['symbols-install', '--linux-all', '--symbol-packs', 'all'])


class CatalogTests(unittest.TestCase):
    def test_packaged_catalog_all_entries_pinned(self):
        result = linux.describe()
        self.assertEqual(result['tables'], 10255)
        self.assertEqual(result['download_bytes'], 20974550776)
        self.assertEqual(result['entries'], [])

    def test_catalog_checksum_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'catalog.gz'
            path.write_bytes(b'bad')
            with patch.object(linux, 'CATALOG', path), self.assertRaisesRegex(ConfigurationError, 'checksum'):
                linux.catalog()
            data = {'entries': [{'path': '../amd64/bad.json.xz'}]}
            payload = gzip.compress(json.dumps(data).encode())
            path.write_bytes(payload)
            with patch.object(linux, 'CATALOG', path), patch.object(linux, 'CATALOG_SHA256', hashlib.sha256(payload).hexdigest()), self.assertRaisesRegex(ConfigurationError, 'Invalid'):
                linux.catalog()

    def test_download_hosts_size_and_cancellation(self):
        class Response(io.BytesIO):
            def geturl(self): return 'https://release-assets.githubusercontent.com/test'
        entry = {'url': linux.SOURCE+'/releases/download/test/test.json.xz', 'bytes': 2}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'download'
            for stopped in (False, True):
                stop = threading.Event()
                if stopped: stop.set()
                with patch('urllib.request.OpenerDirector.open', return_value=Response(b'oversized')), self.assertRaises(ConfigurationError):
                    linux._download(entry, target, stop)
            with self.assertRaises(ConfigurationError):
                linux._download({'url': 'http://example.com'}, target, threading.Event())
