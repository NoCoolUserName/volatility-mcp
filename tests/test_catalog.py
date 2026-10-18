"""Source attribution must not turn installation location into upstream authorship."""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from volatility_mcp.catalog import plugin_source
import test_backend as support


class SourceTests(unittest.TestCase):
    def test_record_membership_and_bytes_are_required_for_native(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'pslist.py'
            path.write_bytes(b'SYNTHETIC plugin source')
            record = SimpleNamespace(mode='sha256', value=base64.urlsafe_b64encode(
                hashlib.sha256(path.read_bytes()).digest()).decode().rstrip('='))
            records = {path.resolve(): record}
            source = lambda name: plugin_source(name, path, records, root / 'local')
            self.assertEqual(source('windows.pslist.PsList')['kind'], 'native')
            self.assertEqual(plugin_source('windows.pslist.PsList', path, {}, root / 'local')['kind'], 'unknown')
            path.write_bytes(b'local modification')
            self.assertEqual(source('windows.pslist.PsList')['kind'], 'unknown')

    def test_registered_addons_and_unknown_names(self):
        root = Path('/synthetic/plugins')
        pypykatz = plugin_source('vol_pypykatz.pypykatz', root / 'vol_pypykatz.py', {}, root / 'local')
        self.assertEqual(pypykatz['kind'], 'third_party')
        self.assertEqual(pypykatz['url'], 'https://github.com/skelsec/pypykatz-volatility3')
        self.assertIn('not verified', pypykatz['basis'])
        xp = plugin_source('xpnet.XpNetScan', root / 'local/xpnet.py', {}, root / 'local')
        self.assertEqual(xp['kind'], 'local')
        for name in ['xpnet.XpNetScan', 'windows.thirdparty.Plugin', 'invented.Author']:
            self.assertEqual(plugin_source(name, root / 'other.py', {}, root / 'local')['kind'], 'unknown')


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_refresh_discovers_without_analysis_or_evidence_hashing(self):
        backend = self.fixture.backend
        with patch.object(backend, 'run_plugin', side_effect=AssertionError('analysis forbidden')), \
             patch('volatility_mcp.backend.file_fingerprint', side_effect=AssertionError('image hashing forbidden')):
            first = backend.list_plugins()
            backend._catalog['plugins']['synthetic.New'] = {'description': 'cached fixture', 'options': []}
            self.assertEqual(backend.list_plugins()['count'], first['count'] + 1)
            refreshed = backend.list_plugins(refresh=True)
            self.assertEqual(refreshed['count'], first['count'])
            self.assertTrue(refreshed['discovered_at'])
            self.assertEqual(refreshed['plugins'][0]['source']['kind'], 'unknown')
            self.assertFalse((self.fixture.root / 'analysis-count.jsonl').exists())

    def test_failed_refresh_preserves_previous_catalog(self):
        backend = self.fixture.backend
        previous = backend.list_plugins()
        with patch('volatility_mcp.backend.subprocess.run', return_value=SimpleNamespace(returncode=1, stderr='synthetic failure')):
            with self.assertRaisesRegex(ValueError, 'synthetic failure'):
                backend.list_plugins(refresh=True)
        self.assertEqual(backend.list_plugins(), previous)
