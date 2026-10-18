"""Offline installer boundaries and rollback; no real downloads or analysis."""
from contextlib import ExitStack
from io import BytesIO
import json
import fcntl
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from volatility_mcp import addons
from volatility_mcp.config import Config


class AddonTests(unittest.TestCase):
    def test_profile_is_pinned_and_has_all_requested_commands(self):
        data = addons.profile()
        names = {name for source in data['sources'] for name in source['plugins']}
        self.assertEqual(len(names), 15)
        self.assertEqual(set(data['manual_only_plugins']), {'windows.passwordmanagers.PasswordManager', 'linux.openssh_sessionkeys.SSHKeys'})
        self.assertTrue(set(data['manual_only_plugins']) <= set(data['offline_plugins']))
        self.assertEqual(sum(f.get('kind') == 'symbol' for source in data['sources'] for f in source['files']), 2)
        self.assertIn('windows.simple_pteenum.SimplePteEnumerator', names)
        self.assertIn('windows.browserhistoryextractor.BrowserHistoryExtractor', names)
        self.assertTrue(all(source['license'] for source in data['sources']))
        self.assertTrue({'windows.cobaltstrike.CobaltStrike', 'windows.richheader.RichHeader',
                         'windows.zoneid3.ZoneID3', 'windows.pte_resolve.PteResolve'} <= names)

    def test_download_and_adaptation_must_match_both_hashes(self):
        raw = b'# synthetic plugin\n'
        item = {'path': 'sample.py', 'sha256': addons.sha(raw), 'installed_sha256': addons.sha(raw)}
        source = {'repository': 'synthetic/plugins', 'commit': 'a' * 40}
        with patch('urllib.request.urlopen', return_value=BytesIO(raw)):
            self.assertEqual(addons.prepare(source, item), (raw, raw))
        with patch('urllib.request.urlopen', return_value=BytesIO(b'changed')):
            with self.assertRaisesRegex(ValueError, 'hash/size'):
                addons.prepare(source, item)
        item['installed_sha256'] = '0' * 64
        with patch('urllib.request.urlopen', return_value=BytesIO(raw)):
            with self.assertRaisesRegex(ValueError, 'Adapted addon hash'):
                addons.prepare(source, item)

    def test_target_rejects_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'venv'; root.mkdir()
            with self.assertRaises(ValueError): addons.safe_target(root, '../outside.py')
            (root / 'linked').symlink_to(Path(tmp), target_is_directory=True)
            with self.assertRaises(ValueError): addons.safe_target(root, 'linked/out.py')

    def test_install_idempotence_native_refusal_and_catalog_failure_rollback(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp).resolve(); prefix = root / 'venv'; target_root = prefix / 'framework/plugins'
            target_root.mkdir(parents=True)
            config = Config(root / 'cases', root / 'outputs', prefix / 'bin/python', prefix / 'bin/vol')
            content = b'# synthetic addon\n'
            previous = b'# previous synthetic addon\n'
            item = {'path': 'sample.py', 'target': 'windows/sample.py',
                    'installed_sha256': addons.sha(content), 'previous_installed_sha256': addons.sha(previous)}
            data = {'profile': 'synthetic', 'volatility_version': '2.28.2', 'dependencies': [],
                    'sources': [{'repository': 'synthetic/plugins', 'files': [item], 'plugins': ['windows.sample.Example']}]}
            environment = {'prefix': str(prefix), 'plugins': str(target_root), 'packages': {}, 'native': []}
            stack.enter_context(patch.object(addons, 'profile', return_value=data))
            stack.enter_context(patch.object(addons, 'prepare', return_value=(content, content)))
            stack.enter_context(patch('volatility_mcp.cli.inspect_python', return_value={'volatility_version':'2.28.2','base_prefix':'/synthetic/system'}))
            stack.enter_context(patch('volatility_mcp.cli.run', side_effect=lambda argv: SimpleNamespace(returncode=0, stdout=json.dumps(environment) if '-c' in argv else '', stderr='')))
            backend = stack.enter_context(patch('volatility_mcp.backend.VolatilityBackend')).return_value
            backend.list_plugins.return_value = {'plugins':[{'name':'windows.sample.Example'}], 'import_failures':[], 'total':1}
            pip = stack.enter_context(patch('subprocess.run', side_effect=AssertionError('No dependency installation expected')))
            target = target_root / item['target']
            target.parent.mkdir(parents=True)
            target.write_bytes(previous)
            first = addons.install(config); second = addons.install(config)
            self.assertEqual(first['plugins'], second['plugins'])
            self.assertEqual(target.read_bytes(), content)
            self.assertFalse(pip.called)
            target.write_bytes(b'# unknown addon\n')
            with self.assertRaisesRegex(ValueError, 'Unrecognized existing addon bytes'): addons.install(config)
            target.write_bytes(content)
            with (config.output_root / '.execution.lock').open('rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(ValueError, 'Analysis is active'): addons.install(config)
            self.assertEqual(target.read_bytes(), content)
            target.unlink()
            backend.list_plugins.return_value['plugins'] = []
            with self.assertRaisesRegex(ValueError, 'discovery failed'): addons.install(config)
            self.assertFalse(target.exists())
            backend.list_plugins.side_effect = [
                {'plugins':[{'name':'existing.MustRemain'}], 'import_failures':[], 'total':1},
                {'plugins':[{'name':'windows.sample.Example'}], 'import_failures':[], 'total':1}]
            with self.assertRaisesRegex(ValueError, 'existing.MustRemain'): addons.install(config)
            self.assertFalse(target.exists())
            backend.list_plugins.side_effect = None
            environment['native'] = [str(target.resolve())]
            with self.assertRaisesRegex(ValueError, 'official Volatility'): addons.install(config)

    def test_profile_rejects_traversal_duplicate_targets_and_names(self):
        for invalid in ('../zoneid3.py', '/zoneid3.py', 'a//zoneid3.py'):
            data = addons.profile()
            data['sources'][0]['files'][0]['path'] = invalid
            with patch.object(Path, 'read_text', return_value=json.dumps(data)):
                with self.assertRaisesRegex(ValueError, 'fixed plugin or symbol'): addons.profile()
        data = addons.profile()
        data['sources'][0]['files'].append(data['sources'][0]['files'][0])
        with patch.object(Path, 'read_text', return_value=json.dumps(data)):
            with self.assertRaisesRegex(ValueError, 'fixed plugin or symbol'): addons.profile()

    def test_symbol_preparation_preserves_original_bytes(self):
        raw = b'{"symbols": {}, "user_types": {}}'
        item = {'path':'volatility3/symbols/openssh64.json', 'kind':'symbol',
                'sha256':addons.sha(raw), 'installed_sha256':addons.sha(raw)}
        with patch.object(addons, 'fetch', return_value=raw):
            self.assertEqual(addons.prepare({}, item), (raw, raw))

    def test_invalid_symbol_destination_and_manual_policy_rejected(self):
        for target in ('../openssh64.json','windows/openssh64.json','linux/wrong.json'):
            data = addons.profile()
            data['sources'][-1]['files'][-1]['target'] = target
            with patch.object(Path, 'read_text', return_value=json.dumps(data)):
                with self.assertRaises(ValueError): addons.profile()
        data = addons.profile(); data['manual_only_plugins'] = ['not.installed.Command']
        with patch.object(Path, 'read_text', return_value=json.dumps(data)):
            with self.assertRaisesRegex(ValueError, 'Manual-only'): addons.profile()
