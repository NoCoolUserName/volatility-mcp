"""Core integration contracts using a harmless CLI simulator, not real memory.

The independent CryptoMem repository tests detection and Volatility rendering.
These tests exercise existing core subprocess, artifact and isolation behavior.
"""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
import unittest

import test_backend
from volatility_mcp import addons
from volatility_mcp.backend import EvidenceError, OFFLINE_ADDONS, VolatilityBackend
from volatility_mcp.scoped import CaseBackend


PLUGIN = 'windows.cryptomem.CryptoMem'
ADDRESS = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'


class CryptoMemBackendTests(unittest.TestCase):
    PLUGIN = PLUGIN
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend, self.config = self.fixture.backend, self.fixture.config
        self.root, self.image = self.fixture.root, self.fixture.image
        simulator = Path(__file__).parent / 'fixtures' / 'fake_cryptomem.py'
        self.fixture.fake.write_text('#!' + sys.executable + '\n' + simulator.read_text())
        self.source = self.root / 'installed-cryptomem.py'
        self.source.write_text('# SYNTHETIC installed plugin bytes, never imported\n')

    def run_crypto(self, mode=None, arguments=None, **kwargs):
        if mode is not None:
            self.image.write_text(mode)
        return self.backend.run_plugin('example.raw', self.PLUGIN,
            arguments if arguments is not None else ['--pid', '42'], **kwargs)

    def count(self):
        path = self.root / 'analysis-count.jsonl'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def test_external_discovery_does_not_depend_on_xp_addon(self):
        without_xp = self.backend.list_plugins()
        with_xp = VolatilityBackend(replace(self.config, enable_xpnet=True)).list_plugins()
        names = lambda catalog: {p['name'] for p in catalog['plugins']}
        self.assertEqual(names(without_xp), {'windows.cryptomem.CryptoMem', 'linux.cryptomem.CryptoMem', 'mac.cryptomem.CryptoMem', 'windows.pslist.PsList'})
        self.assertEqual(names(with_xp) - names(without_xp), {'xpnet.XpNetScan'})
        item = self.backend.list_plugins(self.PLUGIN)['plugins'][0]
        self.assertTrue(item['manual_only'])
        self.assertEqual(item['origin'], 'installed_volatility')
        self.assertEqual(item['source']['kind'], 'third_party')
        self.assertIn(self.PLUGIN, OFFLINE_ADDONS)
        self.assertEqual(self.count(), 0)

    def test_profile_registers_pinned_independent_source_and_manual_selection(self):
        profile = addons.profile()
        sources = [source for source in profile['sources'] if self.PLUGIN in source['plugins']]
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]['repository'], 'NoCoolUserName/volatility3-cryptomem')
        self.assertRegex(sources[0]['commit'], r'^[0-9a-f]{40}$')
        self.assertNotEqual(sources[0]['commit'], '0' * 40)
        self.assertIn(self.PLUGIN, profile['manual_only_plugins'])
        self.assertIn(self.PLUGIN, profile['offline_plugins'])
        self.assertIn('windows/cryptomem.py', {item['target'] for item in sources[0]['files']})
        for item in sources[0]['files']:
            self.assertRegex(item['sha256'], r'^[0-9a-f]{64}$')
            self.assertNotEqual(item['sha256'], '0' * 64)
            self.assertEqual(item['installed_sha256'], item['sha256'])
        notices = sources[0]['notices']
        self.assertIn('LICENSE', {notice['path'] for notice in notices})
        for notice in notices:
            self.assertRegex(notice['sha256'], r'^[0-9a-f]{64}$')
            self.assertNotEqual(notice['sha256'], '0' * 64)

    def test_parameters_are_typed_required_scalar_and_confined(self):
        validate = lambda args: self.backend.validate_arguments(self.PLUGIN, args)
        valid = ['--pid', '0x2a', '--currency', 'btc', '--max-scan-bytes', '65536',
                 '--max-results', '10']
        self.assertEqual(validate(valid), valid)
        self.assertEqual(validate(['--pid', '42', '--currency', 'xmr']),
                         ['--pid', '42', '--currency', 'xmr'])
        for args in ([], ['--pid', 'x'], ['--pid', '42', '43'],
                     ['--pid', '42', '--pid', '43'], ['--pid', '42', '--currency', 'doge'],
                     ['--pid', '42', '--max-results', '1.5'],
                     ['--pid', '42', '--max-scan-bytes', 'unlimited']):
            with self.subTest(args=args), self.assertRaises(EvidenceError):
                validate(args)
        for flag in ('--api-key', '--api', '--input', '--dump', '--config', '--plugin-dirs',
                     '--output-dir', '--symbol-dirs', '--remote-isf-url', '--offline', '-o'):
            with self.subTest(flag=flag), self.assertRaises(EvidenceError):
                validate(['--pid', '42', flag, '/tmp/untrusted'])
        self.assertEqual(self.count(), 0)

    def test_secret_extraction_is_explicit_private_and_never_readable_over_mcp(self):
        args = ['--pid','42','--detect-mnemonics','--extract-secrets']
        with self.assertRaisesRegex(EvidenceError,'requires an enabled'):
            self.run_crypto(arguments=['--pid','42','--extract-secrets'])
        self.backend.outputs.chmod(0o755)
        with self.assertRaisesRegex(EvidenceError,'private configured output'):
            self.run_crypto(arguments=args)
        self.backend.outputs.chmod(0o700)
        result = self.run_crypto(arguments=args)
        self.assertEqual(result['status'],'success')
        secret = 'abandon '*11+'about'  # Public BIP-39 vector, no evidence.
        self.assertNotIn(secret,json.dumps(result))
        files = Path(result['commands'][0]['files_directory'])
        path = files/'cryptomem-secrets-v1.jsonl'
        self.assertIn(secret,path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        for name in ('cryptomem-secrets-v1.jsonl','tmp_synthetic.vol3'):
            relative = 'json/files/'+name
            with self.subTest(name=name):
                for offset,limit in ((0,1),(5,10),(15,65536)):
                    with self.assertRaisesRegex(EvidenceError,'local-only'):
                        self.backend.read_output(str(files/name),offset,limit)
                with self.assertRaisesRegex(EvidenceError,'local-only'):
                    self.backend.query_output('example.raw',result['run_id'],relative)
                with self.assertRaisesRegex(EvidenceError,'local-only'):
                    self.backend.get_evidence({'source':{'image':'example.raw','run_id':result['run_id'],'artifact':relative}})
                with self.assertRaisesRegex(EvidenceError,'local-only'):
                    self.backend.inspect_artifact('example.raw',result['run_id'],relative,'strings')
        self.assertIn('[REDACTED SECRET]',self.backend.read_output(str(files/'cryptomem-findings-v2.jsonl'))['content'])
        self.assertIn('[REDACTED SECRET]',self.backend.read_output(result['json_artifact'])['content'])
        self.assertNotIn(secret,json.dumps(self.backend.case_history('example.raw')))
        self.assertTrue(self.run_crypto(arguments=args)['reused'])

    def test_masked_secret_failures_and_timeout_keep_extraction_local(self):
        args=['--pid','42','--detect-mnemonics','--extract-secrets']
        self.backend.command_timeout=1
        for mode,status in (('incomplete','error'),('timeout','timeout')):
            result=self.run_crypto(mode,arguments=args)
            self.assertEqual(result['status'],status)
            self.assertFalse(result['reuse_eligible'])
            self.assertNotIn('abandon '*11+'about',json.dumps(result))
            path=Path(result['commands'][0]['files_directory'])/'cryptomem-secrets-v1.jsonl'
            with self.assertRaisesRegex(EvidenceError,'local-only'):
                self.backend.read_output(str(path))

    def test_execution_preserves_source_artifacts_hashes_and_provenance(self):
        original = self.image.read_bytes()
        result = self.run_crypto()
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['integrity_verified'])
        self.assertEqual(result['row_count'], 2)
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.image.read_bytes(), original)
        manifest = json.loads(Path(result['manifest_path']).read_text())
        self.assertEqual(manifest['image_sha256_before'], hashlib.sha256(original).hexdigest())
        self.assertEqual(manifest['image_sha256_before'], manifest['image_sha256_after'])
        self.assertEqual(manifest['reuse_context']['plugin']['source_file'], str(self.source))
        self.assertEqual(manifest['reuse_context']['plugin']['source']['kind'], 'third_party')
        self.assertEqual(len(manifest['commands']), 1)
        command = manifest['commands'][0]
        self.assertIs(command['shell'], False)
        self.assertEqual(command['argv'].count('--offline'), 1)
        self.assertNotIn('-p', command['argv'])
        for artifact in command['artifacts']:
            path = Path(artifact['path'])
            self.assertTrue(path.is_relative_to(Path(result['artifact_path'])))
            self.assertEqual(artifact['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertIn(ADDRESS, Path(result['text_artifact']).read_text())
        raw = self.backend.read_output(result['json_artifact'])
        self.assertEqual(json.loads(raw['content'])[0]['Offset'], 4096)
        self.assertFalse(list(self.root.rglob('report.md')))
        self.assertFalse(list(self.root.rglob('case-manifest.json')))

    def test_saved_query_and_evidence_keep_occurrences_and_exact_values(self):
        result = self.run_crypto()
        query = self.backend.query_output('example.raw', result['run_id'], 'json/stdout.json',
            fields=['Value', 'PID', 'Offset', 'Validation'],
            filters=[{'field': 'Value', 'op': 'eq', 'type': 'string', 'value': ADDRESS}])
        self.assertEqual(query['matching_count'], 2)
        self.assertEqual([row['values']['Offset'] for row in query['rows']], [4096, 8192])
        ref = copy.deepcopy(query['rows'][0]['reference'])
        ref['locator']['pointer'] += '/Value'
        evidence = self.backend.get_evidence(ref, {'type': 'string', 'value': ADDRESS})
        self.assertEqual(evidence['observable_validation'], 'matched')
        self.assertEqual(evidence['value'], ADDRESS)
        with self.assertRaises(EvidenceError):
            self.backend.get_evidence(ref, {'type': 'string', 'value': 'different address'})
        grouped = self.backend.query_output('example.raw', result['run_id'], 'json/stdout.json',
                                           group_by=['Canonical'])
        self.assertEqual(grouped['rows'][0]['count'], 2)
        self.assertEqual(self.count(), 1)

    def test_empty_output_and_failed_scans_are_distinct(self):
        result = self.run_crypto('empty')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['row_count'], 0)
        query = self.backend.query_output('example.raw', result['run_id'], 'json/stdout.json')
        self.assertEqual(query['result_state'], 'successful_empty')
        self.assertTrue(self.run_crypto()['reused'])
        for mode, message in [('corrupt', 'layer_name'), ('symbols', 'symbol_table_name'), ('incomplete', 'Unreadable'), ('dependency', 'Crypto.Hash.keccak'),
                              ('unsupported', 'unsupported memory layer')]:
            with self.subTest(mode=mode):
                result = self.run_crypto(mode)
                self.assertEqual(result['status'], 'error')
                self.assertIsNone(result['row_count'])
                self.assertFalse(result['reuse_eligible'])
                self.assertIn(message, result['error_preview'])
                self.assertIn('not a negative finding', result['summary'])
                self.assertTrue(Path(result['commands'][0]['stderr_path']).is_file())
        malformed = self.run_crypto('badjson')
        self.assertEqual(malformed['status'], 'output_error')
        self.assertTrue(Path(malformed['commands'][0]['stdout_path']).is_file())

    def test_missing_dependency_discovery_remains_actionable_and_pslist_works(self):
        (self.root / 'missing-dependency').write_text('SYNTHETIC missing dependency')
        catalog = self.backend.list_plugins(refresh=True)
        self.assertNotIn(self.PLUGIN, {p['name'] for p in catalog['plugins']})
        self.assertIn('volatility3.plugins.windows.cryptomem', catalog['import_failures'])
        with self.assertRaisesRegex(EvidenceError, 'Unknown plugin'):
            self.run_crypto()
        baseline = self.backend.run_plugin('example.raw', 'windows.pslist.PsList', ['--pid', '42'])
        self.assertEqual(baseline['status'], 'success')
        self.assertEqual(baseline['json_preview'][0]['ImageFileName'], 'synthetic.exe')
        self.assertNotIn('--offline', baseline['commands'][0]['argv'])

    def test_timeout_keeps_partial_output_and_integrity(self):
        result = self.run_crypto('timeout')
        self.assertEqual(result['status'], 'timeout')
        self.assertFalse(result['reuse_eligible'])
        self.assertTrue(result['integrity_verified'])
        self.assertIn('SYNTHETIC partial output', Path(result['commands'][0]['stdout_path']).read_text())

    def test_cancellation_stops_running_subprocess_and_preserves_manifest(self):
        event = threading.Event()

        def cancel_started_process():
            deadline = time.monotonic() + 5
            while not (self.root / 'analysis-started').exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            event.set()

        worker = threading.Thread(target=cancel_started_process)
        worker.start()
        try:
            result = self.run_crypto('timeout', cancel_event=event)
        finally:
            worker.join()
        self.assertEqual(result['status'], 'cancelled')
        self.assertTrue(result['integrity_verified'])
        self.assertEqual(self.count(), 1)
        self.assertIn('completed_at', json.loads(Path(result['manifest_path']).read_text()))
        self.assertIn('SYNTHETIC partial output', Path(result['commands'][0]['stdout_path']).read_text())

    def test_case_boundaries_and_source_mutation_are_enforced(self):
        first = self.run_crypto()
        other = self.fixture.evidence / 'other.raw'
        other.write_bytes(self.image.read_bytes())
        second = self.backend.run_plugin('other.raw', self.PLUGIN, ['--pid', '42'])
        self.assertNotEqual(first['case_output_directory'], second['case_output_directory'])
        self.assertFalse(second['reused'])
        with self.assertRaises(EvidenceError):
            self.backend.query_output('other.raw', first['run_id'], 'json/stdout.json')
        scoped = CaseBackend(self.config, [str(other)])
        with self.assertRaisesRegex(EvidenceError, 'not registered'):
            scoped.run_plugin('example.raw', self.PLUGIN, ['--pid', '42'])
        reference = self.backend.query_output('example.raw', first['run_id'],
                                              'json/stdout.json')['rows'][0]['reference']
        with self.assertRaisesRegex(EvidenceError, 'not registered'):
            scoped.get_evidence(reference)
        with self.assertRaises(EvidenceError):
            self.backend.read_output(str(self.image))
        with self.assertRaises(EvidenceError):
            self.backend.run_plugin('../outside.raw', self.PLUGIN, ['--pid', '42'])
        changed = self.run_crypto('mutate')
        self.assertEqual(changed['status'], 'evidence_changed')
        self.assertFalse(changed['integrity_verified'])

    def test_reuse_requires_same_pid_source_bytes_and_saved_artifacts(self):
        first = self.run_crypto()
        again = self.run_crypto(arguments=['--pid=0x2a'])
        self.assertTrue(again['reused'])
        self.assertEqual(first['run_id'], again['run_id'])
        self.assertEqual(self.count(), 1)
        self.assertFalse(self.run_crypto(arguments=['--pid', '43'])['reused'])
        self.source.write_text('# SYNTHETIC changed installed detector\n')
        updated = self.run_crypto()
        self.assertFalse(updated['reused'])
        self.assertNotEqual(first['reuse_key'], updated['reuse_key'])
        Path(updated['json_artifact']).write_text('[]')
        self.assertFalse(self.run_crypto()['reused'])
        self.assertEqual(self.count(), 4)


class LinuxCryptoMemBackendTests(CryptoMemBackendTests):
    PLUGIN = 'linux.cryptomem.CryptoMem'


class MacCryptoMemBackendTests(CryptoMemBackendTests):
    PLUGIN = 'mac.cryptomem.CryptoMem'


if __name__ == '__main__':
    unittest.main()
