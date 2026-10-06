"""Persistent reuse acceptance checks; only the harmless analyzer fixture runs."""
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from volatility_mcp.backend import VolatilityBackend
from volatility_mcp.backend import file_fingerprint
from volatility_mcp.reuse import execution_lock
from volatility_mcp.reuse import find_completed
import test_backend


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend
        self.config = self.fixture.config
        self.image = self.fixture.image

    def run_plugin(self, arguments=None, backend=None):
        return (backend or self.backend).run_plugin('example.raw', 'windows.pslist.PsList', arguments)

    def count(self):
        path = self.fixture.root / 'analysis-count.jsonl'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def test_equivalent_requests_restart_and_hash_measurements(self):
        first = self.run_plugin(['--pid', '0x2a', '--dump'])
        original = {p: p.read_bytes() for p in Path(first['artifact_path']).rglob('*') if p.is_file()}
        second = self.run_plugin(['--dump', '--pid=42'])
        third = self.run_plugin(['--pid', '42', '--dump'], VolatilityBackend(self.config))
        self.assertEqual(self.count(), 1)
        self.assertFalse(first['reused'])
        for result in (second, third):
            self.assertTrue(result['reused'])
            self.assertEqual(result['run_id'], first['run_id'])
            self.assertEqual(result['json_artifact'], first['json_artifact'])
            receipt = json.loads(Path(result['reuse_receipt_path']).read_text())
            self.assertTrue(receipt['integrity_verified'])
            self.assertEqual(receipt['hashing'], result['hashing'])
        for result in (first, second, third):
            measurements = result['hashing']
            for phase in ('image_before', 'image_after'):
                self.assertEqual(measurements['groups'][phase]['files'], 1)
                self.assertEqual(measurements['groups'][phase]['bytes'], self.image.stat().st_size)
                self.assertGreaterEqual(measurements['groups'][phase]['seconds'], 0)
            self.assertGreater(measurements['total_seconds'], 0)
        self.assertGreater(second['hashing']['groups']['saved_artifacts']['files'], 2)
        self.assertEqual(original, {p: p.read_bytes() for p in original})
        self.assertEqual(self.backend.case_history('example.raw')['count'], 1)

    def test_image_arguments_inputs_and_context_invalidation(self):
        rules = self.fixture.evidence / 'rules.yar'
        rules.write_text('SYNTHETIC first rules')
        args = ['--input', 'rules.yar']
        self.run_plugin(args)
        self.assertTrue(self.run_plugin(args)['reused'])
        rules.write_text('SYNTHETIC changed rules')
        self.assertFalse(self.run_plugin(args)['reused'])
        self.assertFalse(self.run_plugin([*args, '--pid', '43'])['reused'])
        self.image.write_text('another harmless image')
        self.assertFalse(self.run_plugin(args)['reused'])
        cache = self.config.cache_path / 'symbols.json'
        cache.write_text('SYNTHETIC symbols')
        self.assertFalse(self.run_plugin(args)['reused'])
        cache.write_text('SYNTHETIC new symbols')
        self.assertFalse(self.run_plugin(args)['reused'])
        # In-place analyzer edits invalidate a long-lived backend as well.
        self.fixture.fake.write_text(self.fixture.fake.read_text() + '\n# SYNTHETIC upgrade\n')
        self.assertFalse(self.run_plugin(args)['reused'])
        changed = VolatilityBackend(dataclasses.replace(self.config, command_timeout=2))
        self.assertFalse(self.run_plugin(args, changed)['reused'])
        self.assertEqual(self.count(), 8)

    def test_versions_dependencies_and_plugin_schema_invalidate(self):
        catalog = self.backend.catalog()
        dependency = self.fixture.root / 'synthetic-dependency.py'
        dependency.write_text('SYNTHETIC version one')
        catalog['runtime_files'] = [str(dependency)]
        with patch.object(self.backend, 'catalog', return_value=catalog):
            self.run_plugin()
            self.assertTrue(self.run_plugin()['reused'])
            for field in ('version', 'python_version', 'architecture'):
                catalog[field] = 'SYNTHETIC changed ' + field
                self.assertFalse(self.run_plugin()['reused'])
            catalog['plugins']['windows.pslist.PsList']['plugin_version'] = [0, 0, 1]
            self.assertFalse(self.run_plugin()['reused'])
            catalog['packages'] = {'SYNTHETIC-dependency': '2'}
            self.assertFalse(self.run_plugin()['reused'])
            dependency.write_text('SYNTHETIC dependency edited without version bump')
            self.assertFalse(self.run_plugin()['reused'])
        self.assertEqual(self.count(), 7)

    def test_uninventoried_defaults_disable_reuse_without_blocking_analysis(self):
        catalog = self.backend.catalog()
        catalog['reuse_blockers'] = ['SYNTHETIC implicit external defaults']
        with patch.object(self.backend, 'catalog', return_value=catalog):
            for _ in range(2):
                result = self.run_plugin()
                self.assertEqual(result['status'], 'success')
                self.assertFalse(result['reused'])
                self.assertFalse(result['reuse_eligible'])
                self.assertIn('implicit external defaults', result['reuse_unavailable_reason'])
        self.assertEqual(self.count(), 2)

    def test_damaged_missing_added_and_symlinked_artifacts_are_not_reused(self):
        for damage in ('changed', 'missing', 'extra', 'symlink', 'command'):
            with self.subTest(damage=damage):
                result = self.run_plugin()
                path = Path(result['json_artifact'])
                if damage == 'changed': path.write_text('[]')
                elif damage == 'missing': path.unlink()
                elif damage == 'extra': (path.parent / 'extra.txt').write_text('SYNTHETIC unexpected')
                elif damage == 'command': (path.parent.parent / 'command.started.json').write_text('{}')
                else:
                    path.unlink()
                    path.symlink_to(self.image)
                count = self.count()
                replacement = self.run_plugin()
                self.assertFalse(replacement['reused'])
                self.assertNotEqual(replacement['run_id'], result['run_id'])
                self.assertEqual(self.count(), count + 1)
        self.assertEqual(self.image.read_text(), 'normal')

    def test_failures_and_legacy_records_are_not_reused(self):
        for mode, status in [('error', 'error'), ('badjson', 'output_error'), ('timeout', 'timeout')]:
            with self.subTest(mode=mode):
                self.image.write_text(mode)
                count = self.count()
                for _ in range(2):
                    result = self.run_plugin()
                    self.assertEqual(result['status'], status)
                    self.assertFalse(result['reused'])
                self.assertEqual(self.count(), count + 2)
        self.image.write_text('normal')
        first = self.run_plugin()
        path = Path(first['manifest_path'])
        record = json.loads(path.read_text())
        record.pop('reuse_key')
        path.write_text(json.dumps(record))
        self.assertFalse(self.run_plugin()['reused'])

    def test_cached_artifact_traversal_is_rejected_before_reading(self):
        first = self.run_plugin()
        outside = self.fixture.root / 'outside.txt'
        outside.write_text('SYNTHETIC outside output root')
        path = Path(first['manifest_path'])
        record = json.loads(path.read_text())
        escape = str(path.parent / '..' / '..' / '..' / '..' / 'outside.txt')
        command = record['commands'][0]
        command['stdout_path'] = command['json_path'] = escape
        command['artifacts'][0]['path'] = escape
        path.write_text(json.dumps(record))
        def guarded(candidate):
            self.assertNotEqual(candidate.resolve(), outside)
            return file_fingerprint(candidate)
        with patch('volatility_mcp.backend.file_fingerprint', side_effect=guarded):
            self.assertFalse(self.run_plugin()['reused'])
        self.assertEqual(self.count(), 2)

    def test_empty_success_reuses_and_unstable_symbol_context_does_not(self):
        self.image.write_text('empty')
        self.assertEqual(self.run_plugin()['row_count'], 0)
        self.assertTrue(self.run_plugin()['reused'])
        self.image.write_text('warm-cache')
        first = self.run_plugin()
        record = json.loads(Path(first['manifest_path']).read_text())
        self.assertEqual(first['status'], 'success')
        self.assertFalse(record['reuse_eligible'])
        self.assertIn('context changed', record['reuse_unavailable_reason'])
        self.assertFalse(self.run_plugin()['reused'])
        self.assertTrue(self.run_plugin()['reused'])
        self.assertEqual(self.count(), 3)

    def test_source_change_during_reuse_is_rejected(self):
        self.run_plugin()
        def changed(*args):
            result = find_completed(*args)
            self.image.write_text('SYNTHETIC changed during cache validation')
            return result
        with patch('volatility_mcp.backend.find_completed', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during reuse'):
                self.run_plugin()
        self.assertEqual(self.count(), 1)

    def test_incomplete_and_corrupt_manifests_are_not_reused(self):
        for state in ('running', 'cancelled', 'unsupported', 'evidence_changed', 'corrupt', 'wrong-shape'):
            first = self.run_plugin()
            path = Path(first['manifest_path'])
            record = json.loads(path.read_text())
            record['status'] = state
            path.write_text('{' if state == 'corrupt' else '[]' if state == 'wrong-shape' else json.dumps(record))
            self.assertFalse(self.run_plugin()['reused'])

    def test_discovery_reuses_probes_after_restart(self):
        first = self.backend.get_image_info('example.raw')
        second = VolatilityBackend(self.config).get_image_info('example.raw')
        self.assertEqual(self.count(), 2)
        self.assertEqual([p['run_id'] for p in first['probes']], [p['run_id'] for p in second['probes']])
        self.assertTrue(all(p['reused'] for p in second['probes']))

    def test_parallel_processes_launch_one_analysis(self):
        self.image.write_text('slow')
        config = self.fixture.root / 'config.json'
        config.write_text(json.dumps(self.config.to_dict()))
        code = ('import json,sys; from volatility_mcp.config import load_config; '
                'from volatility_mcp.backend import VolatilityBackend; '
                'print(json.dumps(VolatilityBackend(load_config(sys.argv[1])).run_plugin('
                '"example.raw","windows.pslist.PsList")))')
        children = [subprocess.Popen([sys.executable, '-c', code, str(config)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        try:
            results = []
            for child in children:
                out, err = child.communicate(timeout=20)
                self.assertEqual(child.returncode, 0, err)
                results.append(json.loads(out))
            self.assertEqual(self.count(), 1)
            self.assertEqual(results[0]['run_id'], results[1]['run_id'])
            self.assertEqual(sorted(r['reused'] for r in results), [False, True])
        finally:
            for child in children:
                if child.poll() is None: child.kill()
                child.wait()

    def test_waiting_duplicate_cancels_without_analysis(self):
        event = threading.Event()
        with execution_lock(self.backend, threading.Event()):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.backend.run_plugin, 'example.raw', 'windows.pslist.PsList', None, event)
                event.set()
                with self.assertRaisesRegex(ValueError, 'cancelled'):
                    future.result(timeout=5)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.run_plugin()['status'], 'success')

    def test_dead_lock_owner_does_not_block_retry(self):
        path = self.fixture.root / 'config.json'
        path.write_text(json.dumps(self.config.to_dict()))
        code = ('import sys,time,threading; from volatility_mcp.config import load_config; '
                'from volatility_mcp.backend import VolatilityBackend; from volatility_mcp.reuse import execution_lock; '
                'lock=execution_lock(VolatilityBackend(load_config(sys.argv[1])),threading.Event()); '
                'lock.__enter__(); print("locked",flush=True); time.sleep(30)')
        child = subprocess.Popen([sys.executable, '-c', code, str(path)], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'locked')
        finally:
            child.kill(); child.wait(); child.stdout.close()
        self.assertEqual(self.run_plugin()['status'], 'success')
        self.assertEqual(self.count(), 1)

    def test_surviving_analyzer_keeps_lock_after_server_is_killed(self):
        self.image.write_text('timeout')
        path = self.fixture.root / 'config.json'
        path.write_text(json.dumps(dataclasses.replace(self.config, command_timeout=10).to_dict()))
        code = ('import sys; from volatility_mcp.config import load_config; '
                'from volatility_mcp.backend import VolatilityBackend; '
                'VolatilityBackend(load_config(sys.argv[1])).run_plugin("example.raw","windows.pslist.PsList")')
        child = subprocess.Popen([sys.executable, '-c', code, str(path)])
        analyzer_pid = None
        try:
            deadline = time.monotonic() + 10
            while not self.count() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(self.count(), 1)
            analyzer_pid = json.loads((self.fixture.root / 'analysis-count.jsonl').read_text())['pid']
            child.kill(); child.wait()
            with (self.config.output_root / '.execution.lock').open('rb') as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.count(), 1)
        finally:
            if child.poll() is None: child.kill()
            child.wait()
            if analyzer_pid:
                try: os.kill(analyzer_pid, 9)
                except ProcessLookupError: pass


if __name__ == '__main__':
    unittest.main()
