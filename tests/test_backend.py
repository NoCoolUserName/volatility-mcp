"""Failure-path checks using harmless simulated Volatility; no real dumps in CI."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

from volatility_mcp.backend import EvidenceError, VolatilityBackend
from volatility_mcp.config import Config


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='volatility-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.fake = self.root / 'fake-python'
        self.fake.write_text('#!' + sys.executable + '\n' +
            (Path(__file__).parent / 'fixtures/fake_volatility.py').read_text())
        self.fake.chmod(0o700)
        self.config = Config(self.evidence, self.root / 'outputs', self.fake, self.fake,
                             cache_path=self.root / 'cache', command_timeout=1, enable_xpnet=False)
        self.backend = VolatilityBackend(self.config)
        self.image = self.evidence / 'example.raw'
        self.image.write_text('normal')

    def run_fixture(self, mode='normal', arguments=None):
        self.image.write_text(mode)
        return self.backend.run_plugin('example.raw', 'windows.pslist.PsList', arguments)

    def test_source_validation_and_discovery(self):
        outside = self.root / 'outside.raw'
        outside.write_text('outside')
        (self.evidence / 'escape.raw').symlink_to(outside)
        (self.evidence / 'internal.raw').symlink_to(self.image)
        (self.evidence / 'linkdir').symlink_to(self.root, target_is_directory=True)
        for value in ('../outside.raw', str(outside), 'escape.raw', 'internal.raw',
                      'linkdir/outside.raw', 'example.raw;id', 'example.raw$(id)'):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                self.backend.resolve_input(value)
        self.assertEqual(self.backend.list_memory_images()['count'], 1)

    def test_separate_outputs_and_symlinks(self):
        self.backend.outputs.rmdir()
        self.backend.outputs.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises(EvidenceError):
            self.run_fixture()
        self.assertEqual(self.image.read_text(), 'normal')

    def test_strict_options_numeric_types_and_uri_paths(self):
        validate = lambda args: self.backend.validate_arguments('windows.pslist.PsList', args)
        self.assertEqual(validate(['--pid', '0x2a', '43']), ['--pid', '0x2a', '43'])
        for args in (['--pid','no'], ['-o','/tmp'], ['--plugin-dirs','/tmp'], ['--config','x'],
                     ['--output-dir=/tmp'], ['--pid','2','--pid','3'], ['--text','a;id'],
                     ['--text','https://example.test'], ['--input','../outside']):
            with self.subTest(args=args), self.assertRaises(EvidenceError):
                validate(args)
        rules = self.evidence / 'rules.yar'
        rules.write_text('SYNTHETIC text')
        self.assertEqual(validate(['--input','rules.yar']), ['--input', str(rules)])
        with self.assertRaisesRegex(EvidenceError, 'Unknown plugin'):
            self.backend.run_plugin('example.raw','absent.Plugin')
        key = r'ControlSet001\Services\Example'
        self.assertEqual(self.backend.validate_arguments('windows.registry.printkey.PrintKey',
            ['--key',key]), ['--key',key])

    def test_one_execution_preserves_evidence_and_artifacts(self):
        original = self.image.read_bytes()
        result = self.run_fixture(arguments=['--dump'])
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['integrity_verified'])
        self.assertEqual(self.image.read_bytes(), original)
        manifest = json.loads(Path(result['manifest_path']).read_text())
        self.assertEqual(len(manifest['commands']), 1)
        command = manifest['commands'][0]
        self.assertIs(command['shell'], False)
        self.assertEqual(command['argv'][:3], [str(self.fake), '-I', str(self.fake)])
        for artifact in command['artifacts']:
            p = Path(artifact['path'])
            self.assertTrue(p.is_relative_to(self.backend.outputs))
            self.assertEqual(artifact['sha256'], hashlib.sha256(p.read_bytes()).hexdigest())
        self.assertTrue(Path(result['text_artifact']).exists())
        self.assertFalse(list(self.root.rglob('report.md')))
        self.assertFalse(list(self.root.rglob('case-manifest.json')))

    def test_error_and_malformed_output_not_clean(self):
        error = self.run_fixture('error')
        self.assertEqual(error['status'],'error')
        self.assertEqual(error['failure_category'],'missing_symbols_or_layer')
        self.assertIn('not a negative finding',error['summary'])
        self.assertIn('symbol_table_name',error['error_preview'])
        malformed = self.run_fixture('badjson')
        self.assertEqual(malformed['status'], 'output_error')
        self.assertEqual(len(malformed['commands']),1)
        self.assertTrue(Path(malformed['commands'][0]['stdout_path']).exists())

    def test_timeout_and_cancellation_preserve_partial_output(self):
        result = self.run_fixture('timeout')
        self.assertEqual(result['status'], 'timeout')
        self.assertTrue(result['integrity_verified'])
        self.assertIn('partial stdout', Path(result['commands'][0]['stdout_path']).read_text())
        self.image.write_text('timeout')
        event = threading.Event()
        timer = threading.Timer(0.25,event.set)
        timer.start()
        try:
            result = self.backend.run_plugin('example.raw','windows.pslist.PsList',cancel_event=event)
        finally:
            timer.join()
        self.assertEqual(result['status'],'cancelled')
        self.assertIn('completed_at',json.loads(Path(result['manifest_path']).read_text()))

    def test_source_mutation_invalidates_run(self):
        result = self.run_fixture('mutate')
        self.assertEqual(result['status'],'evidence_changed')
        self.assertFalse(result['integrity_verified'])

    def test_large_output_and_bounded_reads(self):
        result = self.run_fixture('huge')
        self.assertEqual(result['row_count'],1000)
        self.assertLess(len(json.dumps(result)),20000)
        self.assertTrue(result['preview_truncated'])
        chunk = self.backend.read_output(result['json_artifact'],0,1024)
        self.assertEqual(len(chunk['content']),1024)
        self.assertTrue(chunk['truncated'])
        next_chunk = self.backend.read_output(result['json_artifact'],chunk['next_offset'],1024)
        self.assertEqual(next_chunk['offset'],1024)
        for path in (str(self.image),'../evidence/example.raw'):
            with self.assertRaises(EvidenceError): self.backend.read_output(path)
        link = self.backend.outputs / 'linked.txt'
        link.symlink_to(self.image)
        with self.assertRaises(EvidenceError): self.backend.read_output(str(link))
        with self.assertRaises(EvidenceError): self.backend.read_output(result['json_artifact'],limit=65537)

    def test_history_identifies_unfinished_previous_session(self):
        result = self.run_fixture()
        manifest = Path(result['manifest_path'])
        data = json.loads(manifest.read_text())
        data['status'] = 'running'
        data['server_session'] = 'SYNTHETIC previous process'
        manifest.write_text(json.dumps(data))
        history = self.backend.case_history('example.raw')
        self.assertEqual(history['entries'][0]['status'],'interrupted_or_external_session')
        self.assertEqual(json.loads(manifest.read_text())['status'],'running')

    def test_output_fifo_is_rejected_without_blocking(self):
        fifo = self.backend.outputs / 'not-a-file.txt'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(EvidenceError, 'Not a regular file'):
            self.backend.read_output(str(fifo), limit=1)

if __name__ == '__main__': unittest.main()
