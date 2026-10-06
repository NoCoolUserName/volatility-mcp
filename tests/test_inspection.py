import asyncio
import dataclasses
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.backend import EvidenceError, VolatilityBackend, file_fingerprint
from volatility_mcp.cli import decode_result
from volatility_mcp.inspect_worker import pe_headers, strings_page
from volatility_mcp.ui.scoped_mcp import CaseBackend
from volatility_mcp.ui.storage import Bundle, now
from fixtures.synthetic_pe import synthetic_pe
import test_backend


class ParserTests(unittest.TestCase):
    def test_pe32_pe32plus_and_header_flags(self):
        for plus in (False, True):
            for dll in (False, True):
                result = pe_headers(synthetic_pe(plus, dll))
                self.assertEqual(result['format'], 'PE32+' if plus else 'PE32')
                self.assertEqual(result['dll_flag'], dll)
                self.assertTrue(result['executable_image_flag'])
                self.assertEqual(result['structural_status'], 'declared_ranges_present', result)
                self.assertEqual(result['entry_point']['file_offset'], 0x200)
                self.assertEqual(result['sections'][0]['raw_size'], 0x200)
                self.assertEqual(result['subsystem']['value'], 3)

    def test_malformed_truncated_and_missing_dll_flag_are_not_verdicts(self):
        self.assertEqual(pe_headers(b'not a PE')['structural_status'], 'not_pe')
        self.assertEqual(pe_headers(b'MZ')['structural_status'], 'malformed_or_truncated')
        self.assertEqual(pe_headers(synthetic_pe()[:700])['structural_status'], 'truncated_or_inconsistent')
        self.assertEqual(pe_headers(synthetic_pe()[:160])['structural_status'], 'malformed_or_truncated')
        changed = bytearray(synthetic_pe()); struct.pack_into('<H', changed, 0x96, 0)
        result = pe_headers(bytes(changed))
        self.assertFalse(result['dll_flag']); self.assertFalse(result['executable_image_flag'])
        self.assertIn('neither', result['classification'])

    def test_ascii_wide_offsets_and_record_pagination(self):
        data = synthetic_pe()
        for encoding, text, offset in [('ascii','HELLO_ASCII',0x210),('utf-16le','WORLD_WIDE',0x240),
                                       ('utf-16le','ODD_WIDE',0x281)]:
            settings = dict(offset=0,scan_bytes=1024,min_length=4,limit=1,max_string_length=16,encoding=encoding)
            rows = []
            for _ in range(30):
                page = strings_page(io.BytesIO(data),len(data),settings)
                rows.extend(page['records'])
                if not page['truncated']:break
                self.assertGreater(page['next_offset'],settings['offset'])
                settings['offset']=page['next_offset']
            match = next(r for r in rows if r['text'] == text)
            self.assertEqual(match['offset'],offset)

    def test_string_length_and_scan_bounds(self):
        data = b'Z'*600+b'\0'
        settings = dict(offset=0,scan_bytes=256,min_length=4,limit=2,max_string_length=16,encoding='ascii')
        page = strings_page(io.BytesIO(data),len(data),settings)
        self.assertTrue(page['truncated']); self.assertTrue(page['records'][0]['text_truncated'])
        self.assertTrue(page['records'][0]['may_continue_in_next_window'])
        self.assertEqual(len(page['records'][0]['text']),16)
        settings['offset']=page['next_offset']
        self.assertTrue(strings_page(io.BytesIO(data),len(data),settings)['records'][0]['continues_from_previous_window'])
        data = b'\0'*254+b'HELLO\0'
        settings['offset']=0
        first = strings_page(io.BytesIO(data),len(data),settings)
        self.assertEqual(first['next_offset'],254)
        settings['offset']=first['next_offset']
        self.assertEqual(strings_page(io.BytesIO(data),len(data),settings)['records'][0]['text'],'HELLO')
        data=b'\0'*251+'HELLO'.encode('utf-16le')+b'\0\0'
        settings.update(offset=0,encoding='utf-16le')
        first=strings_page(io.BytesIO(data),len(data),settings)
        self.assertEqual(first['next_offset'],251)
        settings['offset']=first['next_offset']
        self.assertEqual(strings_page(io.BytesIO(data),len(data),settings)['records'][0]['text'],'HELLO')


class InspectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend
        self.run = self.backend.run_plugin('example.raw','windows.pslist.PsList',['--dump'])
        self.relative = 'json/files/synthetic.dmp'
        self.source = Path(self.run['artifact_path'])/self.relative
        self.source.write_bytes(synthetic_pe(dll=True))
        manifest = Path(self.run['manifest_path'])
        record = json.loads(manifest.read_text())
        record['commands'][0]['artifacts'].append(file_fingerprint(self.source))
        manifest.write_text(json.dumps(record))

    def inspect(self, **kwargs):
        return self.backend.inspect_artifact('example.raw',self.run['run_id'],self.relative,**kwargs)

    async def test_inspection_reuses_without_volatility_or_image_hashing(self):
        original = self.source.read_bytes()
        def guarded(path):
            self.assertNotEqual(path, self.fixture.image)
            return file_fingerprint(path)
        with patch('volatility_mcp.artifact_inspection.file_fingerprint',side_effect=guarded):
            first = self.inspect(); second = self.inspect()
        self.assertEqual(first['status'],'success'); self.assertTrue(second['reused'])
        self.assertTrue(first['result']['dll_flag'])
        self.assertEqual(first['manifest_path'],second['manifest_path'])
        self.assertEqual(self.source.read_bytes(),original)
        self.assertEqual(len((self.fixture.root/'analysis-count.jsonl').read_text().splitlines()),1)
        restarted = VolatilityBackend(self.fixture.config)
        self.assertTrue(restarted.inspect_artifact('example.raw',self.run['run_id'],self.relative)['reused'])
        Path(first['result_path']).write_text('{}')
        self.assertFalse(self.inspect()['reused'])

    async def test_rejected_paths_unregistered_artifacts_and_limits(self):
        for path in ('../../outside',str(self.source),'json/files/../stdout.json','missing.bin'):
            with self.subTest(path=path), self.assertRaises((ValueError,OSError)):
                self.backend.inspect_artifact('example.raw',self.run['run_id'],path)
        unknown = self.source.with_name('unregistered.bin'); unknown.write_text('SYNTHETIC')
        with self.assertRaisesRegex(ValueError,'not registered'):
            self.backend.inspect_artifact('example.raw',self.run['run_id'],'json/files/unregistered.bin')
        with self.assertRaises(ValueError):
            self.backend.inspect_artifact('example.raw','../escape',self.relative)
        for args in ({'limit':201},{'offset':-1},{'min_length':1},{'scan_bytes':4*1024*1024+1},
                     {'encoding':'utf-8'},{'max_string_length':513},{'offset':True}):
            with self.subTest(args=args), self.assertRaises(ValueError):self.inspect(**args)
        self.source.unlink(); self.source.symlink_to(self.fixture.image)
        with self.assertRaises(ValueError):self.inspect()

    async def test_changed_source_is_not_certified(self):
        self.inspect()
        self.source.write_bytes(b'MZ changed')
        with self.assertRaisesRegex(ValueError,'differs from its extraction'):
            self.inspect()

    async def test_worker_timeout_retains_failure_and_large_artifact_is_rejected(self):
        self.backend.command_timeout = 0.05
        popen = subprocess.Popen
        def slow_worker(argv, **kwargs):
            return popen([sys.executable,'-c','import time; print("SYNTHETIC partial output",flush=True); time.sleep(5)'],**kwargs)
        with patch('volatility_mcp.artifact_inspection.subprocess.Popen',side_effect=slow_worker):
            result = self.inspect()
        self.assertEqual(result['status'],'error'); self.assertIsNone(result['result'])
        manifest=json.loads(Path(result['manifest_path']).read_text())
        self.assertTrue(manifest['integrity_verified'])
        self.assertIn('timed out',manifest['error'])
        with self.source.open('r+b') as f:f.truncate(64*1024*1024+1)
        with self.assertRaisesRegex(ValueError,'64 MiB'):self.inspect()

    async def test_real_scoped_mcp_discovery_call_and_other_image_rejection(self):
        cfg = self.fixture.root/'scope.json'
        cfg.write_text(json.dumps({'config':self.fixture.config.to_dict(),'images':[str(self.fixture.image)]}))
        transport = StdioServerParameters(command=sys.executable,
            args=['-m','volatility_mcp.ui.scoped_mcp',str(cfg)])
        async with Client(transport,mode='legacy',read_timeout_seconds=15) as client:
            self.assertIn('inspect_artifact',{t.name for t in (await client.list_tools()).tools})
            params = dict(image='example.raw',run_id=self.run['run_id'],artifact=self.relative)
            pe = decode_result(await client.call_tool('inspect_artifact',params))
            self.assertTrue(pe['result']['dll_flag'])
            strings = decode_result(await client.call_tool('inspect_artifact',{**params,'operation':'strings'}))
            self.assertTrue(any(r['text']=='HELLO_ASCII' for r in strings['result']['records']))
            other = self.fixture.evidence/'other.raw'; other.write_text('SYNTHETIC')
            self.assertTrue((await client.call_tool('inspect_artifact',{**params,'image':str(other)})).is_error)

    async def test_regex_regression_and_global_options_still_rejected(self):
        regex = r'[\x20-\x7e][\x20-\x7e][\x20-\x7e][\x20-\x7e]+'
        plugin = 'windows.vadregexscan.VadRegExScan'
        args = ['--pid','668','940','868','1928','--pattern',regex,'--maxsize','256']
        self.assertEqual(self.backend.validate_arguments(plugin,args),args)
        for tail in (['--plugin-dirs','/tmp'],['--output-dir','/tmp'],['--pattern','x']):
            with self.assertRaises(ValueError):self.backend.validate_arguments(plugin,args+tail)
        for invalid in ('[', 'x\x00', 'a'*4097):
            with self.assertRaises(ValueError):self.backend.validate_arguments(plugin,['--pattern',invalid])
        with self.assertRaises(ValueError):self.backend.validate_arguments('windows.pslist.PsList',['--text',regex])

    async def test_new_bundle_includes_inspection_provenance_as_separate_run(self):
        result = self.inspect()
        case_dir = self.fixture.root/'ui-case'
        # Existing fixture output layout becomes a private synthetic case analysis root.
        case_dir.mkdir()
        import shutil
        shutil.copytree(self.fixture.config.output_root,case_dir/'analysis')
        case = {'id':'synthetic','images':[{'id':'E001','path':str(self.fixture.image),
            'sha256':file_fingerprint(self.fixture.image)['sha256'],'size_bytes':6}], 'notes':{}}
        version={'id':'new','status':'draft','created_at':now()}
        bundle=Bundle(case_dir,case,version)
        manifest = bundle.prepare()
        self.assertTrue(any(r['run_id'].startswith('inspection-') for r in manifest['runs']))
        self.assertTrue(any(a['path'].endswith('/result.json') for a in manifest['artifacts']))
        artifact=next(a for a in manifest['artifacts'] if a['path'].endswith('/result.json'))
        from test_ui import report_text
        bundle.save(report_text(artifact['path'],artifact['artifact_id']),
                    [{'finding_id':'F001','evidence_refs':[{'artifact_id':artifact['artifact_id'],'locator':'format'}]}],[])
        bundle.seal({'E001':file_fingerprint(self.fixture.image)})
        self.assertEqual(version['status'],'sealed')


if __name__ == '__main__':unittest.main()
