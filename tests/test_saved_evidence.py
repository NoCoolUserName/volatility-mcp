"""Saved-only fixtures: no analyzer execution during query/report verification."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.backend import EvidenceError, VolatilityBackend, file_fingerprint
from volatility_mcp.cli import decode_result
from volatility_mcp.saved_evidence import reference, resolve_source
from volatility_mcp.reporting import check_bundle, check_citation
from volatility_mcp.scoped import CaseBackend
from volatility_mcp.timestamps import utc_now as now
from volatility_mcp.inspect_worker import pe_headers, strings_page
from fixtures.synthetic_pe import synthetic_pe
import io
import test_backend


class SavedTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend
        self.case_dir = self.fixture.root/'workbench'/'synthetic'
        from dataclasses import replace
        self.backend = VolatilityBackend(replace(self.fixture.config, output_root=self.case_dir/'analysis'))
        self.rows = [
            {'PID':4, 'Name':'System', 'Address':18446744073709551600, 'Unknown':None,
             '__children':[{'PID':42, 'Name':'Child.exe', 'Address':4096, '__children':[]}]},
            {'PID':42, 'Name':'Other.exe', 'Address':8192, 'Unknown':'N/A', '__children':[]},
            {'PID':7, 'Name':'Empty', 'Address':0, 'Unknown':None, '__children':[]}]
        self.create_run('saved', self.rows)
        # Count EVERY fake Volatility interpreter launch (catalogs included).
        script=self.fixture.fake.read_text(); line,body=script.split('\n',1)
        counter=self.fixture.root/'all-volatility-launches.txt'
        self.fixture.fake.write_text(line+'\nwith open('+repr(str(counter))+", 'a') as counter: counter.write('launch\\n')\n"+body)
        self.counter=counter

    def create_run(self, rid, payload, status='success'):
        case=self.backend.case_directory(self.fixture.image)
        root=case/'runs'/rid; (root/'json').mkdir(parents=True)
        path=root/'json/stdout.json'; path.write_text(json.dumps(payload))
        image=file_fingerprint(self.fixture.image)
        record={'run_id':rid,'image':str(self.fixture.image),'image_relative_path':'example.raw',
            'image_sha256_before':image['sha256'],'image_sha256_after':image['sha256'],
            'integrity_verified':True,'status':status,'started_at':now(),'completed_at':now(),
            'plugin':'synthetic.PsList','arguments':[], 'volatility_version':'synthetic',
            'volatility_python_version':'synthetic','mcp_sdk_version':'synthetic','server_version':'synthetic',
            'commands':[{'argv':['SIMULATED, NOT EXECUTED'],'stdout_path':str(path),'artifacts':[file_fingerprint(path)]}]}
        (root/'manifest.json').write_text(json.dumps(record))
        return path

    def query(self, **kw):
        return self.backend.query_output('example.raw','saved','json/stdout.json',**kw)

    def ref(self, location='/0/PID'):
        q=self.query(fields=['PID']); ref=copy.deepcopy(q['rows'][0]['reference'])
        ref['locator']['pointer']=location
        return ref

    def test_selection_filter_count_group_sort_and_pagination(self):
        q=self.query(fields=['PID','Name'],filters=[{'field':'PID','op':'eq','type':'integer','value':'0x2a'}])
        self.assertEqual(q['matching_count'],2)
        self.assertEqual([r['values']['Name'] for r in q['rows']],['Child.exe','Other.exe'])
        self.assertEqual(q['rows'][0]['parent_locator'],'/0')
        self.assertEqual(q['rows'][0]['locator'],'/0/__children/0')
        self.assertEqual(self.query(group_by=['PID'])['rows'][1]['count'],2)
        first=self.query(sort=[{'field':'PID','type':'integer','direction':'desc'}],limit=1)
        second=self.query(sort=[{'field':'PID','type':'integer','direction':'desc'}],offset=first['next_offset'],limit=1)
        self.assertEqual(first['rows'][0]['values']['Name'],'Child.exe')
        self.assertEqual(second['rows'][0]['values']['Name'],'Other.exe')
        self.assertEqual(self.query(filters=[{'field':'Name','op':'contains','type':'string','value':'.exe'}])['matching_count'],2)
        self.assertEqual(self.query(filters=[{'field':'Unknown','op':'eq','type':'null','value':None}])['matching_count'],2)
        self.assertEqual(self.query(filters=[{'field':'Unknown','op':'exists','value':False}])['matching_count'],1)
        self.assertEqual(self.query()['rows'][0]['values']['Address'],{'$integer':'18446744073709551600'})
        self.assertFalse(self.counter.exists())

    def test_checked_values_references_restart_and_rederivation(self):
        ref=self.ref('/0/Address')
        result=self.backend.get_evidence(ref,{'type':'integer','value':'0xfffffffffffffff0'})
        self.assertEqual(result['observable_validation'],'matched')
        # No persistent derived index: repeat lazy derivation with a new backend.
        restarted=VolatilityBackend(self.backend.config)
        self.assertEqual(restarted.query_output('example.raw','saved','json/stdout.json')['rows'][0]['reference']['source'],ref['source'])
        self.assertEqual(restarted.get_evidence(ref)['value'],result['value'])
        for loc in ['/900/PID','/0/absent','/0/__children/99/PID']:
            with self.subTest(loc=loc), self.assertRaises(EvidenceError):self.backend.get_evidence(self.ref(loc))
        for claim in [{'type':'integer','value':999},{'type':'boolean','value':True},{'type':'string','value':'4'}]:
            with self.subTest(claim=claim),self.assertRaises(EvidenceError):self.backend.get_evidence(self.ref(),claim)
        with self.assertRaises(EvidenceError):self.backend.get_evidence(self.ref('/0/Name'),{'type':'string','value':'system'})
        bad=copy.deepcopy(ref); bad['source']['case_id']='other'
        with self.assertRaises(EvidenceError):self.backend.get_evidence(bad)
        bad=copy.deepcopy(ref); bad['source']['sha256']='0'*64
        with self.assertRaises(EvidenceError):self.backend.get_evidence(bad)
        path,_,_=resolve_source(self.backend,'example.raw','saved','json/stdout.json');path.write_text('[]')
        with self.assertRaises(EvidenceError):self.backend.get_evidence(ref)

    def test_bounds_invalid_fields_formats_status_and_escapes(self):
        for options in [dict(fields=['NoSuchField']),dict(limit=201),dict(offset=-1),
                        dict(filters=[{'field':'PID','op':'eval','value':'x'}]),
                        dict(sort=[{'field':'PID','type':'integer','direction':'sideways'}])]:
            with self.subTest(options=options),self.assertRaises(EvidenceError):self.query(**options)
        for status in ['error','output_error','timeout','cancelled','running','unsupported']:
            self.create_run(status,[],status)
            q=self.backend.query_output('example.raw',status,'json/stdout.json')
            self.assertEqual(q['source_result']['source_status'],status)
            self.assertEqual(q['result_state'],'collection_not_successful')
        self.create_run('empty',[])
        self.assertEqual(self.backend.query_output('example.raw','empty','json/stdout.json')['result_state'],'successful_empty')
        with self.assertRaisesRegex(EvidenceError,'missing'):self.backend.query_output('example.raw','missing','json/stdout.json')
        path=self.create_run('bad',[],'output_error');path.write_text('[{"PID":1},')
        manifest=path.parent.parent/'manifest.json';m=json.loads(manifest.read_text());m['commands'][0]['artifacts']=[file_fingerprint(path)];manifest.write_text(json.dumps(m))
        q=self.backend.query_output('example.raw','bad','json/stdout.json')
        self.assertEqual(q['status'],'unsupported_format');self.assertIsNone(q['matching_count'])
        for image,rid,artifact in [('../example.raw','saved','json/stdout.json'),('example.raw','../saved','json/stdout.json'),('example.raw','saved','../manifest.json')]:
            with self.assertRaises((EvidenceError,OSError)):self.backend.query_output(image,rid,artifact)
        other=self.fixture.evidence/'other.raw';other.write_text('harmless')
        scoped=CaseBackend(self.backend.config,[str(other)])
        with self.assertRaises(EvidenceError):scoped.get_evidence(self.ref())
        path=self.create_run('symlink',[]);path.unlink();path.symlink_to(self.fixture.image)
        with self.assertRaises(EvidenceError):self.backend.query_output('example.raw','symlink','json/stdout.json')

    def test_malformed_numeric_and_processing_response_limits(self):
        from volatility_mcp.saved_evidence import load_tree
        path=self.fixture.root/'untrusted.json'
        for text in ['[{"PID":1,"PID":2}]', '[{"Address":1e999}]', '[NaN]', '[{"__children":{}}]']:
            path.write_text(text)
            if '__children' in text:
                from volatility_mcp.saved_evidence import rows
                with self.assertRaises(EvidenceError):rows(load_tree(path),'volatility')
            else:
                with self.assertRaises(EvidenceError):load_tree(path)
        path.write_text(json.dumps([{'a':1}]))
        with patch('volatility_mcp.saved_evidence.MAX_NODES',1), self.assertRaises(EvidenceError):load_tree(path)
        with patch('volatility_mcp.saved_evidence.MAX_BYTES',1), self.assertRaises(EvidenceError):load_tree(path)
        self.create_run('wide',[{'PID':i,'Text':'x'*10000,'__children':[]} for i in range(20)])
        q=self.backend.query_output('example.raw','wide','json/stdout.json')
        self.assertTrue(q['truncated']);self.assertLess(q['returned_count'],20)
        self.assertEqual(q['matching_count'],20)
        for bad in [dict(filters=['not an object']),dict(sort=[None])]:
            with self.assertRaises(EvidenceError):self.query(**bad)
        self.create_run('typed-object',[{'Value':{'$integer':'4'},'__children':[]}])
        q=self.backend.query_output('example.raw','typed-object','json/stdout.json',
            filters=[{'field':'Value','op':'eq','type':'integer','value':4}])
        self.assertEqual(q['matching_count'],0)
        # Literal shell/SQL-looking text is data, not code or a query program.
        q=self.query(filters=[{'field':'Name','op':'eq','type':'string','value':"'; DROP TABLE x; $(id)"}])
        self.assertEqual(q['matching_count'],0)
        self.assertEqual(q['result_state'],'successful')

    def test_inspection_pe_strings_and_byte_references(self):
        case=self.backend.case_directory(self.fixture.image)
        binary=case/'runs/saved/json/synthetic.dmp';binary.write_bytes(synthetic_pe(dll=True))
        manifest=case/'runs/saved/manifest.json';m=json.loads(manifest.read_text());m['commands'][0]['artifacts'].append(file_fingerprint(binary));manifest.write_text(json.dumps(m))
        for operation in ['pe','strings']:
            folder=case/'inspections'/operation;folder.mkdir(parents=True)
            settings=dict(operation=operation,encoding='ascii',offset=0,scan_bytes=1024,min_length=4,limit=100,max_string_length=256)
            result=pe_headers(binary.read_bytes()) if operation=='pe' else strings_page(io.BytesIO(binary.read_bytes()),binary.stat().st_size,settings)
            path=folder/'result.json';path.write_text(json.dumps(result))
            meta={'source_ref':{'image_relative_path':'example.raw','run_id':'saved','artifact':'json/synthetic.dmp','sha256':file_fingerprint(binary)['sha256']},
                  'settings':settings,'parser':{'name':'synthetic fixture'},'integrity_verified':True,'result_sha256':file_fingerprint(path)['sha256'],
                  'status':'success','completed_at':now(),'source_run_status':'success'}
            (folder/'manifest.json').write_text(json.dumps(meta))
            q=self.backend.query_output('example.raw','inspection-'+operation,'result.json')
            if operation=='pe':
                ref=q['rows'][0]['reference'];ref['locator']['pointer']='/dll_flag'
                self.assertEqual(self.backend.get_evidence(ref,{'type':'boolean','value':True})['observable_validation'],'matched')
            else:
                row=next(r for r in q['rows'] if r['values']['text']=='HELLO_ASCII')
                ref=row['reference'];ref['locator']['pointer']=row['field_locators']['text']
                self.assertEqual(self.backend.get_evidence(ref,{'type':'string','value':'HELLO_ASCII'})['observable_validation'],'matched')
                self.assertEqual(row['values']['offset'],0x210)
                path.write_text(json.dumps({'records':[], 'truncated':True, 'next_offset':256}))
                meta['result_sha256']=file_fingerprint(path)['sha256']
                (folder/'manifest.json').write_text(json.dumps(meta))
                empty=self.backend.query_output('example.raw','inspection-strings','result.json')
                self.assertEqual(empty['result_state'],'saved_inspection_only')
                self.assertTrue(empty['inspection_page']['truncated'])
        _,source,_=resolve_source(self.backend,'example.raw','saved','json/synthetic.dmp')
        ref=reference(source,{'kind':'bytes','offset':0x210,'length':11,'encoding':'ascii'})
        self.assertEqual(self.backend.get_evidence(ref,{'type':'string','value':'HELLO_ASCII'})['observable_validation'],'matched')
        wide=reference(source,{'kind':'bytes','offset':0x240,'length':20,'encoding':'utf-16le'})
        self.assertEqual(self.backend.get_evidence(wide,{'type':'string','value':'WORLD_WIDE'})['observable_validation'],'matched')
        ref['locator']['offset']=99999
        with self.assertRaises(EvidenceError):self.backend.get_evidence(ref)




class SavedProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_twenty_queries_across_stdio_restart_zero_volatility_launches(self):
        fixture=SavedTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        config=fixture.fixture.root/'config.json';config.write_text(json.dumps(fixture.backend.config.to_dict()))
        transport=StdioServerParameters(command=sys.executable,args=['-m','volatility_mcp','serve','--config',str(config)])
        variants=[{}, {'fields':['PID']}, {'fields':['Address']},
            {'filters':[{'field':'PID','op':'gt','type':'integer','value':4}]},
            {'filters':[{'field':'Name','op':'starts_with','type':'string','value':'Child'}]},
            {'filters':[{'field':'Unknown','op':'eq','type':'null','value':None}]},
            {'group_by':['PID']}, {'sort':[{'field':'PID','type':'integer','direction':'desc'}]},
            {'limit':1}, {'offset':1,'limit':1}]
        ref=None
        for mode in ['legacy','auto']:
            async with Client(transport,mode=mode,read_timeout_seconds=20) as client:
                self.assertTrue({'query_output','get_evidence'} <= {t.name for t in (await client.list_tools()).tools})
                for options in variants:
                    result=decode_result(await client.call_tool('query_output',dict(image='example.raw',run_id='saved',**options)))
                    self.assertEqual(result['status'],'ok')
                    self.assertEqual(result['source_result']['source_status'],'success')
                if ref is None:ref=fixture.ref()
                result=decode_result(await client.call_tool('get_evidence',{'reference':ref,'observable':{'type':'integer','value':'0x4'}}))
                self.assertEqual(result['observable_validation'],'matched')
                invalid=await client.call_tool('get_evidence',{'reference':ref,'observable':{'type':'integer','value':99}})
                self.assertTrue(invalid.is_error)
        self.assertFalse(fixture.counter.exists(),'All fake Volatility interpreter launches, not just scans, are counted')
        self.assertFalse((fixture.fixture.root/'analysis-count.jsonl').exists())
