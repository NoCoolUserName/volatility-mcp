"""Offline coverage/state contracts and real stdio calls on harmless saved data."""
import asyncio
import copy
import dataclasses
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.backend import VolatilityBackend, EvidenceError, file_fingerprint
from volatility_mcp.coverage import snapshot, set_plan, job_view
from volatility_mcp.cli import decode_result
from volatility_mcp.ui.storage import Bundle, now
from volatility_mcp.reporting import check_bundle
from evaluation.harness import SavedFixture, offline_guard, evaluate


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.f=SavedFixture(self.tmp.name);self.b=self.f.backend
        self.data=[{'PID':4,'Name':'System','__children':[]}]
    def plan(self,args=None):
        return {'profile':'Requested process examination','entries':[{'id':'processes','question':'Which processes were observed?',
            'plugin':'windows.pslist.PsList','arguments':args or []}]}
    def test_scope_idempotence_restart_and_distinct_filters(self):
        with offline_guard() as counts:
            self.assertEqual(self.b.get_coverage('synthetic.raw')['scope'],'unspecified')
            first=set_plan(self.b,'synthetic.raw',self.plan())
            again=set_plan(self.b,'synthetic.raw',self.plan());self.assertTrue(again['reused'])
            self.assertEqual(first['plan_id'],again['plan_id'])
            self.f.run('run0',self.data,{'status':'error','returncode':1})
            self.f.run('run1',self.data,{'status':'success','returncode':0})
            self.f.run('run2',self.data,{'status':'success','returncode':0},arguments=['--pid','99'])
            before={p:p.read_bytes() for p in self.f.case.rglob('*') if p.is_file()}
            a=self.b.get_coverage('synthetic.raw');b=VolatilityBackend(self.f.config).get_coverage('synthetic.raw')
            self.assertEqual(a,b);self.assertEqual(len(a['entries']),2)
            self.assertEqual(a['entries'][0]['attempt_count'],2)
            self.assertEqual(a['entries'][0]['effective']['run_id'],'run1')
            self.assertEqual(a['summary']['declared_plan_entries'],1)
            self.assertEqual(a['summary']['entries_with_successful_collection'],1)
            self.assertEqual(before,{p:p.read_bytes() for p in before})
            changed=set_plan(self.b,'synthetic.raw',self.plan(['--pid','100']))
            self.assertEqual(changed['previous'],first['plan_id'])
            view=self.b.get_coverage('synthetic.raw')
            self.assertEqual(view['entries'][0]['effective']['execution'],'not_run')
        self.assertEqual(counts['subprocess_launches'],0)
    def test_states_missing_metadata_integrity_and_delivery(self):
        for i,state in enumerate(['queued','running','cancelled','interrupted','timeout']):
            self.f.run('run'+str(i),self.data,{'status':state,'returncode':None},arguments=['--pid',str(i)])
        q=self.b.get_coverage('synthetic.raw',limit=1)
        self.assertTrue(q['delivery']['truncated'])
        executions={e['effective']['execution'] for e in snapshot(self.b,'synthetic.raw')['entries']}
        self.assertEqual(executions,{'queued','running','cancelled','interrupted','timed_out'})
        jobs=job_view([{'id':'j','kind':'report','status':'incomplete','case_id':'c'}],'c')
        self.assertEqual(jobs[0]['execution'],'interrupted')
        self.assertEqual(job_view([{'id':'j','kind':'report','status':'completed','case_id':'other'}],'c'),[])
        self.f.run('run5',self.data,{'status':'success','returncode':0})
        path=self.f.case/'runs/run5/json/stdout.json';path.write_text('[]')
        view=self.b.get_coverage('synthetic.raw')
        entry=next(e for e in view['entries'] if e['arguments']==[])
        self.assertEqual(entry['effective']['availability'],'unavailable')
        self.assertIn('integrity_error',entry['effective']['reason_codes'])
    def test_plan_validation_case_boundaries_and_attempt_pagination(self):
        for bad in [dict(profile='p',entries=[{'id':'x'}]),dict(profile='p',entries=[] ,unexpected=1)]:
            with self.assertRaises(EvidenceError):set_plan(self.b,'synthetic.raw',bad)
        with self.assertRaises(EvidenceError):self.b.get_coverage('../escape.raw')
        for i in range(3):self.f.run('run'+str(i),self.data,{'status':'success','returncode':0})
        q=self.b.get_coverage('synthetic.raw',attempt_limit=1)
        self.assertEqual(q['entries'][0]['attempt_next_offset'],1)
        q=self.b.get_coverage('synthetic.raw',entry_id=q['entries'][0]['entry_id'],attempt_offset=1,attempt_limit=1)
        self.assertEqual(q['entries'][0]['attempts'][0]['run_id'],'run1')
        other=self.f.evidence/'other.raw';other.write_text('SYNTHETIC')
        self.assertEqual(self.b.get_coverage('other.raw')['summary']['saved_attempts'],0)
        outside=self.f.root/'outside';outside.write_text('{}')
        (self.f.case/'runs/run0/manifest.json').unlink();(self.f.case/'runs/run0/manifest.json').symlink_to(outside)
        self.assertTrue(self.b.get_coverage('synthetic.raw')['issues'])
    def test_saved_report_coverage_zero_analysis(self):
        self.f.case=self.f.root/'ui'/'case'/'analysis'/self.f.case.name
        self.b=VolatilityBackend(dataclasses.replace(self.f.config,output_root=self.f.case.parent));self.f.backend=self.b
        self.f.run('run0',[],{'status':'success','returncode':0})
        set_plan(self.b,'synthetic.raw',self.plan(['--pid','99']))
        image={'id':'E001',**file_fingerprint(self.f.image)}
        case={'id':'case','images':[image],'notes':{}}
        version={'id':'revision','status':'draft','created_at':now()}
        bundle=Bundle(self.f.root/'ui/case',case,version,coverage_backend=self.b)
        with offline_guard() as counts:
            m=bundle.prepare();a=next(a for a in m['artifacts'] if a['path'].endswith('stdout.json'))
            text='\n\n'.join(['## Executive summary','F1: Synthetic empty scope only.','## Scope','Synthetic.',
                '## Technical findings','F1: Empty saved output.','## Investigative workflow','Saved only.','## Limitations','Unknowns remain.','## IOCs','None.'])
            result=bundle.save(text,[{'finding_id':'F1','evidence_refs':[{'artifact_id':a['artifact_id'],'locator':'empty array'}]}],[])
            self.assertEqual(result['status'],'valid')
            # A changed derived count cannot override the original empty table,
            # even when its artifact hash is mechanically updated.
            coverage_path=bundle.root/'coverage.json';coverage=json.loads(coverage_path.read_text())
            attempt=next(e for e in coverage['images'][0]['entries'] if e['attempts'])['attempts'][0]
            attempt.update(availability='rows_present',row_count=1)
            coverage_path.write_text(json.dumps(coverage))
            mp=bundle.root/'case-manifest.json';record=json.loads(mp.read_text());fp=file_fingerprint(coverage_path)
            next(a for a in record['artifacts'] if a['artifact_id']=='coverage-snapshot').update(sha256=fp['sha256'],size_bytes=fp['size_bytes'])
            mp.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,'row count contradicts'):check_bundle(bundle.root)
            # An explicitly extended plan after saving changes the authoritative
            # snapshot. Sealing refreshes only its mechanical limitations block.
            plan=self.plan(['--pid','99'])
            plan['entries'].append({'id':'another-scope','question':'Synthetic second scope',
                                    'plugin':'windows.pslist.PsList','arguments':['--pid','100']})
            set_plan(self.b,'synthetic.raw',plan)
            bundle.seal({'E001':image});before=(bundle.root/'report.md').read_bytes()
            self.assertIn(b'2 recorded scopes have missing/partial/unknown results',before)
            self.assertIn(b'F1: Empty saved output.',before)
            self.assertEqual(before.count(b'<!-- coverage-summary -->'),1)
            self.assertEqual(check_bundle(bundle.root)['status'],'valid')
            self.assertEqual(before,(bundle.root/'report.md').read_bytes())
        self.assertEqual(counts['subprocess_launches'],0)
    def test_offline_baseline(self):
        result=evaluate()
        self.assertEqual(result['counts']['failed'],0,result)
        self.assertEqual(result['baseline_status'],'passed')
        self.assertEqual(result['counts']['skipped'],0)
        self.assertEqual(result['invocations']['subprocess_launches'],0)
        self.assertEqual(result['lead_task_metrics']['false_positive_leads'],0)
        self.assertEqual(result['lead_task_metrics']['appropriate_abstentions'],3)


class CoverageProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_mcp_restart_import_no_launches(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture=SavedFixture(tmp);fixture.run('run0',[],{'status':'success','returncode':0})
            config=fixture.root/'config.json';config.write_text(json.dumps(fixture.config.to_dict()))
            # Client process itself is necessary; forbid every analyzer subprocess in server.
            code='''
import sys,subprocess
from volatility_mcp.config import load_config
from volatility_mcp.server import create_server
def forbidden(*args,**kwargs):raise AssertionError('Analysis subprocess forbidden')
subprocess.Popen=forbidden
create_server(load_config(sys.argv[1])).run(transport='stdio')
'''
            previous=None
            for mode in ['legacy','auto']:
                async with Client(StdioServerParameters(command=sys.executable,args=['-c',code,str(config)]),mode=mode,read_timeout_seconds=20) as client:
                    self.assertIn('get_coverage',{t.name for t in (await client.list_tools()).tools})
                    q=decode_result(await client.call_tool('get_coverage',{'image':'synthetic.raw'}))
                    self.assertEqual(q['entries'][0]['effective']['availability'],'successfully_empty')
                    if previous:self.assertEqual(q,previous)
                    previous=q
                    self.assertTrue((await client.call_tool('get_coverage',{'image':'../outside.raw'})).is_error)
