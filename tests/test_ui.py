"""Optional UI tests: real local HTTP/MCP, simulated Codex and harmless images."""
import asyncio
import dataclasses
import hashlib
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from volatility_mcp.ui.app import Workbench
from volatility_mcp.ui.http import Server
from volatility_mcp.ui.scoped_mcp import CaseBackend
from volatility_mcp.ui.storage import Bundle, read_chunk
import test_backend

PROJECT=Path(__file__).resolve().parents[1]


def report_text(path,aid):
    return '\n'.join(['# SYNTHETIC UI TEST — NOT A REAL INVESTIGATION','## Executive summary',
        'F001: Simulated analyzer result. ['+aid+']('+path+')',
        '## Scope and evidence','Harmless synthetic fixture; no malware.',
        '## Reconstructed event timeline','No real incident timeline.',
        '## Technical findings','F001: Synthetic fixture only.',
        '## Investigative workflow and coverage','See investigation.jsonl.',
        '## Limitations and unresolved questions','Simulated Codex, no forensic conclusion.',
        '## Hunting content','Not justified for synthetic fixture.',
        '## Reproduction and references','Synthetic local test.',
        '## IOC appendix','No indicators.'])


class FakeCodex:
    def __init__(self,event,request):
        self.event,self.request=event,request
        self.proc=type('Process',(),{'returncode':None})()
        self.calls=[]
        self.threads=0
        self.tasks=[]
        self.turn=0
    async def start(self):pass
    async def close(self):
        for t in self.tasks:t.cancel()
        await asyncio.gather(*self.tasks,return_exceptions=True)
    async def call(self,method,params=None,timeout=120):
        params=params or {};self.calls.append((method,params))
        if method=='account/read':return {'account':{'type':'chatgpt'},'requiresOpenaiAuth':True}
        if method in ('thread/start','thread/resume'):
            self.threads+=1
            return {'thread':{'id':params.get('threadId','synthetic-thread-'+str(self.threads))},
                    'approvalPolicy':'on-request','approvalsReviewer':'user','sandbox':{'type':'readOnly'}}
        if method=='turn/start':
            self.turn+=1;tid=str(self.turn)
            self.tasks.append(asyncio.create_task(self.finish(params,tid)))
            return {'turn':{'id':tid}}
        if method=='turn/interrupt':
            for task in self.tasks:task.cancel()
            await self.event('turn/completed',{'threadId':params['threadId'],'turn':{'id':params['turnId'],'status':'interrupted'}})
            return {}
        raise ValueError(method)
    async def finish(self,params,tid):
        await asyncio.sleep(.02)
        text=params['input'][0]['text']
        if 'WAIT_FOR_STOP' in text:
            await asyncio.sleep(30)
        if 'Generate and save' in text or 'Explicitly update' in text:
            async def tool(name,args):
                result=await self.request({'method':'item/tool/call','id':tid+name,'params':{'threadId':params['threadId'],'turnId':tid,'tool':name,'arguments':args}})
                if not result['success']:raise ValueError(result)
                return json.loads(result['contentItems'][0]['text'])
            context=await tool('case_report_context',{})
            a=context['manifest']['artifacts'][0]
            await tool('case_save_report',{'markdown':report_text(a['path'],a['artifact_id']),
                'findings':[{'finding_id':'F001','evidence_refs':[{'artifact_id':a['artifact_id'],'locator':'synthetic test record'}]}],'iocs':[]})
        await self.event('item/completed',{'threadId':params['threadId'],'item':{'type':'agentMessage','id':tid,'text':'Synthetic response; no real investigation.'}})
        await self.event('turn/completed',{'threadId':params['threadId'],'turn':{'id':tid,'status':'completed'}})


class UITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture=test_backend.BackendTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config=self.fixture.root/'config.json'
        self.config.write_text(json.dumps(self.fixture.config.to_dict()))
        self.app=Workbench(self.config,self.fixture.root/'ui',PROJECT,codex_factory=FakeCodex)
        await self.app.start()
        self.case=self.app.add([str(self.fixture.image)])[0]
    async def asyncTearDown(self):await self.app.close()
    async def wait_job(self,job):
        for _ in range(150):
            if job['status'] not in ('queued','running','stopping'):return job
            await asyncio.sleep(.05)
        self.fail('Job did not finish: '+str(job))
    async def ready(self):
        job=self.app.enqueue(self.case['id'],'readiness')
        await self.wait_job(job)
        self.assertEqual(job['status'],'completed',job)
        self.assertIn(self.case['readiness']['status'],('Ready','Ready with limitations'))
    async def test_stage_a_readiness_report_evidence(self):
        await self.ready()
        before=self.fixture.image.read_bytes()
        job=self.app.enqueue(self.case['id'],'report')
        await self.wait_job(job)
        self.assertEqual(job['status'],'completed',job)
        report=self.case['reports'][0]
        self.assertEqual(report['status'],'sealed')
        manifest=json.loads((self.app.directory(self.case)/'reports'/report['id']/'case-manifest.json').read_text())
        self.assertTrue(manifest['artifacts'])
        self.assertTrue(all(r['image_id']=='E001' for r in manifest['runs']))
        self.assertEqual(self.fixture.image.read_bytes(),before)
        a=manifest['artifacts'][0]
        data=self.app.read_file(self.case,'reports/'+report['id']+'/'+a['path'])
        self.assertTrue(data['text'])
    async def test_stage_b_continuity_and_immutable_revision(self):
        await self.ready()
        first=self.app.enqueue(self.case['id'],'report');await self.wait_job(first)
        self.assertEqual(first['status'],'completed',first)
        report=self.case['reports'][0];path=self.app.directory(self.case)/'reports'/report['id']/'SHA256SUMS'
        original=path.read_bytes();thread=self.case['thread_id']
        question=self.app.enqueue(self.case['id'],'question','Explain F001');await self.wait_job(question)
        self.assertEqual(len(self.case['reports']),1)
        update=self.app.enqueue(self.case['id'],'update');await self.wait_job(update)
        self.assertEqual(update['status'],'completed',update)
        self.assertEqual(self.case['thread_id'],thread)
        self.assertEqual(path.read_bytes(),original)
        self.assertEqual(self.case['reports'][1]['previous'],report['id'])
        with self.assertRaises(ValueError):Bundle(self.app.directory(self.case),self.case,report).prepare()
    async def test_duplicate_submission_and_stop_queue(self):
        job=self.app.enqueue(self.case['id'],'question','WAIT_FOR_STOP','request-1')
        self.assertIs(self.app.enqueue(self.case['id'],'question','WAIT_FOR_STOP','request-1'),job)
        second=self.app.add([str(self.fixture.image)])[0]
        queued=self.app.enqueue(second['id'],'readiness')
        for _ in range(100):
            if job.get('turn_id'):break
            await asyncio.sleep(.02)
        await self.app.stop();await self.wait_job(job)
        self.assertEqual(queued['status'],'cancelled')
        self.assertNotEqual(job['status'],'completed')
    async def test_readiness_cancel_keeps_source_and_partial_record(self):
        self.fixture.image.write_text('timeout')
        job=self.app.enqueue(self.case['id'],'readiness')
        for _ in range(100):
            if list(self.app.directory(self.case).glob('analysis/*/runs/*/manifest.json')):break
            await asyncio.sleep(.03)
        await self.app.stop();await self.wait_job(job)
        self.assertEqual(job['status'],'incomplete')
        self.assertEqual(self.fixture.image.read_text(),'timeout')
    async def test_case_scope_grouping_and_paths(self):
        other=self.fixture.evidence/'other.raw';other.write_text('normal')
        cases=self.app.add([str(self.fixture.image),str(other)])
        self.assertEqual(len(cases),2)
        related=self.app.add([str(self.fixture.image),str(other)],True)[0]
        self.assertEqual(len(related['images']),2)
        backend=CaseBackend(self.fixture.config,[str(self.fixture.image)])
        with self.assertRaises(ValueError):backend.resolve_input(str(other))
        link=self.fixture.evidence/'escape.raw';link.symlink_to(other)
        for p in ('../outside.raw',str(link)):
            with self.assertRaises(ValueError):self.app.add([p])
        for p in ('../config.json','/etc/passwd','mcp.json'):
            with self.assertRaises(ValueError):self.app.read_file(self.case,p)
        with self.assertRaises(ValueError):self.app.browse('../')
    async def test_reopen_marks_interrupted_without_restart(self):
        case=self.case;case['thread_id']='saved-thread'
        self.app.state['jobs'].append({'id':'lost','case_id':case['id'],'status':'running','kind':'question'})
        self.app.save()
        reopened=Workbench(self.config,self.app.root,PROJECT,codex_factory=FakeCodex)
        self.assertEqual(reopened.state['jobs'][-1]['status'],'incomplete')
        self.assertTrue(reopened.queue.empty())
        await reopened.ensure_thread(reopened.case(case['id']))
        self.assertTrue(any(c[0]=='thread/resume' for c in reopened.agent.calls))
        await reopened.agent.close()
    async def test_unsupported_approval_and_explicit_decision(self):
        self.case['thread_id']='thread';self.app.active={'case_id':self.case['id']}
        with self.assertRaises(ValueError):
            await self.app.agent_request({'method':'unknownApproval','params':{'threadId':'thread'}})
        task=asyncio.create_task(self.app.agent_request({'method':'item/commandExecution/requestApproval','params':{'threadId':'thread','command':'synthetic command'}}))
        await asyncio.sleep(.01)
        pending=next(iter(self.app.approvals.values()))
        self.assertFalse(task.done())
        pending['future'].set_result('decline')
        self.assertEqual(await task,{'decision':'decline'})
        self.app.active=None
    async def test_report_failure_and_changed_evidence_not_complete(self):
        await self.ready()
        self.fixture.image.write_text('changed')
        job=self.app.enqueue(self.case['id'],'report');await self.wait_job(job)
        self.assertEqual(job['status'],'failed')
        self.assertIn('changed',job['error'])
    async def test_http_origin_auth_and_preview_boundaries(self):
        server=Server(self.app,0,asyncio.get_running_loop())
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(path,data=None,headers=None):
            h={'Content-Type':'application/json',**(headers or {})}
            req=urllib.request.Request(server.origin+path,data=json.dumps(data).encode() if data is not None else None,headers=h)
            try:
                with urllib.request.urlopen(req,timeout=5) as r:return r.status,r.read(),r.headers
            except urllib.error.HTTPError as e:return e.code,e.read(),e.headers
        try:
            status,_,_=await asyncio.to_thread(request,'/api/state');self.assertEqual(status,403)
            status,_,_=await asyncio.to_thread(request,'/api/unlock',{'token':server.token},{'Origin':'https://evil.example'});self.assertEqual(status,403)
            status,_,headers=await asyncio.to_thread(request,'/api/unlock',{'token':server.token},{'Origin':server.origin});self.assertEqual(status,200)
            cookie=headers['Set-Cookie'].split(';')[0]
            self.assertIn('HttpOnly',headers['Set-Cookie'])
            status,body,_=await asyncio.to_thread(request,'/api/state',None,{'Cookie':cookie});self.assertEqual(status,200)
            self.assertEqual(len(json.loads(body)['cases']),1)
            status,_,_=await asyncio.to_thread(request,'/api/stop',{}, {'Cookie':cookie});self.assertEqual(status,403)
            status,_,_=await asyncio.to_thread(request,'/api/state',None,{'Cookie':cookie,'Host':'evil.example'});self.assertEqual(status,403)
            for _ in range(2):await asyncio.to_thread(request,'/api/state',None,{'Cookie':cookie})
            self.assertEqual(len(self.app.state['jobs']),0)
        finally:
            await asyncio.to_thread(server.shutdown);server.server_close()

    async def test_bundle_rejects_run_from_changed_source(self):
        await self.ready()
        path=next(self.app.directory(self.case).glob('analysis/*/runs/*/manifest.json'))
        record=json.loads(path.read_text());record['image_sha256_before']='0'*64;path.write_text(json.dumps(record))
        from volatility_mcp.ui.storage import now
        report={'id':'draft','status':'draft','created_at':now()}
        with self.assertRaisesRegex(ValueError,'integrity/identity'):
            Bundle(self.app.directory(self.case),self.case,report).prepare()
    async def test_missing_symbols_is_limitation_not_clean(self):
        self.fixture.image.write_text('error')
        await self.ready()
        self.assertEqual(self.case['readiness']['status'],'Ready with limitations')
        self.assertTrue(any('error' in r for r in self.case['readiness']['reasons']))
    async def test_oversized_and_symlink_artifact_reads(self):
        folder=self.app.directory(self.case)/'analysis';folder.mkdir()
        (folder/'large.txt').write_text('x'*100000)
        result=self.app.read_file(self.case,'analysis/large.txt')
        self.assertTrue(result['truncated']);self.assertEqual(result['next_offset'],32768)
        (folder/'escape.txt').symlink_to(self.config)
        with self.assertRaises(ValueError):self.app.read_file(self.case,'analysis/escape.txt')
    async def test_effective_policy_override_blocks(self):
        class Overridden(FakeCodex):
            async def call(self,method,params=None,timeout=120):
                r=await super().call(method,params,timeout)
                if method=='thread/start':r['approvalPolicy']='never'
                return r
        self.app.factory=Overridden
        with self.assertRaisesRegex(Exception,'approval settings differ'):
            await self.app.ensure_thread(self.case)

    async def test_volatility_preauthorized_on_start_and_resume(self):
        await self.app.ensure_thread(self.case)
        self.app.loaded_threads.clear()
        await self.app.ensure_thread(self.case)
        calls=[(method,params) for method,params in self.app.agent.calls
               if method in ('thread/start','thread/resume')]
        self.assertEqual([method for method,_ in calls],['thread/start','thread/resume'])
        for _,params in calls:
            settings=params['config']
            self.assertEqual(settings['mcp_servers.volatility']['default_tools_approval_mode'],'approve')
            self.assertEqual(params['sandbox'],'read-only')
            self.assertFalse(settings['features.shell_tool'])
        self.assertFalse(self.app.approvals)
    async def test_report_creation_requires_explicit_job(self):
        self.app.active={'case_id':self.case['id'],'kind':'question'}
        with self.assertRaisesRegex(ValueError,'explicit'):
            self.app.dynamic(self.case,'case_report_context',{})
        self.app.active=None


    async def test_mcp_form_requires_explicit_valid_approval(self):
        self.case['thread_id']='thread';self.app.active={'case_id':self.case['id']}
        request={'method':'mcpServer/elicitation/request','params':{'threadId':'thread','serverName':'volatility','mode':'form','message':'Approve synthetic analysis?', 'requestedSchema':{'type':'object','properties':{'approved':{'type':'boolean'}},'required':['approved']}}}
        task=asyncio.create_task(self.app.agent_request(request))
        await asyncio.sleep(.01)
        self.assertFalse(task.done())
        next(iter(self.app.approvals.values()))['future'].set_result({'action':'accept','content':{'approved':True}})
        self.assertEqual(await task,{'action':'accept','content':{'approved':True}})
        request['params']['mode']='url'
        self.assertEqual((await self.app.agent_request(request))['action'],'decline')
        self.app.active=None

    async def test_failed_mcp_request_preserved_without_fake_run(self):
        await self.ready()
        self.app.event(self.case,'item/completed',{'type':'mcpToolCall','tool':'run_plugin','status':'failed','arguments':{'plugin':'synthetic'},'error':{'message':'user rejected MCP tool call'}})
        from volatility_mcp.ui.storage import now
        report={'id':'draft','status':'draft','created_at':now()}
        manifest=Bundle(self.app.directory(self.case),self.case,report).prepare()
        failed=[a for a in manifest['artifacts'] if a['run_id'] is None]
        self.assertEqual(len(failed),1)
        self.assertIn('user rejected', (self.app.directory(self.case)/'reports/draft'/failed[0]['path']).read_text())

    async def test_stop_during_turn_start_interrupts_accepted_turn(self):
        class SlowStart(FakeCodex):
            async def call(self,method,params=None,timeout=120):
                result=await super().call(method,params,timeout)
                if method=='turn/start':await asyncio.sleep(.2)
                return result
        self.app.factory=SlowStart
        job=self.app.enqueue(self.case['id'],'question','WAIT_FOR_STOP')
        for _ in range(100):
            if self.app.agent and any(c[0]=='turn/start' for c in self.app.agent.calls):break
            await asyncio.sleep(.01)
        await self.app.stop();await self.wait_job(job)
        self.assertEqual(job['status'],'incomplete',job)
        self.assertTrue(any(c[0]=='turn/interrupt' for c in self.app.agent.calls))

if __name__=='__main__':unittest.main()
