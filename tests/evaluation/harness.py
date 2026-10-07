"""Offline adapters exercise existing features, not a new forensic detector."""
from contextlib import contextmanager
from datetime import datetime, timezone
import copy
import hashlib
import io
import importlib.metadata
import platform
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from unittest.mock import patch

from volatility_mcp import __version__
from volatility_mcp.backend import VolatilityBackend, file_fingerprint, EvidenceError
from volatility_mcp.config import Config
from volatility_mcp.coverage import snapshot, set_plan
from volatility_mcp.inspect_worker import pe_headers, strings_page
from volatility_mcp.scoped import CaseBackend
from fixtures.synthetic_pe import synthetic_pe

ROOT=Path(__file__).parent
STAMP='2020-01-01 00:00:00Z'


@contextmanager
def offline_guard():
    counters={'subprocess_launches':0,'physical_volatility_invocations':0,'network_attempts':0}
    def no_process(*a,**kw):
        counters['subprocess_launches']+=1
        raise AssertionError('Offline replay forbids ALL subprocesses, including Volatility')
    def no_network(*a,**kw):
        counters['network_attempts']+=1
        raise AssertionError('Offline replay forbids network connections')
    with patch('subprocess.Popen',no_process),patch.object(socket.socket,'connect',no_network),patch('socket.create_connection',no_network):
        yield counters


class SavedFixture:
    def __init__(self, root):
        self.root=Path(root).resolve();self.evidence=self.root/'evidence';self.evidence.mkdir()
        self.image=self.evidence/'synthetic.raw';self.image.write_bytes(b'SYNTHETIC NOT A MEMORY ACQUISITION')
        self.config=Config(self.evidence,self.root/'outputs',Path(sys.executable),Path(sys.executable),cache_path=self.root/'cache',enable_xpnet=False)
        self.backend=VolatilityBackend(self.config)
        self.case=self.backend.case_directory(self.image)

    def run(self, rid, data, spec, plugin='windows.pslist.PsList',arguments=None):
        run=self.case/'runs'/rid;(run/'json').mkdir(parents=True)
        path=run/'json/stdout.json';path.write_text(spec.get('raw',json.dumps(data)))
        fp=file_fingerprint(self.image)
        record={'run_id':rid,'image':str(self.image),'image_relative_path':'synthetic.raw',
            'image_sha256_before':fp['sha256'],'image_sha256_after':fp['sha256'],'integrity_verified':True,
            'plugin':plugin,'arguments':arguments or [],'status':spec.get('status','unknown'),
            'started_at':f'2020-01-01 00:00:{int(rid[-1]):02}Z','completed_at':f'2020-01-01 00:01:{int(rid[-1]):02}Z',
            'volatility_version':'SYNTHETIC SAVED OUTPUT','volatility_python_version':'synthetic','mcp_sdk_version':'synthetic','server_version':'synthetic',
            'commands':[{'stdout_path':str(path),'argv':['SIMULATED; NEVER EXECUTED'],'returncode':spec.get('returncode'),
                'status':spec.get('status'), 'failure_category':spec.get('failure_category'),'artifacts':[file_fingerprint(path)]}]}
        if 'collection_complete' in spec:record['collection_complete']=spec['collection_complete']
        if spec.get('legacy'):record.update(commands=[],status='unknown',completed_at=None)
        if spec.get('missing'):path.unlink()
        (run/'manifest.json').write_text(json.dumps(record))
        return record


def run_scenario(s,tables,root):
    fixture=SavedFixture(root);backend=fixture.backend
    data=copy.deepcopy(tables[s['fixture']])*s.get('repeat',1)
    records=[]
    for i,spec in enumerate(s['runs']):records.append(fixture.run('run'+str(i),data,spec,s['image_scope']['plugin']))
    rid=records[-1]['run_id']
    if s.get('reuse'):
        folder=fixture.case/'reuse';folder.mkdir()
        (folder/'receipt.json').write_text(json.dumps({'reused':True,'integrity_verified':True,'run_id':rid,'requested_at':STAMP,'manifest_path':str(fixture.case/'runs'/rid/'manifest.json'),
            'image_before':file_fingerprint(fixture.image),'image_after':file_fingerprint(fixture.image)}))
    view=snapshot(backend,'synthetic.raw');entry=view['entries'][0]
    actual={**entry['effective'],**view['summary'],'execution':entry['effective']['execution'],
            'availability':entry['effective']['availability'],'attempt_count':len(entry['attempts']),'scope':view['scope']}
    if s.get('repeat'):
        q=backend.query_output('synthetic.raw',rid,'json/stdout.json',limit=1)
        actual['query_truncated']=q['truncated']
    behavior=s['behavior'];decision=None;unsupported=None
    if s.get('additional_fixture'):
        if s.get('separate_image'):
            other=fixture.evidence/'other.raw';other.write_text('SYNTHETIC SECOND IMAGE')
            original_image,original_case=fixture.image,fixture.case
            fixture.image=other;fixture.case=backend.case_directory(other)
            fixture.run('other9',tables[s['additional_fixture']],{'status':'success','returncode':0})
            fixture.image,fixture.case=original_image,original_case
            left=backend.query_output('synthetic.raw',rid,'json/stdout.json')['rows'][0]['values']['PID']
            right=backend.query_output('other.raw','other9','json/stdout.json')['rows'][0]['values']['PID']
            actual['same_pid']=left==right
            ref=backend.query_output('synthetic.raw',rid,'json/stdout.json')['rows'][0]['reference']
            scoped=CaseBackend(fixture.config,[str(other)])
            try:scoped.get_evidence(ref);actual['cross_image_rejected']=False
            except EvidenceError:actual['cross_image_rejected']=True
        else:
            fixture.run('extra9',tables[s['additional_fixture']],{'status':'success','returncode':0},'windows.pslist.PsList')
    if behavior=='query_lead':
        # The defined task is a literal query rule with a completeness precondition,
        # not a malware/injection/process-hiding classifier.
        if entry['effective']['execution']!='succeeded' or entry['effective']['availability'] not in ('rows_present','successfully_empty'):
            decision='abstain'
        else:
            q=backend.query_output('synthetic.raw',rid,'json/stdout.json',filters=[{'field':'Name','op':'eq','type':'string','value':'TRAINING_BEACON.exe'}])
            decision='lead' if q['matching_count'] else 'no_lead'
    elif behavior=='unsupported_detector':
        unsupported='No implemented detector for '+s['required_abstention']+'; observable/coverage contract only was checked.'
    elif behavior=='pe_observation':
        data=synthetic_pe(dll=True);data=data[:700] if s.get('pe_truncated') else data
        p=pe_headers(data);actual.update(pe_format=p.get('format'),dll_flag=p.get('dll_flag'),structural_status=p['structural_status'])
        values={}
        for encoding,name in [('ascii','ascii_text'),('utf-16le','wide_text')]:
            page=strings_page(io.BytesIO(data),len(data),dict(offset=0,scan_bytes=1024,min_length=4,limit=100,max_string_length=256,encoding=encoding))
            offset=0x210 if encoding=='ascii' else 0x240
            values[name]=next((r['text'] for r in page['records'] if r['offset']==offset),None)
        actual.update(values)
        decision='observation_only' if p['structural_status']=='declared_ranges_present' else 'limited_observation'
    elif behavior=='citation':
        ref=backend.query_output('synthetic.raw',rid,'json/stdout.json')['rows'][0]['reference'];ref['locator']['pointer']=s.get('pointer','/0/PID')
        try:
            r=backend.get_evidence(ref,{'type':'integer','value':s['claim']})
            actual.update(observable_validation=r['observable_validation'],interpretation_validation=r['interpretation_validation'],citation_rejected=False)
        except EvidenceError:actual['citation_rejected']=True
    elif behavior=='xp_addon':
        try:
            from test_xpnet import XpNetTests, allocation
            from volatility3.framework import constants
            from volatility3 import schemas
            cache=fixture.root/'xp-cache';cache.mkdir()
            with patch.object(constants,'CACHE_PATH',str(cache)), patch.object(schemas,'cached_validation_filepath',str(cache/'valid_isf.hashcache')), patch.object(schemas,'cached_validations',set()):
                test=XpNetTests();candidate=test.candidate(allocation())
            actual.update(candidate_kind=candidate['Kind'],candidate_pid=candidate['PID'])
        except (ImportError,__import__('unittest').SkipTest):unsupported='Separate official Volatility framework unavailable; XP decoder not evaluated.'
    if entry['effective']['availability'] in ('rows_present','successfully_empty'):
        source_ref=entry['attempts'][-1]['evidence'][0]['reference']
        source_ref['locator']['pointer']=s['expected_evidence_references'][0]['pointer']
        resolved=backend.get_evidence(source_ref)
        actual['reference_validation']=resolved['provenance_validation']
    expected=s['expected'];mismatches={k:{'expected':v,'actual':actual.get(k)} for k,v in expected.items() if actual.get(k)!=v}
    if behavior=='xp_addon' and unsupported:mismatches={}
    if 'expected_decision' in s and decision!=s['expected_decision']:
        mismatches['decision']={'expected':s['expected_decision'],'actual':decision}
    return {'scenario_id':s['id'],'status':'failed' if mismatches else 'unsupported' if unsupported else 'passed',
            'software_contract':'failed' if mismatches else 'passed','task':behavior,
            'actual':actual,'expected':expected,'decision':decision,'expected_decision':s.get('expected_decision'),
            'mismatches':mismatches,'unsupported_reason':unsupported,
            'forbidden_conclusions':s.get('forbidden_conclusions',[]),
            'semantic_validation':'not_evaluated; no free-form model reasoning or malware detector',
            'limitations':s['limitations']}


def evaluate():
    scenarios=json.loads((ROOT/'scenarios.json').read_text());fixtures=json.loads((ROOT/'fixtures.json').read_text())
    results=[]
    with offline_guard() as counters:
        with tempfile.TemporaryDirectory(prefix='synthetic-evaluation-') as temp:
            for s in scenarios['scenarios']:
                root=Path(temp)/s['id'];root.mkdir()
                try:results.append(run_scenario(s,fixtures['tables'],root))
                except Exception as exc:results.append({'scenario_id':s['id'],'status':'failed','task':s['behavior'],'error':str(exc)})
    rules=[r for r in results if r['task']=='query_lead' and 'decision' in r]
    metrics={'task':'Configured exact Name == TRAINING_BEACON.exe query; complete-source prerequisite',
        'evaluated':len(rules), 'false_positive_leads':sum(r['decision']=='lead' and r['expected_decision']=='no_lead' for r in rules),
        'missed_expected_leads':sum(r['decision']!='lead' and r['expected_decision']=='lead' for r in rules),
        'appropriate_abstentions':sum(r['decision']==r['expected_decision']=='abstain' for r in rules),
        'inappropriate_abstentions':sum(r['decision']=='abstain' and r['expected_decision']!='abstain' for r in rules),
        'precision_recall':'Not reported: tiny designed controls are not a forensic accuracy dataset.'}
    baseline=json.loads((ROOT/'baseline.json').read_text())
    baseline_ok=(len(results)==baseline['scenario_count'] and scenarios['version']==baseline['fixture_version'] and
        {r['scenario_id'] for r in results if r['status']=='unsupported'} in
        (set(baseline['required_unsupported_detectors']),set(baseline['required_unsupported_detectors'])|{baseline['optional_framework_scenario']}) and
        len(rules)==baseline['query_lead_controls'] and all(metrics[k]==baseline[k] for k in
        ('appropriate_abstentions','false_positive_leads','missed_expected_leads','inappropriate_abstentions')))
    packages={}
    for name in ('mcp','pefile','volatility3'):
        try:packages[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:packages[name]='not installed'
    source=Path(__file__).resolve().parents[2]/'src'/'volatility_mcp'
    implementation=hashlib.sha256()
    for p in sorted(source.rglob('*.py')):implementation.update(str(p.relative_to(source)).encode()+p.read_bytes())
    return {'schema':'forensic-evaluation-result/1','fixture_version':scenarios['version'],'baseline_status':'passed' if baseline_ok else 'failed',
        'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'python_version':platform.python_version(),'packages':packages,
        'fixture_sha256':hashlib.sha256((ROOT/'fixtures.json').read_bytes()).hexdigest(),
        'ground_truth_sha256':hashlib.sha256((ROOT/'scenarios.json').read_bytes()).hexdigest(),
        'implementation_version':__version__,'implementation_sha256':implementation.hexdigest(),
        'configuration':{'offline':True,'private_images':False,'model_calls':0,'rule':metrics['task']},
        'counts':{state:sum(r['status']==state for r in results) for state in ('passed','unsupported','skipped','failed')},
        'invocations':counters,'lead_task_metrics':metrics,'scenarios':results,
        'limitations':['Synthetic contract/observation replay is not real-world forensic accuracy.',
                      'Unsupported detectors receive no detection credit. No free-form model reasoning is evaluated.',
                      'Saved physical command counts are fixture history, not replay invocation counts.']}


def human(result):
    lines=['# Synthetic offline forensic evaluation',str(result['counts']),'Reviewed baseline: '+result['baseline_status'],
           'Physical Volatility invocations during replay: '+str(result['invocations']['physical_volatility_invocations']),
           'All subprocess launches attempted: '+str(result['invocations']['subprocess_launches']),
           '', '| Scenario | Outcome | Actual versus expected |','|---|---|---|']
    for r in result['scenarios']:
        detail=r.get('error') or r.get('unsupported_reason') or str(r.get('mismatches') or 'Defined contract matched')
        lines.append(f"| {r['scenario_id']} | {r['status']} | {detail} |")
    lines.extend(['',json.dumps(result['lead_task_metrics'],indent=2),*result['limitations']])
    return '\n'.join(lines)+'\n'
