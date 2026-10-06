"""Coverage is a projection of saved evidence and explicit scope, never a scheduler."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from .backend import EvidenceError, file_fingerprint, write_json
from .saved_evidence import load_tree, rows, resolve_source, reference, require
from .timestamps import utc_now, timestamped_id

SCHEMA = 'coverage/1'
MAX_RECORDS = 2000
MAX_READ_BYTES = 256 * 1024 * 1024
APPLICABILITY = {'applicable','not_applicable','unsupported','blocked_prerequisites','unknown'}


def key(plugin, arguments):
    # Exact arguments intentionally preserve distinct PID/address/filter scopes.
    return hashlib.sha256(json.dumps([plugin, arguments], sort_keys=True).encode()).hexdigest()[:24]


def read_record(backend, path):
    backend._check_components(path)
    require(path.is_file() and path.stat().st_size <= 4*1024*1024, 'Coverage manifest exceeds 4 MiB or is missing')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'Coverage record must be an object')
    return value


def plans(backend, case):
    paths = list((case/'coverage'/'plans').glob('*.json'))
    require(len(paths) <= MAX_RECORDS, 'Too many coverage plan revisions')
    return sorted([read_record(backend,p) for p in paths], key=lambda p:(p['declared_ns'],p['plan_id']))


def set_plan(backend, image, plan, declared_by='operator'):
    """Explicit metadata edit only; identical latest plans are idempotent."""
    path = backend.resolve_input(image)
    require(isinstance(plan, dict) and set(plan)=={'profile','entries'}, 'Plan requires profile and entries')
    require(isinstance(plan['profile'],str) and 0<len(plan['profile'])<=500, 'Invalid plan profile')
    require(isinstance(plan['entries'],list) and len(plan['entries'])<=100, 'Plan limit is 100 entries')
    ids=set()
    for e in plan['entries']:
        require(isinstance(e,dict) and {'id','question','plugin','arguments'}<=e.keys() and
                set(e)<={'id','question','plugin','arguments','applicability','reason'}, 'Invalid plan entry fields')
        require(all(isinstance(e[k],str) and 0<len(e[k])<=2000 for k in ('id','question','plugin')), 'Plan strings must be bounded and nonempty')
        require(e['id'] not in ids, 'Duplicate plan entry ID');ids.add(e['id'])
        require(isinstance(e['arguments'],list) and len(e['arguments'])<=100 and
                all(isinstance(v,str) and len(v)<=4096 for v in e['arguments']), 'Invalid planned argument list')
        require(e.get('applicability','unknown') in APPLICABILITY, 'Invalid declared applicability')
        require(isinstance(e.get('reason',''),str) and len(e.get('reason',''))<=2000, 'Invalid applicability reason')
        if e.get('applicability','unknown')!='unknown':require(bool(e.get('reason')), 'Declared applicability needs a reason')
    require(len(json.dumps(plan))<=60000, 'Plan exceeds 60 KB')
    case=backend.case_directory(path); prior=plans(backend,case)
    if prior and prior[-1]['plan']==plan:return {**prior[-1],'reused':True}
    folder=backend._safe_directory(case/'coverage'/'plans')
    record={'schema':SCHEMA,'plan_id':timestamped_id(),'declared_at':utc_now(),'declared_ns':time.time_ns(),
            'declared_by':declared_by,'image':str(path.relative_to(backend.cases)),
            'previous':prior[-1]['plan_id'] if prior else None,'plan':plan}
    write_json(folder/(record['plan_id']+'.json'),record)
    return {**record,'reused':False}


def execution(record, inspection=False):
    status=record.get('status')
    commands=record.get('commands',[])
    codes=[c.get('returncode') for c in commands]
    if status in ('queued','running','cancelled','interrupted'):return status
    if status in ('timeout','timed_out'):return 'timed_out'
    if status in ('error','failed','evidence_changed','unsupported'):return 'failed'
    if any(c is not None and c!=0 for c in codes):return 'failed'
    if status in ('success','output_error') and record.get('completed_at'):
        if inspection or codes and all(c==0 for c in codes):return 'succeeded'
    return 'unknown'


def attempt(backend, image, manifest, record, budget):
    inspection=manifest.parent.parent.name=='inspections'
    rid=('inspection-' if inspection else '')+manifest.parent.name
    if inspection:
        require(record.get('source_ref',{}).get('image_relative_path')==image, 'Inspection belongs to another image')
        plugin='inspect_artifact'
        args={'source_ref':record.get('source_ref'), 'settings':record.get('settings')}
    else:
        require(record.get('image')==str(backend.resolve_input(image)), 'Run belongs to another image')
        require(record.get('run_id')==rid, 'Run identity disagrees with directory')
        plugin=record.get('plugin','unknown');args=record.get('arguments')
    commands=record.get('commands',[])
    reasons=list(dict.fromkeys(c['failure_category'] for c in commands if c.get('failure_category')))
    if record.get('failure_category'):reasons.append(record['failure_category'])
    ex=execution(record,inspection)
    app='unknown'
    if any(r.startswith('unsupported') for r in reasons) or record.get('status')=='unsupported':app='unsupported'
    elif any(r in ('missing_symbols_or_layer','missing_prerequisite') for r in reasons):app='blocked_prerequisites'
    elif ex=='succeeded':app='applicable'
    if ex=='unknown':reasons.append('insufficient_execution_metadata')
    if ex=='running':reasons.append('liveness_unverified')
    result={'attempt_id':rid,'run_id':rid,'plugin':plugin,'arguments':args,
            'kind':'inspection' if inspection else 'analysis','execution':ex,'applicability':app,
            'availability':'unknown','row_count':None,'source_status':record.get('status','unknown'),
            'integrity_verified':record.get('integrity_verified') is True,
            'started_at':record.get('started_at'),'finished_at':record.get('completed_at'),
            'manifest':str(manifest.relative_to(backend.outputs)), 'reason_codes':reasons,
            'evidence':[], 'limitations':['Successful execution alone does not answer the investigative question.'],
            'physical_commands_recorded':0 if inspection else sum(c.get('returncode') is not None for c in commands)}
    error=record.get('error') or next((c.get('error') for c in commands if c.get('error')),None)
    if error:result['failure_reason']=str(error)[:2000]
    if inspection:
        artifact='result.json';kind=record.get('settings',{}).get('operation')
    else:
        output=next((c.get('stdout_path') for c in commands if c.get('stdout_path')),None)
        if not output:
            result['reason_codes'].append('output_identity_unrecorded');return result
        candidate=Path(output)
        require(candidate.is_relative_to(manifest.parent), 'Recorded stdout escapes its run')
        artifact=str(candidate.relative_to(manifest.parent));kind='volatility'
    try:
        path=manifest.parent/artifact
        backend._check_components(path)
        if not path.exists():
            result.update(availability='unavailable');reasons.append('missing_output');return result
        budget[0]+=path.stat().st_size
        if budget[0]>MAX_READ_BYTES:
            result['reason_codes'].append('coverage_read_budget');return result
        path,source,state=resolve_source(backend,image,rid,artifact)
        result['evidence']=[{'path':str(path.relative_to(backend.outputs)),
                             'reference':reference(source,{'kind':'json','pointer':''})}]
        before=file_fingerprint(path)
        data=load_tree(path);count=len(rows(data,kind))
        require(file_fingerprint(path)==before, 'Output changed while deriving coverage')
        result['row_count']=count
        complete=(ex=='succeeded' and record.get('status')=='success' and state['integrity_verified'])
        partial=record.get('collection_complete') is False or any(c.get('collection_complete') is False for c in commands)
        if inspection:
            result['limitations'].append('Static inspection describes saved bytes, not memory-image coverage.')
            if kind=='strings':
                partial=partial or data.get('truncated',False) or data.get('text_truncated',False)
                result['inspection_window']={k:data.get(k) for k in ('offset','scanned_through','next_offset','truncated')}
            if kind=='pe' and data.get('structural_status') not in ('declared_ranges_present','not_pe'):
                partial=True;reasons.append('partial_or_malformed_reconstruction')
        if partial:
            result['availability']='partial';reasons.append('incomplete_collection')
        elif complete:
            result['availability']='rows_present' if count else 'successfully_empty'
        else:
            result['availability']='partial' if count else 'unavailable'
            reasons.append('collection_not_verified_complete')
    except (ValueError,OSError,KeyError,TypeError) as exc:
        # Format errors must never turn into an empty count. Integrity errors are
        # kept distinct from malformed bytes; the saved reader remains available.
        message=str(exc)
        if 'hash' in message or 'size changed' in message or 'integrity' in message:
            result['availability']='unavailable';reasons.append('integrity_error')
        elif any(word in message for word in ('limit','exceeds','budget','unregistered','not registered')):
            result['availability']='unknown';reasons.append('unsupported_or_insufficient_metadata')
        else:
            result['availability']='malformed';reasons.append('unparseable_output')
        result['failure_reason']=message[:2000]
    return result


def snapshot(backend, image):
    source=backend.resolve_input(image);image=str(source.relative_to(backend.cases))
    case=backend.case_directory(source)
    revisions=plans(backend,case);latest=revisions[-1] if revisions else None
    if latest:require(latest['image']==image, 'Plan belongs to another image')
    paths=sorted([*(case/'runs').glob('*/manifest.json'),*(case/'inspections').glob('*/manifest.json')])
    require(len(paths)<=MAX_RECORDS, 'Coverage limit: 2000 saved attempts per image')
    attempts=[];issues=[];budget=[0]
    for path in paths:
        try:attempts.append(attempt(backend,image,path,read_record(backend,path),budget))
        except (ValueError,OSError,KeyError,TypeError) as exc:
            issues.append({'manifest':str(path.relative_to(backend.outputs)),'reason_code':'unreadable_or_foreign_manifest','error':str(exc)[:300]})
    def chronological(a):
        try:return (datetime.fromisoformat(a['started_at'].replace('Z','+00:00')).astimezone(timezone.utc),a['run_id'])
        except (ValueError,TypeError,AttributeError):
            a['reason_codes'].append('unknown_attempt_time')
            return (datetime.min.replace(tzinfo=timezone.utc),a['run_id'])
    attempts.sort(key=chronological)
    entries=[];covered=set()
    for item in latest['plan']['entries'] if latest else []:
        group=[a for a in attempts if a['plugin']==item['plugin'] and a['arguments']==item['arguments']]
        covered.update(a['run_id'] for a in group)
        entries.append(entry(item['id'],item['question'],item['plugin'],item['arguments'],group,item))
    groups={}
    for a in attempts:
        if a['run_id'] not in covered:groups.setdefault(key(a['plugin'],a['arguments']) if a['arguments'] is not None else 'unknown-'+a['run_id'],[]).append(a)
    for k,group in groups.items():
        entries.append(entry('observed-'+k,None,group[0]['plugin'],group[0]['arguments'],group,None))
    receipts=list((case/'reuse').glob('*.json'))
    require(len(receipts)<=MAX_RECORDS, 'Coverage limit: 2000 reuse receipts per image')
    for path in receipts:
        try:
            r=read_record(backend,path)
            found=next((a for a in attempts if a['run_id']==r.get('run_id')),None)
            require(found is not None and r.get('reused') is True and r.get('integrity_verified') is True, 'Unverified or orphan reuse receipt')
            original=read_record(backend,case/'runs'/found['run_id']/'manifest.json')
            require(r.get('manifest_path')==str(case/'runs'/found['run_id']/'manifest.json') and
                    r.get('image_before',{}).get('path')==str(source) and
                    r.get('image_before',{}).get('sha256')==original.get('image_sha256_before') and
                    r.get('image_after',{}).get('sha256')==original.get('image_sha256_after'),
                    'Reuse receipt image/run identity mismatch')
            found.setdefault('reuse_receipts',[]).append({'path':str(path.relative_to(backend.outputs)), 'requested_at':r.get('requested_at')})
        except (ValueError,OSError,KeyError,TypeError) as exc:
            issues.append({'reason_code':'invalid_reuse_receipt','error':str(exc)[:300]})
    for e in entries:
        e['reuse_count']=sum(len(a.get('reuse_receipts',[])) for a in e['attempts'])
    planned=[e for e in entries if e['planned']]
    satisfied=sum(e['effective']['availability'] in ('rows_present','successfully_empty') and
                  e['effective']['execution']=='succeeded' for e in planned)
    return {'schema':SCHEMA,'case_id':case.name,'namespace':hashlib.sha256(str(backend.outputs).encode()).hexdigest(),
            'image':image,'scope':'declared' if latest else 'unspecified','plan':latest,
            'plan_revision_count':len(revisions),'entries':entries,'issues':issues,
            'summary':{'declared_plan_entries':len(planned),'entries_with_successful_collection':satisfied,
                'observed_scopes':len(entries)-len(planned),'physical_commands_recorded':sum(a['physical_commands_recorded'] for a in attempts),
                'saved_attempts':len(attempts),'reuse_requests':sum(len(a.get('reuse_receipts',[])) for a in attempts),
                'execution':dict(Counter(e['effective']['execution'] for e in entries)),
                'availability':dict(Counter(e['effective']['availability'] for e in entries))},
            'limitations':['Scope unspecified; no original plan inferred.' if not latest else
                          'Counts describe collection for declared entries, not questions answered or certainty of a clean image.',
                          'Legacy metadata, source-image freshness and running-process liveness may be unknown. No image was hashed.',
                          'Requests rejected before a run manifest require client history; they are not inferred from run absence.',
                          'Physical command counts require recorded exit metadata; interrupted/legacy launches may be uncountable.']}


def entry(ident,question,plugin,args,attempts,plan):
    # Latest attempt is effective; retain a previous successful run explicitly,
    # without allowing it to conceal a later failed or partial attempt.
    latest=attempts[-1] if attempts else None
    effective={k:latest[k] for k in ('run_id','execution','applicability','availability','row_count','reason_codes')} if latest else {
        'run_id':None,'execution':'not_run','applicability':(plan or {}).get('applicability','unknown'),
        'availability':'unavailable','row_count':None,'reason_codes':['not_collected']}
    successes=[a['run_id'] for a in attempts if a['execution']=='succeeded' and a['availability'] in ('rows_present','successfully_empty')]
    return {'entry_id':ident,'question':question,'plugin':plugin,'arguments':args,'planned':plan is not None,
            'declared_applicability':(plan or {}).get('applicability','unknown'), 'declared_reason':(plan or {}).get('reason'),
            'effective':effective,'successful_run_ids':successes,'attempts':attempts,
            'question_answered':'not_determined','limitations':['Ad hoc scope; original intent was not recorded.'] if not plan else []}


def get_coverage(backend,image,offset=0,limit=20,entry_id=None,attempt_offset=0,attempt_limit=10):
    for value,lo,hi in [(offset,0,MAX_RECORDS),(limit,1,50),(attempt_offset,0,MAX_RECORDS),(attempt_limit,1,50)]:
        require(type(value) is int and lo<=value<=hi,'Coverage pagination outside bounds')
    view=snapshot(backend,image);entries=view.pop('entries');count=len(entries)
    view['issue_count']=len(view['issues']);view['issues']=view['issues'][:10]
    view['issues_truncated']=view['issue_count']>10
    if view['plan']:
        plan=view['plan']
        view['plan']={k:plan[k] for k in ('plan_id','declared_at','declared_by','previous')}
        view['plan'].update(profile=plan['plan']['profile'],entry_count=len(plan['plan']['entries']))
    if entry_id is not None:
        entries=[e for e in entries if e['entry_id']==entry_id]
        require(bool(entries),'Unknown coverage entry in this image')
    selected=entries[offset:offset+limit];returned=[];used=len(json.dumps(view))
    for original in selected:
        e=dict(original);attempts=original['attempts'];e['attempt_count']=len(attempts)
        e['attempts']=[]
        for original_attempt in attempts[attempt_offset:attempt_offset+attempt_limit]:
            a=dict(original_attempt);receipts=a.get('reuse_receipts',[])
            a['reuse_receipt_count']=len(receipts);a['reuse_receipts']=receipts[:5]
            a['reuse_receipts_truncated']=len(receipts)>5
            if len(json.dumps(e))+len(json.dumps(a))+used>60000:break
            e['attempts'].append(a)
        require(bool(e['attempts']) or attempt_offset>=len(attempts), 'One attempt exceeds coverage response budget; read its manifest')
        e['attempt_next_offset']=attempt_offset+len(e['attempts']) if attempt_offset+len(e['attempts'])<len(attempts) else None
        if used+len(json.dumps(e))>60000:break
        returned.append(e);used+=len(json.dumps(e))
    require(bool(returned) or not selected,'Coverage entry exceeds response limit; use narrower attempt pagination')
    end=offset+len(returned)
    return {**view,'entries':returned,'total_entries':count,'returned_count':len(returned),
            'delivery':{'offset':offset,'next_offset':end if end<len(entries) else None,
                'truncated':end<len(entries) or any(e['attempt_next_offset'] is not None for e in returned),
                'meaning':'Response pagination only; does not change collection completeness.'}}


def job_view(jobs,case_id):
    """UI jobs are orchestration, not additional plugin attempts or physical runs."""
    return [{'job_id':j['id'],'kind':j['kind'],'execution':{'completed':'succeeded','incomplete':'interrupted',
                'error':'failed','stopping':'running'}.get(j['status'],j['status']),
             'source_status':j['status'],'created_at':j.get('created_at'),'finished_at':j.get('finished_at'),
             'reason':j.get('error'),'question':j.get('text'),
             'limitation':'Job outcome does not establish plugin coverage; consult saved run records.'}
            for j in jobs if j['case_id']==case_id][-50:]


def report_summary(coverage):
    lines=['[Saved coverage snapshot](coverage.json). This describes examined scope, not absence of compromise.']
    for view in coverage['images']:
        summary=view.get('summary',{})
        gaps=sum(e['effective']['availability'] not in ('rows_present','successfully_empty') for e in view['entries'])
        lines.append(f"Image {view['image_id']}: scope {view['scope']}; "
                     f"{summary.get('entries_with_successful_collection',0)} of {summary.get('declared_plan_entries',0)} "
                     f"declared entries have successful collection; {gaps} recorded scopes have missing/partial/unknown results. "
                     "These counts do not measure questions answered. Inspect the snapshot for exact arguments, failures and prior attempts.")
        if view['scope']=='unspecified':lines.append('Overall investigation coverage is unknown: no original plan was recorded.')
        if view.get('issues'):lines.append('Some records could not be verified; coverage is incomplete.')
    return '\n\n'.join(lines)


def request_failures(activity):
    """Retain client-observed failures without inventing an unrecorded physical run."""
    failures=[]
    for event in activity:
        item=event.get('detail',{})
        if isinstance(item,dict) and item.get('type')=='mcpToolCall' and item.get('status')=='failed':
            failures.append({'event_id':event['id'],'timestamp':event.get('time'),'tool':item.get('tool'),
                'arguments':item.get('arguments'),'error':item.get('error'),
                'execution':'unknown','reason_code':'client_observed_request_failure',
                'limitation':'May precede a run or refer to a saved failed run; no extra physical execution inferred.'})
    return failures[-50:]
