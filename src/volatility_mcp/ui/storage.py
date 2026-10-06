"""Private UI state and report packaging; never a core MCP requirement."""
from __future__ import annotations
import csv
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import shutil
import stat
import uuid
from ..backend import file_fingerprint
from ..reporting import check_bundle
from ..saved_evidence import source_identity
from ..timestamps import utc_now as now
from .coins import populate


def uid():
    return uuid.uuid4().hex


def private_dir(path):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink state/output directory is not allowed')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def atomic_json(path, data):
    path = Path(path)
    private_dir(path.parent)
    temporary = path.with_name(path.name + '.' + uid() + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def safe_file(root, relative):
    root = Path(root)
    path = Path(relative)
    if not isinstance(relative, str) or not relative or path.is_absolute() or '..' in path.parts or '\\' in relative:
        raise ValueError('Use a relative case artifact path without traversal')
    result = root / path
    if any(p.is_symlink() for p in (result, *result.parents)) or not result.resolve().is_relative_to(root.resolve()):
        raise ValueError('Artifact path escapes its case or contains a symlink')
    if result.exists() and not stat.S_ISREG(result.stat().st_mode):
        raise ValueError('Artifact must be a regular file')
    return result


def read_chunk(root, path, offset=0, limit=32768):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 65536:
        raise ValueError('Invalid chunk bounds')
    target = safe_file(root, path)
    with target.open('rb') as stream:
        stream.seek(offset)
        data = stream.read(limit)
    size = target.stat().st_size
    return {'path': path, 'text': data.decode('utf8', errors='replace'), 'size': size,
            'next_offset': offset + len(data), 'truncated': offset + len(data) < size}


class Bundle:
    def __init__(self, case_dir, case, version, cancel=None):
        self.case_dir, self.case, self.version = Path(case_dir), case, version
        self.cancel = cancel
        self.root = private_dir(self.case_dir / 'reports' / version['id'])

    def check_cancel(self):
        if self.cancel and self.cancel.is_set():
            raise ValueError('Report packaging stopped; draft remains incomplete')

    def prepare(self):
        self.check_cancel()
        if self.version['status'] == 'sealed':
            raise ValueError('Sealed report versions cannot be modified')
        artifacts, runs, steps, versions = [], [], [], {}
        notes = self.case.get('notes', {})
        for source in sorted((self.case_dir / 'analysis').glob('*/runs/*/manifest.json')):
            source = safe_file(self.case_dir, str(source.relative_to(self.case_dir)))
            record = json.loads(source.read_text())
            if record['status'] == 'running':
                raise ValueError('An analysis run is still active; finish or stop it before packaging')
            rid = record['run_id']
            cid = 'C-' + hashlib.sha256(rid.encode()).hexdigest()[:12]
            ids = []
            for original in sorted(source.parent.rglob('*')):
                self.check_cancel()
                if original.is_dir():
                    continue
                original = safe_file(self.case_dir, str(original.relative_to(self.case_dir)))
                relative = Path('artifacts') / cid / original.relative_to(source.parent)
                dest = safe_file(self.root, str(relative))
                private_dir(dest.parent)
                with original.open('rb') as src, dest.open('wb') as dst:
                    while chunk := src.read(4 * 1024 * 1024):
                        self.check_cancel()
                        dst.write(chunk)
                identity = file_fingerprint(dest)
                registered = next((a for c in record.get('commands', []) for a in c.get('artifacts', [])
                                   if a['path'] == str(original)), None)
                if registered and any(identity[k] != registered[k] for k in ('sha256', 'size_bytes')):
                    raise ValueError('Saved output disagrees with execution manifest; cannot package changed evidence')
                aid = cid + '-A-' + hashlib.sha256(str(relative).encode()).hexdigest()[:10]
                ids.append(aid)
                artifacts.append({'artifact_id': aid, 'path': str(relative), 'sha256': identity['sha256'],
                    'size_bytes': dest.stat().st_size, 'media_type': mimetypes.guess_type(dest.name)[0] or 'application/octet-stream', 'run_id': rid})
                if registered:
                    artifacts[-1].update(source_ref=source_identity(self.case_dir/'analysis', source.parent.parent.parent,
                        record['image_relative_path'], rid, str(original.relative_to(source.parent)), identity['sha256']),
                        source_result={'source_status':record['status'], 'completed':bool(record.get('completed_at')),
                                       'integrity_verified':record.get('integrity_verified') is True})
            image = next((i for i in self.case['images'] if i['path'] == record['image']), None)
            if image is None:
                raise ValueError('Run has evidence outside the registered case')
            if (not record.get('integrity_verified') or
                    record.get('image_sha256_before') != image.get('sha256') or
                    record.get('image_sha256_after') != image.get('sha256')):
                raise ValueError('Run evidence integrity/identity disagrees with case readiness; cannot combine these results')
            runs.append({'run_id': rid, 'call_id': cid, 'status': record['status'],
                'started_at': record['started_at'], 'finished_at': record['completed_at'],
                'artifact_ids': ids, 'image_id': image['id'],
                'source_case_id':source.parent.parent.parent.name, 'image_relative_path':record['image_relative_path']})
            note = notes.get(rid, {})
            steps.append({'call_id': cid, 'timestamp': record['started_at'],
                'question': note.get('question', 'Not recorded; consult the preserved command and result.'),
                'tool': record['plugin'], 'arguments': record['arguments'],
                'argv': [c['argv'] for c in record['commands']],
                'prerequisite_call_ids': ['C-'+hashlib.sha256(p.encode()).hexdigest()[:12] for p in note.get('prerequisite_run_ids',[])],
                'artifact_ids': ids, 'status': record['status'], 'result': note.get('result', record['status']),
                'rationale': note.get('rationale', 'Not recorded; no retrospective rationale inferred.'),
                'next_step': note.get('next_step', 'Not recorded'),
                'hypothesis_disposition': note.get('hypothesis_disposition', 'unknown'), 'run_id': rid,
                'image_id': image['id']})
            versions = {'python': record['volatility_python_version'], 'volatility': record['volatility_version'],
                'mcp': record['mcp_sdk_version'], 'mcp_server': record['server_version']}
        if not runs:
            raise ValueError('No saved analysis runs. Perform readiness/analysis first.')
        # Static inspections are separate derived runs, linked to their actual
        # extraction artifacts rather than misattributed to a Volatility command.
        for source in sorted((self.case_dir/'analysis').glob('*/inspections/*/manifest.json')):
            self.check_cancel()
            source = safe_file(self.case_dir, str(source.relative_to(self.case_dir)))
            record = json.loads(source.read_text())
            if record['status'] == 'running':
                raise ValueError('An artifact inspection is still active')
            ref = record['source_ref']
            parent = next((r for r in runs if r['run_id'] == ref['run_id']), None)
            if parent is None:
                raise ValueError('Inspection refers to an unknown extraction run')
            source_relative = str(Path('artifacts')/parent['call_id']/ref['artifact'])
            original_artifact = next((a for a in artifacts if a['path'] == source_relative), None)
            if (not original_artifact or original_artifact['sha256'] != ref['sha256'] or
                    not record.get('integrity_verified')):
                raise ValueError('Inspection input identity/integrity does not match the saved extraction')
            rid = 'inspection-' + source.parent.name
            cid = 'C-' + hashlib.sha256(rid.encode()).hexdigest()[:12]
            ids = []
            for original in sorted(source.parent.iterdir()):
                original = safe_file(self.case_dir, str(original.relative_to(self.case_dir)))
                if not original.is_file():
                    raise ValueError('Unexpected inspection subdirectory')
                relative = Path('artifacts')/cid/original.name
                dest = safe_file(self.root, str(relative)); private_dir(dest.parent)
                shutil.copyfile(original, dest)
                identity = file_fingerprint(dest)
                if (original.name == 'result.json' and record['status'] == 'success' and
                        identity['sha256'] != record['result_sha256']):
                    raise ValueError('Inspection result hash changed')
                aid = cid + '-A-' + hashlib.sha256(str(relative).encode()).hexdigest()[:10]
                ids.append(aid)
                artifacts.append({'artifact_id':aid, 'path':str(relative), 'sha256':identity['sha256'],
                    'size_bytes':identity['size_bytes'], 'media_type':mimetypes.guess_type(dest.name)[0] or 'application/octet-stream', 'run_id':rid})
                if original.name == 'result.json' and record.get('result_sha256'):
                    artifacts[-1].update(source_ref=source_identity(self.case_dir/'analysis', source.parent.parent.parent,
                        ref['image_relative_path'], rid, 'result.json', identity['sha256']),
                        source_result={'source_status':record['status'], 'completed':bool(record.get('completed_at')),
                            'integrity_verified':record.get('integrity_verified') is True,
                            'source_run_status':record.get('source_run_status'),
                            'source_run_integrity_verified':record.get('source_run_integrity_verified'), 'source_artifact':ref,
                            'inspection_parser':record['parser'], 'inspection_settings':record['settings']})
            runs.append({'run_id':rid,'call_id':cid,'status':record['status'],'started_at':record['started_at'],
                'finished_at':record['completed_at'],'artifact_ids':ids,'image_id':parent['image_id'],
                'source_case_id':source.parent.parent.parent.name,'image_relative_path':ref['image_relative_path']})
            steps.append({'call_id':cid,'run_id':rid,'timestamp':record['started_at'],
                'question':'Inspect existing extracted artifact: '+record['settings']['operation'],
                'tool':'inspect_artifact','arguments':{'source_ref':ref, **record['settings']},
                'argv':[record['argv']], 'prerequisite_call_ids':[parent['call_id']],
                'input_artifact_ids':[original_artifact['artifact_id']], 'artifact_ids':ids,
                'status':record['status'],'result':record.get('error') or 'Static inspection saved; consult result.json',
                'rationale':'Inspect saved bytes without rerunning memory analysis; no retrospective investigative rationale inferred.',
                'next_step':'Corroborate declarations/strings and retain structural limitations.',
                'hypothesis_disposition':'No maliciousness verdict from static inspection alone'})
        # Requests denied before execution have no core run. Preserve the actual
        # failure as its own artifact/call instead of attributing it to another run.
        activity=self.case_dir/'activity.jsonl'
        if activity.exists():
            with activity.open() as activity_file:
                for line in activity_file:
                    event=json.loads(line)
                    item=event.get('detail',{})
                    if (event['kind']!='item/completed' or not isinstance(item,dict) or
                            item.get('type')!='mcpToolCall' or item.get('status')!='failed'):
                        continue
                    self.check_cancel()
                    cid='UI-'+event['id']
                    relative='artifacts/'+cid+'.json'
                    dest=safe_file(self.root,relative)
                    atomic_json(dest,event)
                    fp=file_fingerprint(dest)
                    artifacts.append({'artifact_id':cid,'path':relative,'sha256':fp['sha256'],
                        'size_bytes':fp['size_bytes'],'media_type':'application/json','run_id':None})
                    steps.append({'call_id':cid,'timestamp':event['time'],'question':'Not recorded for this failed request',
                        'tool':item.get('tool','unknown'),'arguments':item.get('arguments'),
                        'argv':None,'prerequisite_call_ids':[],'artifact_ids':[cid],'status':'error',
                        'result':item.get('error'),'rationale':'Request failure preserved from actual app-server event; no successful execution inferred.',
                        'next_step':'Review failure before retrying','hypothesis_disposition':'unresolved'})
        evidence = []
        for image in self.case['images']:
            if not image.get('sha256'):
                raise ValueError('Evidence hashing is incomplete')
            evidence.append({'id': image['id'], 'path': image['path'], 'sha256': image['sha256'],
                'sha256_before': image['sha256'], 'sha256_after': image['sha256'],
                'size_bytes': image['size_bytes'], 'source': image.get('source') or 'Local file; acquisition provenance unknown', 'acquired_at': None})
        coins=populate(self.case_dir,self.case['images'])
        for coin in coins:
            if 'path' not in coin:continue
            try:
                source=safe_file(self.case_dir,coin['path'])
                target=safe_file(self.root,coin['path'])
                private_dir(target.parent)
                if target.exists() and target.read_bytes()!=source.read_bytes():
                    raise ValueError('Existing report coin differs')
                if not target.exists():shutil.copyfile(source,target)
            except Exception as exc:
                coin.pop('path',None);coin['error']=str(exc)
        manifest = {'coins':coins,'schema_version': '0.1', 'report_spec_version': '0.2', 'case_id': self.case['id'],
            'synthetic': False, 'status': 'in_progress', 'created_at': self.version['created_at'], 'completed_at': None,
            'evidence': evidence, 'tools': versions, 'runs': runs, 'artifacts': artifacts, 'findings': [],
            'previous_report_version': self.version.get('previous'), 'codex_thread_id': self.case.get('thread_id')}
        existing = self.root / 'case-manifest.json'
        if existing.exists():
            manifest['findings'] = json.loads(existing.read_text()).get('findings', [])
        atomic_json(existing, manifest)
        (self.root / 'investigation.jsonl').write_text(''.join(json.dumps(s) + '\n' for s in steps))
        return manifest

    def save(self, markdown, findings, iocs):
        if not isinstance(markdown, str) or len(markdown) > 2_000_000:
            raise ValueError('Report must be text, at most 2 MB')
        if not isinstance(findings, list) or not isinstance(iocs, list):
            raise ValueError('Findings and IOCs must be arrays')
        manifest = self.prepare()
        manifest['findings'] = findings
        atomic_json(self.root / 'case-manifest.json', manifest)
        badges='\n'.join(f"![Decorative coin for {c['image_id']}]({c['path']})" for c in manifest['coins'] if 'path' in c)
        (self.root / 'report.md').write_text((badges+'\n\n' if badges else '')+markdown)
        fields = ['type','value','evidence_ref','confidence','relevance','status','context']
        with (self.root / 'iocs.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
            writer.writeheader()
            for row in iocs:
                writer.writerow(row)
        return check_bundle(self.root)

    def seal(self, fingerprints):
        manifest = self.prepare()
        self.check_cancel()
        for evidence in manifest['evidence']:
            after = fingerprints[evidence['id']]
            if after['sha256'] != evidence['sha256'] or after['size_bytes'] != evidence['size_bytes']:
                raise ValueError('Evidence changed since readiness; report cannot be sealed')
            evidence['sha256_after'] = after['sha256']
        manifest.update(status='complete_with_limitations', completed_at=now(),
            review_status='AI-assisted draft; human forensic review required')
        atomic_json(self.root / 'case-manifest.json', manifest)
        lines = []
        for path in sorted(self.root.rglob('*')):
            self.check_cancel()
            if path.is_file() and path.name != 'SHA256SUMS':
                checked = safe_file(self.root, str(path.relative_to(self.root)))
                lines.append(file_fingerprint(checked)['sha256'] + '  ' + str(path.relative_to(self.root)))
        (self.root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
        try:
            result = check_bundle(self.root)
        except Exception:
            manifest.update(status='in_progress', completed_at=None)
            atomic_json(self.root / 'case-manifest.json', manifest)
            raise
        self.version.update(status='sealed', completed_at=now(), validation=result)
        return result
