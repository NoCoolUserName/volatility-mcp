"""Optional mechanical report provenance checks; never imported by the MCP server.

This validates links/identities, not the truth of forensic conclusions.
"""
from __future__ import annotations
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit, parse_qs


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _timestamp(value, label, optional=False):
    if value is None and optional:
        return
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        _require(parsed.tzinfo is not None and parsed.utcoffset() is not None, f'{label} needs a timezone')
    except (TypeError, AttributeError, ValueError) as exc:
        raise ValueError(f'{label} must be an ISO 8601 timestamp with timezone') from exc


def _path(root, value):
    _require(isinstance(value, str) and bool(value), 'Artifact path must be a nonempty string')
    path = Path(value)
    _require(not path.is_absolute() and '..' not in path.parts and '\\' not in value,
             f'Unsafe bundle path: {value}')
    candidate = root / path
    _require(not any(p.is_symlink() for p in (candidate, *candidate.parents)), f'Symlink bundle path: {value}')
    _require(candidate.resolve().is_relative_to(root), f'Path escapes bundle: {value}')
    _require(candidate.is_file(), f'Missing bundle file: {value}')
    return candidate


def _sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _unique(items, field):
    mapping = {}
    for item in items:
        value = item.get(field)
        _require(isinstance(value, str) and bool(value) and value not in mapping,
                 f'Missing or duplicate {field}: {value!r}')
        mapping[value] = item
    return mapping


def _check_bundle(directory: Path) -> dict:
    root = directory.resolve(strict=True)
    for name in ('report.md', 'case-manifest.json', 'investigation.jsonl', 'iocs.csv'):
        _path(root, name)
    manifest = json.loads((root / 'case-manifest.json').read_text())
    required = {'schema_version','report_spec_version','case_id','synthetic','status','created_at',
                'completed_at','evidence','tools','runs','artifacts','findings'}
    _require(required <= manifest.keys(), f'Missing manifest fields: {sorted(required - manifest.keys())}')
    _require(manifest['schema_version'] == '0.1' and manifest['report_spec_version'] in ('0.1', '0.2', '0.3'), 'Unsupported schema/report spec version')
    _require(type(manifest['synthetic']) is bool, 'synthetic must be a boolean')
    _require(manifest['status'] in {'in_progress','complete','complete_with_limitations','blocked'}, 'Unknown completion status')
    complete = manifest['status'].startswith('complete')
    _timestamp(manifest['created_at'], 'created_at')
    _timestamp(manifest['completed_at'], 'completed_at', optional=not complete)
    _require(bool(manifest['evidence']), 'Evidence identities are required')
    _unique(manifest['evidence'],'id')
    for evidence in manifest['evidence']:
        for field in ('sha256','sha256_before','sha256_after'):
            _require(bool(re.fullmatch('[0-9a-f]{64}', evidence.get(field, '') or '')), f'Invalid evidence {field}')
        _require(type(evidence.get('size_bytes')) is int and evidence['size_bytes'] >= 0, 'Evidence byte size required')
        _timestamp(evidence.get('acquired_at'), 'acquired_at', optional=True)
        if complete:
            _require(evidence['sha256'] == evidence['sha256_before'] == evidence['sha256_after'],
                     'Source integrity failure cannot be a completed investigation')
    _require({'python','volatility','mcp','mcp_server'} <= manifest['tools'].keys(), 'Required tool versions are absent')
    artifacts = _unique(manifest['artifacts'],'artifact_id')
    artifact_paths = set()
    for aid, artifact in artifacts.items():
        path = _path(root, artifact['path'])
        _require(artifact['path'] not in artifact_paths, 'Duplicate artifact path')
        artifact_paths.add(artifact['path'])
        _require(artifact['path'] != 'case-manifest.json', 'Manifest must not hash itself')
        _require(path.stat().st_size == artifact['size_bytes'] and _sha(path) == artifact['sha256'],
                 f'Artifact hash/size mismatch: {aid}')
    for evidence in manifest['evidence']:
        matches = [a for aid, a in artifacts.items() if aid == evidence['id'] or
                   (evidence.get('path') is not None and a['path'] == evidence['path'])]
        for artifact in matches:
            _require(artifact['sha256'] == evidence['sha256'] and artifact['size_bytes'] == evidence['size_bytes'],
                     'Bundled source artifact contradicts its evidence identity')
    runs = _unique(manifest['runs'],'run_id')
    calls = _unique([json.loads(line) for line in (root / 'investigation.jsonl').read_text().splitlines() if line.strip()], 'call_id')
    call_fields = {'timestamp','question','tool','arguments','argv','prerequisite_call_ids','artifact_ids',
                   'status','result','rationale','next_step','hypothesis_disposition'}
    for cid, call in calls.items():
        _require(call_fields <= call.keys(), f'Missing investigation fields for {cid}')
        _timestamp(call['timestamp'], f'{cid} timestamp')
        _require(set(call['artifact_ids']) <= artifacts.keys(), f'Unknown artifact in {cid}')
        _require(set(call['prerequisite_call_ids']) <= calls.keys(), f'Unknown prerequisite in {cid}')
        if manifest['synthetic']:
            _require(call.get('synthetic') is True and call.get('execution_kind') == 'simulated',
                     f'Synthetic call must be explicitly simulated: {cid}')
    visited, active = set(), set()
    def visit(cid):
        _require(cid not in active, 'Investigation dependencies contain a cycle')
        if cid in visited:
            return
        active.add(cid)
        for prerequisite in calls[cid]['prerequisite_call_ids']:
            visit(prerequisite)
        active.remove(cid)
        visited.add(cid)
    for cid in calls:
        visit(cid)
    for rid, run in runs.items():
        _require(run['call_id'] in calls, f'Run {rid} has no investigation call')
        _require(run['status'] == calls[run['call_id']]['status'], f'Run/call status mismatch: {rid}')
        _require(set(run['artifact_ids']) <= artifacts.keys(), f'Unknown run artifact: {rid}')
        for aid in run['artifact_ids']:
            _require(artifacts[aid].get('run_id') == rid, f'Run claims an artifact owned by another run: {rid}')
        _timestamp(run['started_at'], f'{rid} start')
        _timestamp(run['finished_at'], f'{rid} finish', optional=not complete)
        _require(not complete or run['status'] not in {'running','pending'}, 'Unfinished run in a completed bundle')
        if manifest['synthetic']:
            _require(run.get('synthetic') is True, f'Synthetic run must be labeled: {rid}')
    for cid, call in calls.items():
        associated = [run for run in runs.values() if run['call_id'] == cid]
        if call.get('run_id') is not None:
            _require(call['run_id'] in {run['run_id'] for run in associated}, f'Call run_id contradicts run ownership: {cid}')
        if associated:
            produced = {aid for run in associated for aid in run['artifact_ids']}
            _require(produced == set(call['artifact_ids']), f'Call/run output artifact mismatch: {cid}')
    for aid, artifact in artifacts.items():
        rid = artifact.get('run_id')
        _require(rid is None or rid in runs, f'Unknown artifact run: {aid}')
        if rid is not None:
            _require(aid in runs[rid]['artifact_ids'], f'Artifact absent from its run: {aid}')
    report = (root / 'report.md').read_text()
    if manifest['report_spec_version']=='0.3':
        coverage_path=_path(root,manifest.get('coverage',{}).get('path'))
        coverage=json.loads(coverage_path.read_text())
        _require(coverage.get('schema')=='coverage/1' and coverage.get('case_id')==manifest['case_id'], 'Coverage snapshot ownership mismatch')
        _require(any(a['path']==str(coverage_path.relative_to(root)) for a in artifacts.values()), 'Coverage snapshot must be a hashed artifact')
        _require({v['image_id'] for v in coverage['images']}=={e['id'] for e in manifest['evidence']}, 'Coverage image identities disagree')
        from .coverage import report_summary
        _require(report_summary(coverage) in report, 'Report must retain its mechanical coverage limitations')
        for view in coverage['images']:
            for entry in view['entries']:
                for attempt in entry['attempts']:
                    _require(attempt['run_id'] in runs, 'Coverage cites an unknown run')
                    # Check the projection against bundled authority, not a supplied
                    # coverage completion flag. Historical formats bypass this block.
                    from .coverage import execution
                    from .saved_evidence import load_tree, rows
                    recorded_path=attempt.get('bundle_manifest_path')
                    _require(any(a['path']==recorded_path and a['run_id']==attempt['run_id'] for a in artifacts.values()),
                             'Coverage attempt lacks its owning bundled manifest')
                    recorded=json.loads(_path(root,recorded_path).read_text())
                    inspection=attempt['run_id'].startswith('inspection-')
                    _require(attempt['source_status']==recorded.get('status') and
                             attempt['execution']==execution(recorded,inspection), 'Coverage execution contradicts original record')
                    if attempt['availability'] in ('rows_present','successfully_empty'):
                        _require(bool(attempt['evidence']), 'Positive coverage requires saved output')
                        support=attempt['evidence'][0]
                        a=next((a for a in artifacts.values() if a['path']==support.get('bundle_path') and
                                a['run_id']==attempt['run_id']),None)
                        _require(a is not None and a.get('source_ref')==support['reference']['source'], 'Coverage output identity mismatch')
                        count=len(rows(load_tree(_path(root,a['path'])),recorded.get('settings',{}).get('operation') if inspection else 'volatility'))
                        _require(count==attempt['row_count'] and (count==0)==(attempt['availability']=='successfully_empty'),
                                 'Coverage row count contradicts saved output')
                    if attempt['availability']=='successfully_empty':
                        _require(attempt['execution']=='succeeded' and attempt['source_status']=='success' and
                                 attempt['integrity_verified'] and attempt['row_count']==0, 'Invalid successful-empty coverage')
    headings = re.findall(r'^##\s+(.+)$', report, re.M)
    _require(bool(headings) and headings[0].lower().startswith('executive summary'), 'Executive summary must be first')
    _require(headings[-1].lower().startswith('ioc'), 'IOC appendix must be last')
    for name in ('Scope','Technical findings','Investigative workflow','Limitations'):
        _require(any(h.lower().startswith(name.lower()) for h in headings), f'Missing report section: {name}')
    findings = _unique(manifest['findings'],'finding_id')
    citation_checks = []
    for fid, finding in findings.items():
        _require(fid in report, f'Finding missing from report: {fid}')
        _require(bool(finding['evidence_refs']), f'Finding lacks evidence: {fid}')
        for ref in finding['evidence_refs']:
            _require(ref['artifact_id'] in artifacts and bool(ref.get('locator')), f'Invalid finding locator: {fid}')
            checked = check_citation(root, manifest, ref)
            citation_checks.append({'finding_id':fid, 'artifact_id':ref['artifact_id'], **checked})
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',report):
        target = target.strip('<>')
        parsed = urlsplit(target)
        if parsed.scheme:
            _require(parsed.scheme in {'http','https'}, 'Unsafe report link scheme')
        elif parsed.path:
            _path(root, unquote(parsed.path))
            citation = parse_qs(parsed.fragment).get('citation')
            if citation:
                fid, separator, index = citation[0].rpartition(':')
                _require(separator and fid in findings and index.isdecimal(), 'Invalid report citation link')
                refs = findings[fid]['evidence_refs']
                _require(int(index) < len(refs), 'Report citation index out of bounds')
                _require(artifacts[refs[int(index)]['artifact_id']]['path'] == unquote(parsed.path),
                         'Report citation link targets a different artifact')
    with (root / 'iocs.csv').open(newline='') as stream:
        reader = csv.DictReader(stream)
        _require(reader.fieldnames == ['type','value','evidence_ref','confidence','relevance','status','context'], 'Unexpected IOC columns')
        iocs = list(reader)
        for ioc in iocs:
            _require(all(ioc.values()), 'Incomplete IOC row')
            aid, separator, locator = ioc['evidence_ref'].partition(':')
            _require(aid in artifacts and separator and locator, 'IOC needs an exact artifact ID and locator separated by a colon')
    if complete:
        checksum_path = _path(root,'SHA256SUMS')
        listed = {}
        for line in checksum_path.read_text().splitlines():
            digest, relative = line.split('  ',1)
            _require(relative != 'SHA256SUMS' and relative not in listed, 'Invalid checksum entry')
            _require(_sha(_path(root,relative)) == digest, f'Checksum mismatch: {relative}')
            listed[relative] = digest
        files = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p != checksum_path}
        _require(files == listed.keys(), 'Checksum coverage must include every final bundle file except SHA256SUMS')
    return {'status':'valid','case_id':manifest['case_id'],'synthetic':manifest['synthetic'],
            'artifacts':len(artifacts),'calls':len(calls),'findings':len(findings),'iocs':len(iocs),
            'citation_validation':citation_checks,
            'scope':'Provenance and supported observable values only; free-form narrative and inference require analyst review.'}


def check_citation(root, manifest, ref):
    """Resolve against this portable bundle, not caller-supplied validation flags."""
    from .saved_evidence import resolve_reference
    artifacts = _unique(manifest['artifacts'], 'artifact_id')
    artifact = artifacts.get(ref.get('artifact_id'))
    _require(artifact is not None, 'Citation artifact is absent from this case')
    path = _path(Path(root).resolve(), artifact['path'])
    _require(path.stat().st_size == artifact['size_bytes'] and _sha(path) == artifact['sha256'],
             'Citation artifact hash/size mismatch')
    if 'structured' not in ref:
        return {'provenance_validation':'legacy_artifact_only',
                'observable_validation':'not_checked', 'interpretation_validation':'not_checked',
                'limitation':'Legacy locator is readable but not deterministically verified.'}
    source = artifact.get('source_ref')
    _require(isinstance(source, dict), 'Structured citation requires packaged source provenance')
    runs = _unique(manifest['runs'], 'run_id')
    run = runs.get(artifact['run_id'])
    _require(run is not None and source['run_id'] == run['run_id'] and
             source['case_id'] == run.get('source_case_id') and
             source['image'] == run.get('image_relative_path') and
             run.get('image_id') in {e['id'] for e in manifest['evidence']},
             'Citation source/run/image ownership mismatch')
    _require(source['sha256'] == artifact['sha256'], 'Citation and bundled artifact hashes disagree')
    state = artifact.get('source_result', {})
    _require(state.get('source_status') == run['status'], 'Citation source status disagrees with run')
    return resolve_reference(path, ref['structured'], source, state, ref.get('observable'))


def check_bundle(directory: Path) -> dict:
    try:
        return _check_bundle(directory)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid report structure or missing required field: {exc}. See docs/REPORT_SPEC.md.") from exc
