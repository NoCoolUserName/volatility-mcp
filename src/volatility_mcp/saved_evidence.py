"""Bounded saved-result queries and versioned source locators; never invokes analysis.

No persistent index is needed: lazily derive rows from the hash-verified source.
Pointers address the original JSON tree, independent of query order or pagination.
"""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import re
import time

from .backend import EvidenceError, file_fingerprint

SCHEMA = 'saved-evidence/1'
PARSER = 'json-tree/1'
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 200_000
MAX_RESPONSE = 60_000
MISSING = object()


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def portable(value):
    """JSON numbers outside JS's safe range are losslessly tagged, never rounded."""
    if type(value) is int and abs(value) > 2**53-1:
        return {'$integer': str(value)}
    if isinstance(value, dict):
        return {k: portable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [portable(v) for v in value]
    return value


def source_identity(output_root, case_dir, image_relative, run_id, artifact, sha256):
    return {'case_id': case_dir.name,
            'namespace': hashlib.sha256(str(output_root).encode()).hexdigest(),
            'image': image_relative, 'run_id': run_id, 'artifact': artifact,
            'sha256': sha256, 'parser': PARSER}


def identity(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', value),
            'Use a saved run/inspection ID')
    return value


def relative(value):
    require(isinstance(value, str) and value and not Path(value).is_absolute() and
            '..' not in Path(value).parts and '\\' not in value, 'Use an exact registered relative artifact path')
    return value


def resolve_source(backend, image, run_id, artifact):
    image_path = backend.resolve_input(image)  # stat/registration only; no image hashing
    case = backend.case_directory(image_path)
    identity(run_id); relative(artifact)
    inspection = run_id.startswith('inspection-')
    folder = case / ('inspections' if inspection else 'runs') / (run_id[11:] if inspection else run_id)
    manifest = folder/'manifest.json'
    backend._check_components(manifest)
    require(manifest.is_file(), 'Saved run is missing; use case_history. No collection was started.')
    require(manifest.stat().st_size <= MAX_BYTES, 'Run manifest exceeds query limit')
    record = json.loads(manifest.read_text())
    path = folder/artifact
    backend._check_components(path)
    require(path.resolve().is_relative_to(folder) and path.is_file(), 'Saved artifact is missing or escapes its run')
    if inspection:
        parent = record['source_ref']
        require(not parent['run_id'].startswith('inspection-'), 'Inspection parent must be an original extraction run')
        require(parent['image_relative_path'] == str(image_path.relative_to(backend.cases)), 'Inspection belongs to another image')
        require(artifact == 'result.json', 'Query inspection result.json; use read_output for diagnostics')
        # Verify both the derived result and the registered input, without inspecting again.
        _, original, parent_state = resolve_source(backend, image, parent['run_id'], parent['artifact'])
        require(original['sha256'] == parent['sha256'], 'Inspection source changed')
        expected = record.get('result_sha256')
        format_kind = record['settings']['operation']
    else:
        require(record.get('run_id') == run_id and record.get('image') == str(image_path), 'Run belongs to another image')
        registered = next((a for c in record.get('commands', []) for a in c.get('artifacts', [])
                           if a['path'] == str(path)), None)
        require(registered is not None, 'Artifact is not registered in the saved run')
        expected = registered['sha256']
        format_kind = 'volatility' if any(c.get('stdout_path') == str(path) or c.get('json_path') == str(path)
                                           for c in record.get('commands', [])) else 'raw'
        require(path.stat().st_size == registered['size_bytes'], 'Saved artifact size changed')
    # Large binary artifacts can still be read through the existing raw reader.
    require(path.stat().st_size <= MAX_BYTES, 'Saved artifact exceeds 64 MiB structured-access limit; use read_output')
    fp = file_fingerprint(path)
    require(fp['sha256'] == expected, 'Saved artifact hash changed; refusing stale evidence')
    source = source_identity(backend.outputs, case, str(image_path.relative_to(backend.cases)), run_id, artifact, expected)
    state = {'source_status': record.get('status', 'unknown'),
             'integrity_verified': record.get('integrity_verified') is True,
             'completed': bool(record.get('completed_at')),
             'failure_category': record.get('failure_category'), 'format': format_kind,
             'raw_path': str(path)}
    if inspection:
        state.update(source_run_status=parent_state['source_status'],
                     source_run_integrity_verified=parent_state['integrity_verified'],
                     integrity_verified=state['integrity_verified'] and parent_state['integrity_verified'],
                     inspection_parser=record.get('parser'),
                     source_artifact=parent, inspection_settings=record.get('settings'))
    return path, source, state


def _pairs(items):
    result = {}
    for k, v in items:
        require(k not in result, 'Duplicate JSON keys are unsupported')
        result[k] = v
    return result


def load_tree(path):
    require(path.stat().st_size <= MAX_BYTES, 'Structured source exceeds 64 MiB')
    try:
        data = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda v: require(False, 'Nonfinite JSON number is unsupported'))
        stack, count = [(data, 0)], 0
        deadline = time.monotonic()+10
        while stack:
            node, depth = stack.pop(); count += 1
            require(depth <= 64 and count <= MAX_NODES and time.monotonic() < deadline,
                    'JSON exceeds depth/node/time query budget; use read_output')
            if type(node) is float: require(math.isfinite(node), 'Nonfinite JSON number is unsupported')
            if isinstance(node, dict): stack.extend((v, depth+1) for v in node.values())
            elif isinstance(node, list): stack.extend((v, depth+1) for v in node)
        return data
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise EvidenceError('Unsupported or incomplete JSON; use read_output: '+str(exc)[:200]) from exc


def escape(value):
    return value.replace('~', '~0').replace('/', '~1')


def pointer(data, location):
    require(isinstance(location, str) and len(location) <= 2048 and
            (location == '' or location.startswith('/')), 'Use an RFC 6901 JSON pointer')
    if location == '': return data
    for raw in location[1:].split('/'):
        require(not re.search(r'~(?![01])', raw), 'Invalid JSON pointer escape')
        part = raw.replace('~1', '/').replace('~0', '~')
        if isinstance(data, list):
            require(bool(re.fullmatch(r'0|[1-9][0-9]*', part)) and int(part) < len(data), 'Citation array index out of range')
            data = data[int(part)]
        else:
            require(isinstance(data, dict) and part in data, 'Citation field/row does not exist')
            data = data[part]
    return data


def rows(data, kind):
    if kind == 'volatility':
        require(isinstance(data, list), 'Expected Volatility JSON row array')
        result = []
        def visit(items, prefix, parent):
            require(isinstance(items, list), '__children must be an array')
            for i, row in enumerate(items):
                require(isinstance(row, dict), 'Expected object rows')
                loc = prefix+'/'+str(i)
                result.append((loc, parent, {k:v for k,v in row.items() if k != '__children'}))
                visit(row.get('__children', []), loc+'/__children', loc)
        visit(data, '', None)
        return result
    require(isinstance(data, dict), 'Expected inspection result object')
    if kind == 'strings':
        require(isinstance(data.get('records'), list) and all(isinstance(r, dict) for r in data['records']), 'Invalid string records')
        return [('/records/'+str(i), '', row) for i, row in enumerate(data['records'])]
    require(kind == 'pe', 'Unsupported saved format; use read_output')
    return [('', None, data)]


def field_pointer(field):
    require(isinstance(field, str) and 0 < len(field) <= 512, 'Field must be a nonempty name or relative JSON pointer')
    if field.startswith('/'):
        require(not re.search(r'~(?![01])', field), 'Invalid field pointer escape')
    return field if field.startswith('/') else '/'+escape(field)


def field_value(row, field):
    try: return pointer(row, field_pointer(field))
    except EvidenceError: return MISSING


def typed(value, kind, *, allow_tag=False):
    if kind == 'integer':
        if allow_tag and isinstance(value, dict) and set(value) == {'$integer'}: value = value['$integer']
        if type(value) is int: return value
        if isinstance(value, str) and re.fullmatch(r'-?(?:0[xX][0-9a-fA-F]+|[0-9]+)', value):
            return int(value, 16 if 'x' in value.lower() else 10)
    elif kind == 'string' and isinstance(value, str): return value
    elif kind == 'boolean' and type(value) is bool: return value
    elif kind == 'null' and value is None: return None
    elif kind == 'number' and type(value) in (int, float): return value
    raise EvidenceError('Value does not have declared type '+str(kind))


def compare(actual, observable):
    require(isinstance(observable, dict) and set(observable) == {'type', 'value'}, 'Observable requires exactly type and value')
    expected = typed(observable['value'], observable['type'], allow_tag=True)
    actual = typed(actual, observable['type'])
    require(actual == expected, 'Observable value mismatch')
    return 'matched'


def reference(source, locator):
    return {'schema': SCHEMA, 'source': source, 'locator': locator}


def resolve_reference(path, ref, source, state, observable=None):
    require(isinstance(ref, dict) and ref.get('schema') == SCHEMA, 'Unsupported reference version')
    require(ref.get('source') == source and source.get('parser') == PARSER, 'Cross-case, stale or mismatched citation source')
    require(state.get('integrity_verified') is True, 'Source run integrity is unverified; citation cannot be verified')
    before = file_fingerprint(path)
    require(before['sha256'] == source['sha256'], 'Citation source hash mismatch')
    loc = ref.get('locator', {})
    if loc.get('kind') == 'json':
        value = pointer(load_tree(path), loc.get('pointer'))
    elif loc.get('kind') == 'bytes':
        offset, length = loc.get('offset'), loc.get('length')
        require(type(offset) is int and type(length) is int and offset >= 0 and 1 <= length <= 4096
                and offset+length <= before['size_bytes'], 'Citation byte range out of bounds')
        encoding = loc.get('encoding', 'hex')
        require(encoding in ('hex', 'ascii', 'utf-16le'), 'Unsupported byte citation encoding')
        with path.open('rb') as stream:
            stream.seek(offset); raw = stream.read(length)
        try: value = raw.hex() if encoding == 'hex' else raw.decode(encoding)
        except UnicodeError as exc: raise EvidenceError('Byte range does not decode with specified encoding') from exc
    else: raise EvidenceError('Unknown citation locator kind')
    validation = compare(value, observable) if observable is not None else 'not_declared'
    require(file_fingerprint(path) == before, 'Evidence changed while resolving citation')
    result = {'reference': ref, 'value': portable(value), 'source_result': state,
              'provenance_validation': 'verified', 'observable_validation': validation,
              'interpretation_validation': 'not_checked',
              'limitation': 'Matching observations do not verify narrative claims, inference, or maliciousness.'}
    require(len(json.dumps(result)) <= MAX_RESPONSE, 'Resolved value exceeds response budget; select a smaller field or byte range')
    return result


def get_evidence(backend, ref, observable=None):
    require(isinstance(ref, dict) and isinstance(ref.get('source'), dict), 'Reference requires source identity')
    s = ref['source']
    path, source, state = resolve_source(backend, s.get('image'), s.get('run_id'), s.get('artifact'))
    return resolve_reference(path, ref, source, state, observable)


def query_output(backend, image, run_id, artifact, fields=None, filters=None, sort=None,
                 offset=0, limit=100, group_by=None):
    for value, low, high, label in [(offset,0,MAX_NODES,'offset'),(limit,1,200,'limit')]:
        require(type(value) is int and low <= value <= high, label+' outside query bounds')
    for value, cap, label in [(fields,32,'fields'),(filters,16,'filters'),(sort,4,'sort'),(group_by,4,'group_by')]:
        require(value is None or isinstance(value,list) and len(value)<=cap, label+' must be a bounded list')
    require(all(isinstance(f, dict) for f in (filters or []) + (sort or [])), 'Filters and sort entries must be objects')
    path, source, state = resolve_source(backend, image, run_id, artifact)
    base = {'source':source, 'source_result':state, 'offset':offset, 'limit':limit,
            'parser':PARSER, 'schema':SCHEMA, 'matching_count':None, 'returned_count':0,
            'truncated':False, 'next_offset':None, 'rows':[]}
    before = file_fingerprint(path)
    try:
        require(state['format'] in ('volatility','strings','pe'), 'Unsupported saved format; use read_output')
        tree = load_tree(path); records = rows(tree,state['format'])
    except EvidenceError as exc:
        return {**base, 'status':'unsupported_format', 'error':str(exc), 'raw_reader':'read_output'}
    # Complete parsing before answering: a valid prefix of malformed output is not a result.
    fields = fields or sorted({k for _,_,row in records for k in row})
    require(len(fields)<=32, 'Select at most 32 fields')
    selectors = fields + (group_by or []) + [f.get('field') for f in filters or []] + [s.get('field') for s in sort or []]
    for field in selectors:
        field_pointer(field)
        require(not records or any(field_value(row,field) is not MISSING for _,_,row in records), 'Unknown query field: '+field)
    prepared = []
    for f in filters or []:
        require(set(f) <= {'field','op','type','value'} and f.get('op') in ('eq','ne','lt','le','gt','ge','contains','starts_with','exists'), 'Unsupported filter operator/keys')
        op = f['op']
        if op == 'exists':
            require(type(f.get('value')) is bool, 'exists requires a boolean value')
            prepared.append((f,None)); continue
        require(f.get('type') in ('integer','number','string','boolean','null'), 'Filter requires an explicit type')
        v = typed(f.get('value'),f['type'],allow_tag=True)
        if isinstance(v, str): require(len(v)<=1024, 'Filter string exceeds 1024 characters')
        if op in ('contains','starts_with'):
            require(f['type']=='string' and len(v)<=1024, 'Text filter requires a string of at most 1024 characters')
        if op in ('lt','le','gt','ge'): require(f['type'] in ('integer','number','string'), 'Comparison requires an ordered type')
        prepared.append((f,v))
    def matches(row):
        for f, expected in prepared:
            actual = field_value(row,f['field']); op=f['op']
            if op=='exists':
                if (actual is not MISSING) != f['value']:return False
                continue
            try: value=typed(actual,f['type'])
            except EvidenceError:return False
            if not {'eq':lambda:value==expected,'ne':lambda:value!=expected,
                    'lt':lambda:value<expected,'le':lambda:value<=expected,'gt':lambda:value>expected,'ge':lambda:value>=expected,
                    'contains':lambda:expected in value,'starts_with':lambda:value.startswith(expected)}[op]():return False
        return True
    matched=[r for r in records if matches(r[2])]
    for s in reversed(sort or []):
        require(set(s)<={'field','type','direction'} and s.get('direction','asc') in ('asc','desc'), 'Invalid sort contract')
        kind=s.get('type'); typed({'integer':0,'number':0,'string':'','boolean':False,'null':None}.get(kind),kind)
        def key(row):
            try:return (0, typed(field_value(row[2],s['field']),kind))
            except EvidenceError:return (1, '')
        # Missing/incompatible values last in both directions; equal values retain source order.
        valid=[r for r in matched if key(r)[0]==0]; invalid=[r for r in matched if key(r)[0]!=0]
        matched=sorted(valid,key=key,reverse=s.get('direction')=='desc')+invalid
    base.update(matching_count=len(matched), total_rows=len(records),
                status='ok', result_state=('successful_empty' if not records else 'successful')
                if state['source_status']=='success' and state['completed'] and state['integrity_verified'] else 'collection_not_successful')
    if state['format']=='strings': base['inspection_page']={k:v for k,v in tree.items() if k!='records'}
    if state['format'] in ('pe', 'strings') and base['result_state'] in ('successful', 'successful_empty'):
        base['result_state'] = 'saved_inspection_only'
    items=[]
    if group_by:
        groups={}
        for _,_,row in matched:
            values={f:portable(field_value(row,f)) for f in group_by if field_value(row,f) is not MISSING}
            key=json.dumps(values,sort_keys=True)
            if key not in groups:groups[key]={'values':values,'count':0,'missing_fields':[f for f in group_by if field_value(row,f) is MISSING]}
            groups[key]['count']+=1
        candidates=list(groups.values()); base['group_count']=len(candidates)
    else:
        candidates=matched
    used=len(json.dumps(base))
    for item in candidates[offset:offset+limit]:
        if group_by: result=item
        else:
            loc,parent,row=item
            result={'locator':loc,'parent_locator':parent,'values':{f:portable(field_value(row,f)) for f in fields if field_value(row,f) is not MISSING},
                    'missing_fields':[f for f in fields if field_value(row,f) is MISSING],
                    'reference':reference(source,{'kind':'json','pointer':loc}),
                    'field_locators':{f:loc+field_pointer(f) for f in fields if field_value(row,f) is not MISSING}}
        size=len(json.dumps(result))
        if used+size>MAX_RESPONSE:
            require(bool(items), 'One query row exceeds response budget; select fewer/smaller fields')
            break
        used+=size; items.append(result)
    require(file_fingerprint(path)==before, 'Saved artifact changed while querying')
    end=offset+len(items)
    base.update(rows=items,returned_count=len(items),truncated=end<len(candidates),
                next_offset=end if end<len(candidates) else None)
    return base
