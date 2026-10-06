"""Inspect registered saved run artifacts, never a caller-selected arbitrary file."""
import json
from importlib.metadata import version
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time

from .backend import EvidenceError, file_fingerprint, write_json
from .reuse import digest, execution_lock
from .timestamps import utc_now, timestamped_id


def inspect_saved(backend, image, run_id, artifact, operation, min_length, encoding,
                  offset, limit, scan_bytes, max_string_length, cancel_event):
    event = cancel_event or threading.Event()
    settings = dict(operation=operation, min_length=min_length, encoding=encoding, offset=offset,
                    limit=limit, scan_bytes=scan_bytes, max_string_length=max_string_length)
    if operation not in ('pe', 'strings') or encoding not in ('ascii', 'utf-16le'):
        raise EvidenceError('operation must be pe/strings; encoding must be ascii/utf-16le')
    for name, low, high in [('min_length', 2, 128), ('offset', 0, 64*1024*1024),
                            ('limit', 1, 200), ('scan_bytes', 256, 4*1024*1024), ('max_string_length', 16, 512)]:
        if type(settings[name]) is not int or not low <= settings[name] <= high:
            raise EvidenceError(f'{name} must be an integer in {low}..{high}')
    if not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', run_id):
        raise EvidenceError('Use a saved run_id from case_history')
    relative = Path(artifact)
    if not artifact or relative.is_absolute() or '..' in relative.parts or '\\' in artifact:
        raise EvidenceError('artifact must be an exact run-relative path recorded in its manifest')
    with backend._lock, execution_lock(backend, event) as lock_fd:
        # resolve_input enforces the Workbench registered image set. It performs
        # no full-image read/hash and is also required before accessing a cache hit.
        image_path = backend.resolve_input(image)
        case = backend.case_directory(image_path)
        run = case / 'runs' / run_id
        manifest_path = run / 'manifest.json'
        backend._check_components(manifest_path)
        record = json.loads(manifest_path.read_text())
        if record.get('run_id') != run_id or record.get('image') != str(image_path):
            raise EvidenceError('Run does not belong to the selected registered image')
        source = run / relative
        backend._check_components(source)
        if source.resolve(strict=True) != source or not source.is_relative_to(run):
            raise EvidenceError('Artifact escapes the registered run')
        recorded = next((a for c in record.get('commands', []) for a in c.get('artifacts', [])
                         if a['path'] == str(source)), None)
        if recorded is None:
            raise EvidenceError('Artifact is not registered in this run manifest')
        if source.stat().st_size > 64*1024*1024:
            raise EvidenceError('Inspection limit is 64 MiB; no partial PE verdict produced')
        before = file_fingerprint(source)
        if any(before[k] != recorded[k] for k in ('sha256', 'size_bytes')):
            raise EvidenceError('Saved artifact differs from its extraction manifest; inspection refused')
        if offset > before['size_bytes']:
            raise EvidenceError('offset is beyond the saved artifact')
        worker = Path(__file__).with_name('inspect_worker.py')
        import pefile
        parser = {'name': 'pefile-fast-load / bounded-printable-strings', 'pefile_version': version('pefile'),
                  'python_version': platform.python_version(), 'worker_sha256': file_fingerprint(worker)['sha256'],
                  'parser_sha256': file_fingerprint(Path(pefile.__file__))['sha256']}
        source_ref = {'image_relative_path': str(image_path.relative_to(backend.cases)), 'run_id': run_id,
                      'artifact': artifact, 'sha256': before['sha256'], 'size_bytes': before['size_bytes']}
        identity = dict(source_ref=source_ref, settings=settings, parser=parser,
                        extraction_manifest_sha256=file_fingerprint(manifest_path)['sha256'])
        key = digest(identity)
        root = backend._safe_directory(case / 'inspections')
        for prior in sorted(root.glob('*/manifest.json'), reverse=True):
            try:
                backend._check_components(prior)
                meta = json.loads(prior.read_text())
                if not isinstance(meta, dict): continue
                if meta.get('key') != key or meta.get('status') != 'success' or not meta.get('integrity_verified'): continue
                result_path = prior.parent / 'result.json'
                backend._check_components(result_path)
                if file_fingerprint(result_path)['sha256'] != meta['result_sha256']: continue
                result = json.loads(result_path.read_text())
                if file_fingerprint(source) != before: raise EvidenceError('Artifact changed during inspection reuse')
                return response(meta, prior, result, True)
            except (OSError, KeyError, json.JSONDecodeError):
                continue
        folder = backend._safe_directory(root / timestamped_id())
        meta_path, output, stderr = folder/'manifest.json', folder/'result.json', folder/'stderr.txt'
        meta = {**identity, 'key': key, 'schema_version': '1', 'status': 'running',
                'started_at': utc_now(), 'source_before': before, 'source_run_status': record.get('status'),
                'source_run_integrity_verified': record.get('integrity_verified'),
                'argv': [sys.executable, '-I', str(worker), str(source), json.dumps(settings, sort_keys=True)],
                'shell': False, 'timeout_seconds': min(30, backend.command_timeout)}
        write_json(meta_path, meta)
        result = None
        try:
            with output.open('xb') as out, stderr.open('xb') as err:
                proc = subprocess.Popen(meta['argv'], shell=False, stdin=subprocess.DEVNULL,
                                        stdout=out, stderr=err, start_new_session=True, pass_fds=(lock_fd,))
                deadline = time.monotonic()+meta['timeout_seconds']
                while proc.poll() is None:
                    if event.is_set() or backend.shutdown_event.is_set() or time.monotonic() > deadline:
                        backend._kill(proc)
                        raise EvidenceError('Inspection cancelled or timed out; partial outputs retained, no complete result')
                    event.wait(0.02)
                if proc.returncode:
                    raise EvidenceError('Inspection parser failed: '+backend._tail(stderr)[-1200:])
            result = json.loads(output.read_text())
            meta.update(status='success', result_sha256=file_fingerprint(output)['sha256'])
        except (OSError, ValueError) as exc:
            meta.update(status='error', error=str(exc))
        finally:
            try:
                after = file_fingerprint(source)
                meta.update(source_after=after, integrity_verified=before == after)
                if before != after: meta.update(status='evidence_changed', error='Artifact changed during inspection')
            except (OSError, ValueError) as exc:
                meta.update(status='evidence_changed', integrity_verified=False, error=str(exc))
            meta['completed_at'] = utc_now()
            temporary = folder/'manifest.complete.json'
            write_json(temporary, meta)
            os.replace(temporary, meta_path)
        return response(meta, meta_path, result, False)


def response(meta, path, result, reused):
    from .saved_evidence import source_identity, reference
    saved_reference = None
    if meta['status'] == 'success':
        saved_reference = reference(source_identity(path.parents[3], path.parents[2],
            meta['source_ref']['image_relative_path'], 'inspection-'+path.parent.name,
            'result.json', meta['result_sha256']), {'kind':'json', 'pointer':''})
    return {'status': meta['status'], 'reused': reused, 'evidence_reference': saved_reference, 'source_ref': meta['source_ref'],
            'source_run_status': meta.get('source_run_status'),
            'source_run_integrity_verified': meta.get('source_run_integrity_verified'),
            'integrity_verified': meta.get('integrity_verified'), 'parser': meta['parser'],
            'settings': meta['settings'], 'inspection_id': path.parent.name,
            'manifest_path': str(path), 'result_path': str(path.parent/'result.json'),
            'result': result if meta['status'] == 'success' else None, 'error': meta.get('error'),
            'warning': 'Static inspection of reconstructed bytes; no execution, maliciousness or full-recovery verdict.'}
