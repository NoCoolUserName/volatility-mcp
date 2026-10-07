"""Conservative persistent reuse; no database, evidence shortcuts, or job scheduler."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
from .relocation import resolved_path
import stat
import time


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class HashMeasurements:
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint
        self.groups = {}

    def file(self, path, group):
        metric = self.groups.setdefault(group, {'seconds': 0.0, 'bytes': 0, 'files': 0})
        start = time.perf_counter()
        try:
            result = self.fingerprint(path)
            metric['bytes'] += result['size_bytes']
            metric['files'] += 1
            return result
        finally:
            metric['seconds'] += time.perf_counter() - start

    def content(self, path, group):
        record = self.file(path, group)
        return {'path': str(path), 'sha256': record['sha256'], 'size_bytes': record['size_bytes']}

    def summary(self):
        return {'clock': 'perf_counter', 'groups': self.groups,
                'total_seconds': sum(g['seconds'] for g in self.groups.values()),
                'total_bytes': sum(g['bytes'] for g in self.groups.values())}


@contextmanager
def execution_lock(backend, event):
    """Serialize backends sharing an output root, including independent clients.

    Never unlink the lock: replacing its inode could create two lock owners.
    The kernel releases it on process exit; there are no stale PID lock files.
    """
    path = backend._safe_directory(backend.outputs) / '.execution.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Execution lock must be a regular file')
        deadline = time.monotonic() + backend.command_timeout + backend.config.catalog_timeout
        while True:
            if event.is_set() or backend.shutdown_event.is_set():
                raise ValueError('Analysis cancelled while waiting for the execution lock; no plugin started.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('Timed out waiting for another analysis in this output root; inspect case_history before retrying.')
                event.wait(0.05)
        yield fd
    finally:
        os.close(fd)


def context_identity(backend, plugin, values, hashes):
    """Hash relevant bytes, deliberately favoring safe misses over weak identity."""
    catalog = backend.catalog()
    runtime = set(catalog.get('runtime_files', []))
    runtime.update(str(p) for p in (backend.vol_python, backend.vol))
    runtime.update(str(backend.project / name) for name in
                   ('backend.py', 'reuse.py', 'catalog.py', 'json_rows.py', 'prepare_symbol_cache.py'))
    if backend.config.enable_xpnet:
        backend._plugin_arguments()
        runtime.update(str(p) for p in backend.local_plugins.rglob('*.py'))
    for metadata in catalog['plugins'].values():
        if metadata.get('source_file'):
            runtime.add(metadata['source_file'])
    # Executables in venvs are commonly symlinks. These are operator-controlled,
    # unlike evidence/output paths; include both configured and resolved identity.
    runtime_records = []
    for name in sorted(runtime):
        path = Path(name).resolve(strict=True)
        runtime_records.append([name, hashes.content(path, 'runtime')])
    symbol_records = []
    for root in (backend.supplemental_symbols, backend.symbol_cache):
        if root is None:
            continue
        backend._check_components(root)
        for folder, dirs, files in os.walk(root, followlinks=False):
            for name in sorted([*dirs, *files]):
                path = Path(folder) / name
                backend._check_components(path)
                if path.is_file():
                    # The preparation audit is not an input to Volatility. Its
                    # timestamp changes even when the selected symbols do not.
                    if root == backend.symbol_cache and path.name in ('preference.json', 'preference.complete.json'):
                        continue
                    symbol_records.append(hashes.content(path, 'symbols'))
    inputs = {}
    for option in catalog['plugins'][plugin]['options']:
        value = values.get(option['dest'])
        if option['is_path'] and value is not None:
            inputs[option['dest']] = [hashes.file(backend.resolve_input(item, memory_image=False), 'input_files')
                                     for item in (value if isinstance(value, list) else [value])]
    return {'schema': 1, 'catalog': {k: catalog.get(k) for k in
                                   ('version', 'architecture', 'python_version', 'packages', 'import_failures', 'reuse_blockers')},
            'plugin': catalog['plugins'][plugin],
            'runtime': digest(runtime_records), 'symbols': digest(sorted(symbol_records, key=lambda r: r['path'])),
            'input_files': inputs, 'python': str(backend.vol_python), 'vol': str(backend.vol),
            'symbol_root': str(backend.supplemental_symbols), 'cache_root': str(backend.symbol_cache),
            'enable_xpnet': backend.config.enable_xpnet, 'timeout': backend.command_timeout}


def find_completed(backend, case, key, hashes):
    """Validate immutable original artifacts before returning a reusable manifest."""
    runs = backend._safe_directory(case / 'runs')
    for path in sorted(runs.glob('*/manifest.json'), reverse=True):
        try:
            backend._check_components(path)
            record = json.loads(path.read_text())
            if not isinstance(record, dict):
                continue
            if (record.get('reuse_key') != key or not record.get('reuse_eligible') or
                    record.get('status') != 'success' or not record.get('integrity_verified') or
                    not record.get('completed_at') or len(record.get('commands', [])) != 1):
                continue
            if (record['image_before'] != record['image_after'] or
                    record['image_sha256_before'] != record['image_sha256_after'] or
                    record['artifact_path'] != str(path.parent) or record['run_id'] != path.parent.name):
                continue
            command = record['commands'][0]
            if command['status'] != 'success' or command['returncode'] != 0:
                continue
            artifacts = command['artifacts']
            expected = {str(path.parent / 'command.started.json')}
            expected.update(a['path'] for a in artifacts)
            if record.get('plugin_provenance'):
                artifacts = [*artifacts, record['plugin_provenance']['snapshot']]
                expected.add(record['plugin_provenance']['snapshot']['path'])
            required = {command['stdout_path'], command['stderr_path'], command['json_path'], command['text_path'],
                        str(path.parent / 'command.started.json')}
            if not required.issubset({a['path'] for a in artifacts}):
                continue
            for artifact in artifacts:
                item = Path(artifact['path'])
                if not item.is_relative_to(path.parent):
                    raise ValueError('Cached artifact outside original run')
                backend._check_components(item)
                if resolved_path(item, strict=True) != item or not resolved_path(item).is_relative_to(path.parent):
                    raise ValueError('Cached artifact escapes original run')
                current = hashes.file(item, 'saved_artifacts')
                if any(current[k] != artifact[k] for k in ('sha256', 'size_bytes')):
                    raise ValueError('Cached artifact changed')
            # Detect additions/removals and do not follow directories replaced by links.
            actual = set()
            for item in path.parent.rglob('*'):
                backend._check_components(item)
                if item.is_file() and item != path:
                    actual.add(str(item))
            if actual != expected:
                continue
            return record, path
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Corrupt/incomplete/missing artifacts are a cache miss, never clean evidence.
            continue
    return None
