"""Conservative persistent reuse; no evidence shortcuts."""
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
        self.symbol_inventory = {'method': 'trusted-local-filesystem-metadata-v1',
                                 'content_bytes_read': 0, 'files': 0, 'directories': 0, 'seconds': 0.0}

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
        return {'clock': 'perf_counter', 'groups': self.groups, 'symbol_inventory': dict(self.symbol_inventory),
                'total_seconds': sum(g['seconds'] for g in self.groups.values()),
                'total_bytes': sum(g['bytes'] for g in self.groups.values())}


def _open_lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('Execution lock must be a regular file')
    return fd


def _acquire(fd, backend, event, *, shared=False):
    deadline = time.monotonic() + backend.command_timeout + backend.config.catalog_timeout
    while True:
        if event.is_set() or backend.shutdown_event.is_set():
            raise ValueError('Analysis cancelled while waiting for execution; no plugin started.')
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise ValueError('Timed out waiting for another analysis; inspect case_history before retrying.')
            event.wait(0.05)


@contextmanager
def execution_lock(backend, event, key=None):
    """Cross-process singleflight and bounded slots; children inherit every lease.

    The unkeyed form is an exclusive maintenance gate, retained for integrations.
    Keyed requests share that gate and each own one key and one execution slot.
    Lock inodes are never replaced or unlinked; the kernel releases dead owners.
    """
    root = backend._safe_directory(backend.outputs)
    gate = _open_lock(root / '.execution.lock')
    fds = [gate]
    try:
        _acquire(gate, backend, event, shared=key is not None)
        if key is None:
            yield gate
            return
        directory = backend._safe_directory(root / '.execution')
        keys = backend._safe_directory(directory / 'keys')
        duplicate = _open_lock(keys / (key + '.lock'))
        fds.append(duplicate)
        _acquire(duplicate, backend, event)
        deadline = time.monotonic() + backend.command_timeout + backend.config.catalog_timeout
        while True:
            if event.is_set() or backend.shutdown_event.is_set():
                raise ValueError('Analysis cancelled while waiting for an execution slot; no plugin started.')
            policy_fd = _open_lock(directory / 'policy.lock')
            slot = None
            try:
                _acquire(policy_fd, backend, event)
                policy = directory / 'policy.json'
                backend._check_components(policy)
                previous = json.loads(policy.read_text()) if policy.exists() else None
                limit = backend.config.max_concurrent_runs
                if previous != {'max_concurrent_runs': limit}:
                    # A setting changes only at an idle boundary. Clients with
                    # conflicting live configs must never form disjoint pools.
                    proof = []
                    try:
                        for index in range(64):
                            fd = _open_lock(directory / f'slot-{index:03}.lock')
                            proof.append(fd)
                            try:
                                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            except BlockingIOError as exc:
                                raise ValueError('Concurrency setting differs from an active client. Wait for idle and reload all clients with the same max_concurrent_runs.') from exc
                        import uuid
                        temporary = directory / ('policy-' + uuid.uuid4().hex + '.json')
                        with temporary.open('x') as stream:
                            json.dump({'max_concurrent_runs': limit}, stream)
                        os.replace(temporary, policy)
                    finally:
                        for fd in proof:
                            os.close(fd)
                for index in range(limit):
                    candidate = _open_lock(directory / f'slot-{index:03}.lock')
                    try:
                        fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        os.close(candidate)
                    else:
                        slot = candidate
                        break
            finally:
                os.close(policy_fd)
            if slot is not None:
                fds.append(slot)
                break
            if time.monotonic() >= deadline:
                raise ValueError('Timed out waiting for an execution slot; inspect case_history before retrying.')
            event.wait(0.05)
        yield tuple(fds)
    finally:
        for fd in reversed(fds):
            os.close(fd)


def isolated_cache(backend, key, event, verify_seed=None):
    """Seed an identity-private cache; no analyzer writes configured shared state.

    Caller holds the key lease. SQLite backup creates coherent snapshots even
    when a separately managed source cache uses a WAL. Sidecars are not copied.
    """
    import shutil
    import sqlite3
    import uuid
    seed = backend.config.cache_path
    root = backend._safe_directory(backend.outputs / '.execution' / 'caches')
    destination = root / key
    backend._check_components(destination)
    if destination.exists():
        return destination
    temporary = backend._safe_directory(root / ('.seed-' + uuid.uuid4().hex))
    try:
        deadline = time.monotonic() + backend.config.catalog_timeout
        def cancelled(*args):
            if event.is_set() or backend.shutdown_event.is_set():
                raise ValueError('Analysis cancelled during private cache preparation; no plugin started.')
            if time.monotonic() >= deadline:
                raise ValueError('Private cache preparation timed out; no plugin started.')
        for folder, dirs, files in os.walk(seed, followlinks=False):
            cancelled()
            if backend.supplemental_symbols is not None:
                dirs[:] = [name for name in dirs if Path(folder) / name != backend.supplemental_symbols]
            relative = Path(folder).relative_to(seed)
            target = backend._safe_directory(temporary / relative)
            for name in [*dirs, *files]:
                backend._check_components(Path(folder) / name)
            for name in files:
                cancelled()
                source = Path(folder) / name
                if name.endswith(('-wal', '-shm', '-journal')):
                    continue
                with source.open('rb') as stream:
                    sqlite = stream.read(16) == b'SQLite format 3\0'
                if sqlite:
                    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=0) as src:
                        with sqlite3.connect(target / name) as dst:
                            src.backup(dst, pages=256, progress=cancelled, sleep=0.05)
                    (target / name).chmod(0o600)
                else:
                    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as src, (target / name).open('xb') as dst:
                        if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                            raise ValueError('Configured cache entry is not a regular file.')
                        while chunk := src.read(1024 * 1024):
                            cancelled()
                            dst.write(chunk)
                    (target / name).chmod(0o600)
        if verify_seed is not None:
            verify_seed()
        os.rename(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return destination


SYMBOL_CODE_EXTENSIONS = frozenset({'.py', '.pyi', '.so', '.dylib', '.dll', '.pyd'})
SYMBOL_IDENTITY_METHOD = 'trusted-local-filesystem-metadata-v1'


def symbol_inventory(backend, roots, hashes):
    """Observe local metadata only, without opening or hashing symbol contents.

    Directory entries detect additions/removals without volatile directory
    timestamps. File ctime detects ordinary rewrites that restore mtime.
    This is change detection, not cryptographic verification.
    """
    start = time.perf_counter()
    records = []
    metric = hashes.symbol_inventory
    try:
        for role, root in roots:
            backend._check_components(root)
            try:
                root_stat = root.lstat()
            except FileNotFoundError:
                records.append({'root': role, 'path': '.', 'kind': 'missing'})
                continue
            if not stat.S_ISDIR(root_stat.st_mode):
                raise ValueError('Configured symbol/cache root must be a directory.')
            records.append({'root': role, 'path': '.', 'kind': 'directory'})
            metric['directories'] += 1
            binding = (root_stat.st_dev, root_stat.st_ino)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                anchored = os.fstat(root_fd)
                if (anchored.st_dev, anchored.st_ino) != binding:
                    raise ValueError('Symbol/cache root changed during inventory.')
                expected_dirs = {'.': binding}

                def fail(error):
                    raise error

                walker = os.fwalk('.', dir_fd=root_fd, follow_symlinks=False, onerror=fail)
                try:
                    for folder, dirs, files, directory_fd in walker:
                        relative_folder = Path(folder)
                        opened = os.fstat(directory_fd)
                        actual = (opened.st_dev, opened.st_ino)
                        if expected_dirs.pop(relative_folder.as_posix(), None) != actual:
                            raise ValueError('Symbol/cache directory changed during inventory.')
                        for name in sorted([*dirs, *files]):
                            relative = relative_folder / name
                            # Relative no-follow metadata is anchored to the
                            # opened parent. Do not restat every ancestor for
                            # every leaf; neither payloads nor links are opened.
                            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                                raise ValueError('Symbol/cache entries must be regular files or directories; symlinks are forbidden.')
                            if (name == '__pycache__' or name.endswith('.pyc') or
                                    (role == 'cache' and (name in ('preference.json', 'preference.complete.json')
                                                          or name.endswith('-shm')))):
                                continue
                            kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file'
                            record = {'root': role, 'path': relative.as_posix(), 'kind': kind}
                            if kind == 'directory':
                                metric['directories'] += 1
                                expected_dirs[relative.as_posix()] = (info.st_dev, info.st_ino)
                            else:
                                metric['files'] += 1
                                record.update(size_bytes=info.st_size, mtime_ns=info.st_mtime_ns,
                                              ctime_ns=info.st_ctime_ns, device=info.st_dev, inode=info.st_ino)
                            records.append(record)
                        dirs[:] = sorted(name for name in dirs if name != '__pycache__')
                finally:
                    walker.close()
                # fwalk intentionally skips a directory replaced between its
                # stat and open. Such a partial inventory must never be accepted.
                if expected_dirs:
                    raise ValueError('Symbol/cache directory changed or disappeared during inventory.')
                backend._check_components(root)
                current = root.lstat()
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != binding:
                    raise ValueError('Symbol/cache root changed during inventory.')
            finally:
                os.close(root_fd)
        return records
    finally:
        metric['seconds'] += time.perf_counter() - start


def context_identity(backend, plugin, values, hashes):
    """Hash relevant bytes, deliberately favoring safe misses over weak identity."""
    catalog = backend.catalog()
    runtime = set(catalog.get('runtime_files', []))
    runtime.update(str(p) for p in (backend.vol_python, backend.vol))
    runtime.update(str(backend.project / name) for name in
                   ('backend.py', 'reuse.py', 'execution.py', 'catalog.py', 'json_rows.py', 'prepare_symbol_cache.py'))
    if backend.config.enable_xpnet:
        backend._plugin_arguments()
        runtime.update(str(p) for p in backend.local_plugins.rglob('*.py'))
    for metadata in catalog['plugins'].values():
        if metadata.get('source_file'):
            runtime.add(metadata['source_file'])
    # Executables in venvs are commonly symlinks. These are operator-controlled,
    # unlike evidence/output paths; include both configured and resolved identity.
    installed_symbol_roots = [Path(name) for name in catalog.get('symbol_roots', [])]
    all_symbol_roots = [*installed_symbol_roots, backend.symbol_cache]
    if backend.supplemental_symbols is not None:
        all_symbol_roots.append(backend.supplemental_symbols)
    runtime_records = []
    for name in sorted(runtime):
        candidate = Path(name).absolute()
        if (candidate.suffix not in SYMBOL_CODE_EXTENSIONS and
                any(candidate.is_relative_to(root) for root in all_symbol_roots)):
            continue
        path = Path(name).resolve(strict=True)
        runtime_records.append([name, hashes.content(path, 'runtime')])
    roots = [('installed:' + str(root), root) for root in installed_symbol_roots]
    if backend.supplemental_symbols is not None:
        roots.append(('supplemental', backend.supplemental_symbols))
    roots.append(('cache', backend.symbol_cache))
    symbol_records = symbol_inventory(backend, roots, hashes)
    inputs = {}
    for option in catalog['plugins'][plugin]['options']:
        value = values.get(option['dest'])
        if option['is_path'] and value is not None:
            inputs[option['dest']] = [hashes.file(backend.resolve_input(item, memory_image=False), 'input_files')
                                     for item in (value if isinstance(value, list) else [value])]
    return {'schema': 1, 'catalog': {k: catalog.get(k) for k in
                                   ('version', 'architecture', 'python_version', 'packages', 'import_failures', 'reuse_blockers')},
            'plugin': catalog['plugins'][plugin],
            'runtime': digest(runtime_records), 'symbols': digest(symbol_records),
            'symbols_identity_method': SYMBOL_IDENTITY_METHOD, 'symbol_content_verified': False,
            'symbol_roots': [str(root) for root in installed_symbol_roots],
            'input_files': inputs, 'python': str(backend.vol_python), 'vol': str(backend.vol),
            'symbol_root': str(backend.supplemental_symbols), 'cache_root': str(backend.config.cache_path),
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
