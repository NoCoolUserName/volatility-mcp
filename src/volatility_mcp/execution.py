"""Explicit bounded jobs with private cross-process status and cancellation."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import fcntl
import json
import math
import os
import re
import threading
import uuid
from .timestamps import timestamped_id, utc_now
from .reuse import _open_lock

ACTIVE = frozenset({'queued', 'running'})
JOB_ID = re.compile(r'^[A-Za-z0-9_-]{1,96}$')


class JobCancellation:
    def __init__(self, path, backend):
        self.path, self.backend = path, backend
        self.event = threading.Event()

    def is_set(self):
        self.backend._check_components(self.path)
        return self.event.is_set() or self.path.exists() or self.backend.shutdown_event.is_set()

    def set(self):
        self.event.set()

    def wait(self, timeout):
        if self.is_set():
            return True
        self.event.wait(min(timeout, 0.1))
        return self.is_set()


class JobManager:
    def __init__(self, backend):
        self.backend = backend
        self.root = backend._safe_directory(backend.outputs / '.jobs')
        self.pool = ThreadPoolExecutor(max_workers=backend.config.max_concurrent_runs,
                                       thread_name_prefix='volatility-job')
        self.lock = threading.RLock()
        self.events = {}
        self.closed = False

    def _path(self, job_id, suffix='.json'):
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ValueError('Invalid job_id.')
        path = self.root / (job_id + suffix)
        self.backend._check_components(path)
        return path

    def _save(self, record):
        path = self._path(record['job_id'])
        temporary = self._path(record['job_id'] + '-' + uuid.uuid4().hex)
        try:
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump(record, stream, ensure_ascii=True, indent=2)
                stream.write('\n')
            temporary.chmod(0o600)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _read(self, job_id):
        try:
            record = json.loads(self._path(job_id).read_text())
        except FileNotFoundError as exc:
            raise ValueError('Unknown job_id.') from exc
        if not isinstance(record, dict) or record.get('job_id') != job_id:
            raise ValueError('Invalid saved job record.')
        self.backend.authorize_saved_image(record['image'])
        return record

    def get(self, job_id):
        record = self._read(job_id)
        record['cancel_requested'] = self._path(job_id, '.cancel').exists()
        if record['state'] in ACTIVE:
            fd = _open_lock(self._path(job_id, '.lock'))
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    record['state'] = 'interrupted'
                    record['error'] = ('Job owner is no longer active. Saved run artifacts may be partial; '
                                       'inspect case_history before explicitly submitting new work.')
            finally:
                os.close(fd)
        return record

    def list(self, offset=0, limit=100):
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError('offset must be a nonnegative integer.')
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 256:
            raise ValueError('limit must be an integer from 1 to 256.')
        records = []
        for path in sorted(self.root.glob('*.json'), reverse=True):
            try:
                record = self.get(path.stem)
            except (ValueError, OSError, KeyError, TypeError):
                continue
            if record.get('result'):
                record['result'] = {k: record['result'].get(k) for k in
                    ('status', 'run_id', 'manifest_path', 'reused', 'row_count', 'summary')}
            records.append(record)
        count = len(records)
        selected = records[offset:offset + limit]
        return {'jobs': selected, 'count': count, 'returned_count': len(selected),
                'offset': offset, 'limit': limit,
                'next_offset': offset + len(selected) if offset + len(selected) < count else None}

    def cancel(self, job_id):
        record = self.get(job_id)
        if record['state'] in ACTIVE:
            fd = os.open(self._path(job_id, '.cancel'), os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            os.close(fd)
            with self.lock:
                if job_id in self.events:
                    self.events[job_id].set()
            record['cancel_requested'] = True
        return record

    def _estimates(self, admitted):
        def identity(job):
            return job['image'], job['plugin'], tuple(job['arguments'])
        wanted = {identity(job) for job in admitted}
        samples = {}
        for image in {job['image'] for job in admitted}:
            case = self.backend.case_directory(self.backend.resolve_input(image))
            for path in sorted(case.glob('runs/*/manifest.json'))[-2000:]:
                try:
                    self.backend._check_components(path)
                    record = json.loads(path.read_text())
                    key = identity(record)
                    if key not in wanted or record['status'] != 'success' or len(record['commands']) != 1:
                        continue
                    command = record['commands'][0]
                    duration = command.get('elapsed_seconds')
                    if duration is None:
                        fmt = '%Y-%m-%d %H:%M:%SZ'
                        duration = (datetime.strptime(command['completed_at'], fmt) -
                                    datetime.strptime(command['started_at'], fmt)).total_seconds()
                    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration < 0:
                        continue
                    samples[key] = duration if key not in samples else (samples[key] + duration) / 2
                except (ValueError, OSError, KeyError, TypeError):
                    continue
        return samples

    def submit(self, jobs, order='input'):
        if not isinstance(jobs, list) or not 1 <= len(jobs) <= 256:
            raise ValueError('jobs must contain from 1 to 256 explicit plugin requests.')
        if order not in {'input', 'slowest-first'}:
            raise ValueError("order must be 'input' or 'slowest-first'.")
        admitted = []
        for request in jobs:
            if not isinstance(request, dict) or set(request) - {'image', 'plugin', 'arguments'}:
                raise ValueError('Each job must contain image, plugin and optional arguments only.')
            if 'image' not in request or 'plugin' not in request:
                raise ValueError('Each job requires image and plugin.')
            image = str(self.backend.resolve_input(request['image']))
            arguments = self.backend.validate_arguments(request['plugin'], request.get('arguments'))
            admitted.append({'image': image, 'plugin': request['plugin'], 'arguments': arguments})
        estimates = self._estimates(admitted) if order == 'slowest-first' else {}
        sequence = sorted(range(len(admitted)), key=lambda i:
                          -estimates.get((admitted[i]['image'], admitted[i]['plugin'], tuple(admitted[i]['arguments'])), -1))
        records, owners, transferred = [], [], set()
        with self.lock:
            if self.closed or self.backend.shutdown_event.is_set():
                raise ValueError('The analysis scheduler is shutting down.')
            try:
                for position, job in enumerate(admitted):
                    job_id = timestamped_id()
                    fd = _open_lock(self._path(job_id, '.lock'))
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    owners.append(fd)
                    record = {'schema_version': 1, 'job_id': job_id, **job,
                              'state': 'queued', 'submitted_at': utc_now(), 'started_at': None,
                              'completed_at': None, 'result': None, 'error': None,
                              'owner_pid': os.getpid(), 'owner_session': self.backend.session_id,
                              'input_position': position, 'order': order,
                              'estimated_seconds': estimates.get((job['image'], job['plugin'], tuple(job['arguments'])))}
                    self._save(record)
                    records.append(record)
                    self.events[job_id] = JobCancellation(self._path(job_id, '.cancel'), self.backend)
                for index in sequence:
                    self.pool.submit(self._execute, records[index], owners[index])
                    transferred.add(index)
            except BaseException:
                try:
                    for index, record in enumerate(records):
                        self.events[record['job_id']].set()
                        if index not in transferred:
                            record.update(state='error', error='Submission did not complete; no plugin started.', completed_at=utc_now())
                            try:
                                self._save(record)
                            except OSError:
                                # Preserve the original admission/storage error;
                                # the released owner lease exposes interruption.
                                pass
                            self.events.pop(record['job_id'], None)
                finally:
                    for index, fd in enumerate(owners):
                        if index not in transferred:
                            os.close(fd)
                raise
        return {'jobs': records, 'count': len(records), 'order': order}

    def _execute(self, original, owner_fd):
        record = dict(original)
        event = self.events[record['job_id']]
        try:
            if event.is_set():
                record.update(state='cancelled', error='Job cancelled before execution; no plugin started.')
            else:
                record.update(state='running', started_at=utc_now())
                self._save(record)
                result = self.backend.run_plugin(record['image'], record['plugin'], record['arguments'], cancel_event=event)
                record.update(state=result['status'], result=result)
        except BaseException as exc:
            record.update(state='cancelled' if event.is_set() else 'error', error=str(exc))
        finally:
            record['completed_at'] = utc_now()
            try:
                self._save(record)
            finally:
                os.close(owner_fd)
                with self.lock:
                    self.events.pop(record['job_id'], None)

    def shutdown(self, wait=True):
        with self.lock:
            self.closed = True
            for event in self.events.values():
                event.set()
        self.pool.shutdown(wait=wait, cancel_futures=False)
