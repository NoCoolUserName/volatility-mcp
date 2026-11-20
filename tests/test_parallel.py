"""Harmless concurrent subprocess and durable queue acceptance checks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from volatility_mcp.backend import VolatilityBackend
from volatility_mcp.config import Config, ConfigurationError
from volatility_mcp.reuse import _open_lock
import test_backend


class ParallelTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = replace(self.fixture.config, max_concurrent_runs=2, command_timeout=5)
        self.backend = VolatilityBackend(self.config)
        self.addCleanup(self.backend.shutdown_jobs)
        self.fixture.image.write_text('slow')
        marker = 'mode = image.read_text().strip()'
        activity = '''import atexit

def activity(kind):
    fd = os.open(Path(sys.argv[0]).with_name('activity.jsonl'), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps({'pid': os.getpid(), 'time': time.monotonic(), 'kind': kind}) + '\\n').encode())
    finally:
        os.close(fd)
activity('start')
atexit.register(activity, 'end')
'''
        self.fixture.fake.write_text(self.fixture.fake.read_text().replace(marker, activity + marker))

    def count(self):
        path = self.fixture.root / 'analysis-count.jsonl'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def wait_job(self, backend, job_id):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = backend.get_job(job_id)
            if result['state'] not in {'queued', 'running'}:
                return result
            time.sleep(0.02)
        self.fail('Job never reached a terminal state')

    def peak(self):
        rows = [json.loads(line) for line in (self.fixture.root / 'activity.jsonl').read_text().splitlines()]
        active = peak = 0
        for row in sorted(rows, key=lambda row: row['time']):
            active += 1 if row['kind'] == 'start' else -1
            peak = max(peak, active)
        self.assertEqual(active, 0)
        return peak

    def test_distinct_direct_requests_overlap_and_respect_cap(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(self.backend.run_plugin, 'example.raw', 'windows.pslist.PsList', ['--pid', str(pid)])
                       for pid in range(41, 45)]
            results = [future.result(timeout=10) for future in futures]
        self.assertEqual({result['status'] for result in results}, {'success'})
        self.assertEqual(self.count(), 4)
        self.assertEqual(self.peak(), 2)
        # Each argv contains a private cache, never the configured shared cache.
        for result in results:
            command = json.loads(Path(result['manifest_path']).read_text())['commands'][0]['argv']
            cache = Path(command[command.index('--cache-path') + 1])
            self.assertTrue(cache.is_relative_to(self.backend.outputs / '.execution' / 'caches'))
            self.assertNotEqual(cache, self.config.cache_path)

    def test_independent_processes_share_capacity(self):
        config = self.fixture.root / 'parallel-config.json'
        config.write_text(json.dumps(self.config.to_dict()))
        code = ('import json,sys; from volatility_mcp.backend import VolatilityBackend; '
                'from volatility_mcp.config import load_config; '
                'print(json.dumps(VolatilityBackend(load_config(sys.argv[1])).run_plugin('
                '"example.raw","windows.pslist.PsList",["--pid",sys.argv[2]])))')
        children = [subprocess.Popen([sys.executable, '-c', code, str(config), str(pid)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for pid in range(41, 45)]
        try:
            for child in children:
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout)['status'], 'success')
            self.assertEqual(self.count(), 4)
            self.assertEqual(self.peak(), 2)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait()

    def test_conflicting_live_cap_rejected_and_idle_change_allowed(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.backend.run_plugin, 'example.raw', 'windows.pslist.PsList')
            deadline = time.monotonic() + 5
            while not self.count() and time.monotonic() < deadline:
                time.sleep(0.01)
            other = VolatilityBackend(replace(self.config, max_concurrent_runs=1))
            with self.assertRaisesRegex(ValueError, 'Concurrency setting differs'):
                other.run_plugin('example.raw', 'windows.info.Info')
            self.assertEqual(future.result(timeout=10)['status'], 'success')
        self.assertEqual(other.run_plugin('example.raw', 'windows.info.Info')['status'], 'success')

    def test_cross_client_cancel_remains_available_after_source_removed(self):
        self.fixture.image.write_text('timeout')
        job = self.backend.submit_jobs([{'image': 'example.raw', 'plugin': 'windows.pslist.PsList'}])['jobs'][0]
        deadline = time.monotonic() + 5
        while not self.count() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.count(), 1)
        self.fixture.image.unlink()
        observer = VolatilityBackend(self.config)
        self.addCleanup(observer.shutdown_jobs)
        self.assertEqual(observer.get_job(job['job_id'])['state'], 'running')
        self.assertTrue(observer.cancel_job(job['job_id'])['cancel_requested'])
        completed = self.wait_job(observer, job['job_id'])
        self.assertEqual(completed['state'], 'evidence_changed')
        self.assertEqual(completed['result']['commands'][0]['status'], 'cancelled')
        self.assertEqual(observer.list_jobs()['count'], 1)

    def test_partial_enqueue_failure_releases_unscheduled_owners(self):
        manager = self.backend._job_manager()
        original = manager.pool.submit
        calls = 0
        def failing(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError('SYNTHETIC enqueue failure')
            return original(*args)
        requests = [{'image': 'example.raw', 'plugin': 'windows.pslist.PsList', 'arguments': ['--pid', str(pid)]}
                    for pid in range(41, 44)]
        with patch.object(manager.pool, 'submit', side_effect=failing):
            with self.assertRaisesRegex(RuntimeError, 'enqueue failure'):
                self.backend.submit_jobs(requests)
        self.backend.shutdown_jobs()
        records = self.backend.list_jobs()['jobs']
        self.assertEqual(len(records), 3)
        self.assertTrue(all(record['state'] not in {'queued', 'running', 'interrupted'} for record in records))
        self.assertTrue(all(record['completed_at'] for record in records))

    def test_job_poll_rereads_terminal_record_after_owner_releases_lock(self):
        manager = self.backend._job_manager()
        job_id = 'completed-during-poll'
        running = {'job_id': job_id, 'image': str(self.fixture.image), 'state': 'running',
                   'result': None, 'error': None}
        manager._save(running)
        owner_fd = _open_lock(manager._path(job_id, '.lock'))
        fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original_read = manager._read
        reads = 0

        def finish_after_first_read(selected_id):
            nonlocal reads, owner_fd
            record = original_read(selected_id)
            reads += 1
            if reads == 1:
                manager._save({**running, 'state': 'success', 'result': {'status': 'success'}})
                os.close(owner_fd)
                owner_fd = None
            return record

        try:
            with patch.object(manager, '_read', side_effect=finish_after_first_read):
                result = manager.get(job_id)
        finally:
            if owner_fd is not None:
                os.close(owner_fd)
        self.assertEqual(reads, 2)
        self.assertEqual(result['state'], 'success')
        self.assertEqual(result['result'], {'status': 'success'})
        self.assertEqual(original_read(job_id)['state'], 'success')

        manager._save({**running, 'job_id': 'abandoned-job'})
        abandoned = manager.get('abandoned-job')
        self.assertEqual(abandoned['state'], 'interrupted')
        self.assertEqual(original_read('abandoned-job')['state'], 'running')

    def test_ordering_uses_only_matching_successful_argument_timings(self):
        self.fixture.image.write_text('normal')
        for pid, duration in [(41, 3), (42, 8)]:
            result = self.backend.run_plugin('example.raw', 'windows.pslist.PsList', ['--pid', str(pid)])
            path = Path(result['manifest_path'])
            record = json.loads(path.read_text())
            record['commands'][0]['elapsed_seconds'] = duration
            path.write_text(json.dumps(record))
        # Changed synthetic image bytes prevent reuse; invocation order
        # proves dispatch without relying on second-resolution timestamps.
        self.fixture.image.write_text('slow')
        single = VolatilityBackend(replace(self.config, max_concurrent_runs=1))
        self.addCleanup(single.shutdown_jobs)
        requests = [{'image': 'example.raw', 'plugin': 'windows.pslist.PsList', 'arguments': ['--pid', str(pid)]}
                    for pid in (41, 43, 42)]
        jobs = single.submit_jobs(requests, order='slowest-first')['jobs']
        self.assertEqual([job['estimated_seconds'] for job in jobs], [3, None, 8])
        for job in jobs:
            self.assertEqual(self.wait_job(single, job['job_id'])['state'], 'success')
        invocations = [json.loads(line)['argv'] for line in
                       (self.fixture.root / 'analysis-count.jsonl').read_text().splitlines()][-3:]
        self.assertEqual([argv[argv.index('--pid') + 1] for argv in invocations], ['42', '41', '43'])
        page = single.list_jobs(limit=2)
        self.assertEqual((page['count'], page['returned_count'], page['next_offset']), (3, 2, 2))
        self.assertEqual(single.list_jobs(offset=2, limit=2)['returned_count'], 1)

    def test_configurable_bounds_and_atomic_bad_batch(self):
        for value in (0, 65, True, '8'):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                replace(self.config, max_concurrent_runs=value)
        with self.assertRaises(ValueError):
            self.backend.submit_jobs([{'image': 'example.raw', 'plugin': 'windows.pslist.PsList'},
                                      {'image': 'example.raw', 'plugin': 'unknown.Plugin'}])
        self.assertEqual(self.backend.list_jobs()['count'], 0)
        self.assertEqual(self.count(), 0)


if __name__ == '__main__':
    unittest.main()
