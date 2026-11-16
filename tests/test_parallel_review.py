"""Focused regressions for parallel admission and private symbol-cache seeding."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import dataclasses
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

import test_backend
from volatility_mcp.config import ConfigurationError
from volatility_mcp.reuse import isolated_cache


class ParallelReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend

    def test_waiting_request_rejects_changed_configured_context_before_seeding(self):
        seed = self.fixture.config.cache_path / 'input.json'
        seed.write_text('SYNTHETIC before wait')

        @contextmanager
        def changed_while_waiting(*args):
            seed.write_text('SYNTHETIC changed while waiting')
            yield ()

        with patch('volatility_mcp.backend.execution_lock', changed_while_waiting):
            with patch('volatility_mcp.backend.isolated_cache') as copy:
                with self.assertRaisesRegex(ValueError, 'inputs changed while waiting'):
                    self.backend.run_plugin('example.raw', 'windows.pslist.PsList')
                copy.assert_not_called()
        self.assertFalse((self.fixture.root / 'analysis-count.jsonl').exists())

    def test_wal_snapshot_contains_committed_rows_without_mutating_seed(self):
        seed = self.fixture.config.cache_path / 'identifiers.sqlite'
        connection = sqlite3.connect(seed)
        self.addCleanup(connection.close)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('CREATE TABLE symbols (value TEXT)')
        connection.execute("INSERT INTO symbols VALUES ('SYNTHETIC committed in WAL')")
        connection.commit()
        # SQLite's shared-memory reader marks may change even on a read-only
        # connection. The durable database and committed WAL must stay intact.
        before = {p.name: p.read_bytes() for p in seed.parent.iterdir()
                  if p.is_file() and not p.name.endswith('-shm')}
        destination = isolated_cache(self.backend, 'wal-review', threading.Event())
        copied = sqlite3.connect(destination / seed.name)
        try:
            self.assertEqual(copied.execute('SELECT value FROM symbols').fetchall(),
                             [('SYNTHETIC committed in WAL',)])
        finally:
            copied.close()
        self.assertEqual(before, {p.name: p.read_bytes() for p in seed.parent.iterdir()
                                  if p.is_file() and not p.name.endswith('-shm')})
        self.assertEqual((destination / seed.name).stat().st_mode & 0o777, 0o600)

    def test_seed_change_during_copy_is_rejected_without_publishing_cache(self):
        seed = self.fixture.config.cache_path / 'input.json'
        seed.write_text('SYNTHETIC before copy')

        def changed_during_copy(backend, key, event, verify_seed=None):
            seed.write_text('SYNTHETIC changed during copy')
            return isolated_cache(backend, key, event, verify_seed=verify_seed)

        with patch('volatility_mcp.backend.isolated_cache', changed_during_copy):
            with self.assertRaisesRegex(ValueError, 'inputs changed during private cache'):
                self.backend.run_plugin('example.raw', 'windows.pslist.PsList')
        self.assertFalse((self.fixture.root / 'analysis-count.jsonl').exists())
        caches = self.fixture.config.output_root / '.execution' / 'caches'
        self.assertEqual(list(caches.iterdir()), [])

    def test_busy_sqlite_seed_cancels_and_removes_partial_destination(self):
        seed = self.fixture.config.cache_path / 'identifiers.sqlite'
        connection = sqlite3.connect(seed)
        self.addCleanup(connection.close)
        connection.execute('CREATE TABLE symbols (value TEXT)')
        connection.commit()
        connection.execute('BEGIN EXCLUSIVE')
        event = threading.Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(isolated_cache, self.backend, 'busy-review', event)
            time.sleep(0.1)
            event.set()
            try:
                with self.assertRaisesRegex(ValueError, 'cancelled during private cache'):
                    pending.result(timeout=2)
            finally:
                connection.rollback()
        root = self.fixture.config.output_root / '.execution' / 'caches'
        self.assertEqual(list(root.iterdir()), [])

    def test_config_rejects_both_cache_output_overlap_directions(self):
        config = self.fixture.config
        output = config.output_root
        for selected_output, cache in ((output, output), (output, output / 'cache'),
                                       (output / 'runs', output)):
            with self.subTest(output=selected_output, cache=cache), self.assertRaises(ConfigurationError):
                dataclasses.replace(config, output_root=selected_output, cache_path=cache)


if __name__ == '__main__':
    unittest.main()
