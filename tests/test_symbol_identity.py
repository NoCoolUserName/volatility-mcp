"""Symbol identities trust local metadata and never reread the symbol payloads."""
from contextlib import ExitStack, contextmanager
import builtins
import dataclasses
import io
import os
from pathlib import Path
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

import test_backend
from volatility_mcp.backend import VolatilityBackend, file_fingerprint
from volatility_mcp.reuse import HashMeasurements, context_identity, isolated_cache
from volatility_mcp.prepare_symbol_cache import EXPECTED_GUID, RELATIVE_ISF


@contextmanager
def forbid_content_opens(*roots):
    """Catch both fingerprint os.open and Python file-reading entry points."""
    def guarded(original, *, directory_descriptors=False):
        def call(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(os.fsdecode(path)).absolute()
                if any(candidate.is_relative_to(root) for root in roots):
                    # Anchored traversal opens a directory descriptor, not a
                    # symbol payload. O_DIRECTORY cannot open a regular file.
                    if not (directory_descriptors and args and args[0] & os.O_DIRECTORY):
                        raise AssertionError(f'Symbol content opened: {candidate}')
            return original(path, *args, **kwargs)
        return call
    with ExitStack() as stack:
        stack.enter_context(patch('os.open', guarded(os.open, directory_descriptors=True)))
        stack.enter_context(patch('io.open', guarded(io.open)))
        stack.enter_context(patch('builtins.open', guarded(builtins.open)))
        yield


class SymbolIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend
        self.symbols = self.fixture.root / 'symbols'
        self.symbols.mkdir()
        self.symbol = self.symbols / 'kernel.json.xz'
        self.symbol.write_bytes(b'SYNTHETIC symbols')
        self.backend.supplemental_symbols = self.symbols
        self.catalog = self.backend.catalog()

    def identity(self):
        hashes = HashMeasurements(file_fingerprint)
        with patch.object(self.backend, 'catalog', return_value=self.catalog):
            result = context_identity(self.backend, 'windows.pslist.PsList', {}, hashes)
        return result, hashes.summary()

    def test_configured_and_installed_symbol_payloads_are_not_opened(self):
        installed = self.fixture.root / 'installed-symbols'
        installed.mkdir()
        (installed / 'builtin.json').write_text('SYNTHETIC installed table')
        self.catalog['symbol_roots'] = [str(installed)]
        (self.fixture.config.cache_path / 'cached-table.cache').write_text('SYNTHETIC cache')
        with forbid_content_opens(self.symbols, installed, self.fixture.config.cache_path):
            context, measurements = self.identity()
        self.assertEqual(context['symbols_identity_method'], 'trusted-local-filesystem-metadata-v1')
        self.assertFalse(context['symbol_content_verified'])
        self.assertEqual(measurements['symbol_inventory']['content_bytes_read'], 0)
        self.assertNotIn('symbols', measurements['groups'])
        before = context['symbols']
        (installed / 'builtin.json').write_text('SYNTHETIC changed installed table')
        self.assertNotEqual(before, self.identity()[0]['symbols'])

    def test_same_size_restored_mtime_mutation_invalidates_via_ctime(self):
        before = self.identity()[0]['symbols']
        original = self.symbol.stat()
        self.symbol.write_bytes(b'SYNTHETIC changed')
        self.assertEqual(self.symbol.stat().st_size, original.st_size)
        os.utime(self.symbol, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(self.symbol.stat().st_mtime_ns, original.st_mtime_ns)
        self.assertNotEqual(before, self.identity()[0]['symbols'])

    def test_add_remove_entries_restore_identity_despite_directory_timestamp_changes(self):
        before = self.identity()[0]['symbols']
        for directory in (False, True):
            with self.subTest(directory=directory):
                extra = self.symbols / 'extra'
                extra.mkdir() if directory else extra.write_text('SYNTHETIC addition')
                self.assertNotEqual(before, self.identity()[0]['symbols'])
                extra.rmdir() if directory else extra.unlink()
                self.assertEqual(before, self.identity()[0]['symbols'])
        (self.fixture.config.cache_path / 'preference.json').write_text('SYNTHETIC audit')
        (self.fixture.config.cache_path / 'identifiers.sqlite-shm').write_bytes(b'SYNTHETIC reader marks')
        self.assertEqual(before, self.identity()[0]['symbols'])

    def test_symlinks_and_special_files_are_rejected(self):
        invalid = self.symbols / 'invalid'
        invalid.symlink_to(self.symbol)
        with self.assertRaises(ValueError):
            self.identity()
        invalid.unlink()
        os.mkfifo(invalid)
        with self.assertRaises(ValueError):
            self.identity()

    def test_nested_symbol_store_is_not_copied_into_private_cache(self):
        cache = self.fixture.config.cache_path
        nested = cache / 'tables'
        nested.mkdir()
        (nested / 'large-symbols.zip').write_text('SYNTHETIC must not be copied')
        (cache / 'cache-marker').write_text('SYNTHETIC cache seed')
        backend = VolatilityBackend(dataclasses.replace(self.fixture.config, symbols=nested))
        with forbid_content_opens(nested):
            destination = isolated_cache(backend, 'nested-symbol-review', threading.Event())
        self.assertEqual((destination / 'cache-marker').read_text(), 'SYNTHETIC cache seed')
        self.assertFalse((destination / 'tables').exists())

    def test_queued_requests_use_metadata_and_reuse_persistent_private_cache(self):
        (self.fixture.config.cache_path / 'cache-marker').write_text('SYNTHETIC cache seed')
        self.addCleanup(self.backend.shutdown_jobs)

        def submit_and_wait():
            submitted = self.backend.submit_jobs([{'image': 'example.raw', 'plugin': 'windows.pslist.PsList'}])
            job_id = submitted['jobs'][0]['job_id']
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                job = self.backend.get_job(job_id)
                if job['state'] not in {'queued', 'running'}:
                    self.assertEqual(job['state'], 'success', job.get('error'))
                    return job['result']
                time.sleep(0.01)
            self.fail('Harmless queued request did not finish')

        with forbid_content_opens(self.symbols):
            first = submit_and_wait()
            second = submit_and_wait()
        self.assertTrue(second['reused'])
        self.assertEqual(first['run_id'], second['run_id'])
        for result in (first, second):
            self.assertEqual(result['hashing']['symbol_inventory']['content_bytes_read'], 0)

    def test_runtime_symbol_arguments_never_launch_preparation_or_open_payload(self):
        self.catalog['symbol_cache'] = {'filename': 'identifier.cache', 'schema_version': 1}
        selected = self.symbols / RELATIVE_ISF
        selected.parent.mkdir(parents=True)
        selected.write_text('SYNTHETIC selected table; contents must not be read')
        cache = self.fixture.config.cache_path / 'identifier.cache'
        connection = sqlite3.connect(cache)
        try:
            connection.execute('CREATE TABLE database_info (schema_version INT)')
            connection.execute('INSERT INTO database_info VALUES (1)')
            connection.execute('CREATE TABLE cache (location TEXT, identifier BLOB, operating_system TEXT, '
                               'stats_types INT, local BOOL)')
            connection.execute('INSERT INTO cache VALUES (?, ?, ?, ?, ?)',
                               (selected.as_uri(), f'ntkrnlpa.pdb|{EXPECTED_GUID}|1'.encode(), 'windows', 561, 1))
            connection.commit()
        finally:
            connection.close()
        with patch('volatility_mcp.backend.subprocess.run', side_effect=AssertionError('Runtime preparation launched')):
            with forbid_content_opens(self.symbols):
                arguments = self.backend._symbol_arguments()
        self.assertEqual(arguments, ['-s', str(self.symbols), '--cache-path', str(self.fixture.config.cache_path)])

    def test_archive_without_known_xp_rows_is_accepted_without_opening_archive(self):
        self.catalog['symbol_cache'] = {'filename': 'identifier.cache', 'schema_version': 1}
        (self.symbols / 'windows.zip').write_bytes(b'SYNTHETIC archive; must not be opened')
        with patch('volatility_mcp.backend.subprocess.run', side_effect=AssertionError('Runtime preparation launched')):
            with forbid_content_opens(self.symbols):
                arguments = self.backend._symbol_arguments()
        self.assertEqual(arguments, ['-s', str(self.symbols), '--cache-path', str(self.fixture.config.cache_path)])

    def test_archive_with_known_zero_type_xp_rows_requires_explicit_setup(self):
        self.catalog['symbol_cache'] = {'filename': 'identifier.cache', 'schema_version': 1}
        archive = self.symbols / 'windows.zip'
        archive.write_bytes(b'SYNTHETIC archive; must not be opened')
        connection = sqlite3.connect(self.fixture.config.cache_path / 'identifier.cache')
        try:
            connection.execute('CREATE TABLE database_info (schema_version INT)')
            connection.execute('INSERT INTO database_info VALUES (1)')
            connection.execute('CREATE TABLE cache (location TEXT, identifier BLOB, operating_system TEXT, '
                               'stats_types INT, local BOOL)')
            connection.execute('INSERT INTO cache VALUES (?, ?, ?, ?, ?)',
                               (f'jar:file:{archive}!{RELATIVE_ISF.as_posix()}',
                                f'ntkrnlpa.pdb|{EXPECTED_GUID}|1'.encode(), 'windows', 0, 1))
            connection.commit()
        finally:
            connection.close()
        with patch('volatility_mcp.backend.subprocess.run', side_effect=AssertionError('Runtime preparation launched')):
            with forbid_content_opens(self.symbols):
                with self.assertRaisesRegex(ValueError, 'run volatility-mcp symbols-install'):
                    self.backend._symbol_arguments()


if __name__ == '__main__':
    unittest.main()
