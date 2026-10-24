"""Real Volatility symbol indexing of synthetic ISFs, without memory images."""
import base64
import gzip
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('preparation', Path(__file__).parents[1]/'src/volatility_mcp/prepare_symbol_cache.py')
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


class IndexSmoke(unittest.TestCase):
    def test_linux_community_tree_indexes_exact_banner_offline(self):
        from volatility3 import symbols as symbol_module
        from volatility3.framework.automagic.symbol_cache import SqliteCache
        banner = b'Linux version 6.1.0-synthetic (test) #1 SMP test\n\x00'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            symbols, cache = root/'symbols', root/'cache'
            table = symbols/'linux/community/Test/amd64/test.json.xz'
            table.parent.mkdir(parents=True)
            isf = {'metadata': {'format': '6.2.0', 'linux': {}}, 'base_types': {},
                   'user_types': {'task_struct': {'kind': 'struct', 'size': 8, 'fields': {}}}, 'enums': {}, 'symbols': {'linux_banner': {
                       'address': 4096, 'constant_data': base64.b64encode(banner).decode()}}}
            table.write_bytes(lzma.compress(json.dumps(isf).encode()))
            catalog = root/'catalog.json.gz'
            entry = {'path': 'Test/amd64/test.json.xz', 'banner': banner.rstrip(b'\n\x00').decode()}
            catalog.write_bytes(gzip.compress(json.dumps({'entries': [entry]}).encode()))
            with patch.object(symbol_module, '__path__', []), \
                 patch('socket.create_connection', side_effect=AssertionError('No network permitted')):
                result = preparation.index_all(symbols, cache, catalog)
                self.assertEqual(result['verified_linux_tables'], 1)
                entry['banner'] += ' mismatch'
                catalog.write_bytes(gzip.compress(json.dumps({'entries': [entry]}).encode()))
                with self.assertRaisesRegex(ValueError, 'not correctly indexed'):
                    preparation.index_all(symbols, cache, catalog)
            self.assertEqual(result['unique_identifiers'], {'linux': 1})
            manager = SqliteCache(str(cache/'identifier.cache'))
            self.assertEqual(manager.get_identifier(table.as_uri()), banner)

    def test_fresh_index_and_verified_duplicate_preference(self):
        from volatility3 import symbols as symbol_module
        from volatility3.framework.automagic.symbol_cache import SqliteCache
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            symbols, cache = root/'symbols', root/'cache'
            symbols.mkdir()
            types = {f'_TEST{i}': {'kind': 'struct', 'size': 4, 'fields': {}} for i in range(559)}
            types.update({name: {'kind': 'struct', 'size': 4, 'fields': {}} for name in ('_ETHREAD', '_EPROCESS')})
            isf = {'metadata': {'format': '6.2.0', 'windows': {'pdb': {
                'GUID': preparation.EXPECTED_GUID, 'age': 1, 'database': 'ntkrnlpa.pdb', 'machine_type': 0}}},
                'base_types': {'pointer': {'kind': 'int', 'size': 4, 'signed': False, 'endian': 'little'}},
                'user_types': types, 'enums': {}, 'symbols': {}}
            data = lzma.compress(json.dumps(isf).encode())
            archive = symbols/'windows.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr(preparation.RELATIVE_ISF.as_posix(), data)
            incomplete = symbols/'incomplete.json'
            incomplete.write_text(json.dumps({**isf, 'user_types': {}}))
            with patch.object(symbol_module, '__path__', []), \
                 patch.object(preparation, 'EXPECTED_SHA256', hashlib.sha256(data).hexdigest()), \
                 patch('socket.create_connection', side_effect=AssertionError('No network permitted')):
                result = preparation.index_all(symbols, cache)
            self.assertEqual(result['unique_identifiers'], {'windows': 1})
            self.assertEqual(result['preference']['preferred_type_count'], 561)
            self.assertEqual(len(result['preference']['disabled_zero_type_entries']), 1)
            manager = SqliteCache(str(cache/'identifier.cache'))
            self.assertIsNone(manager.get_identifier(incomplete.as_uri()))
            loose = symbols/preparation.RELATIVE_ISF
            loose.parent.mkdir(parents=True)
            loose.write_bytes(data)
            duplicate = f'jar:file:{archive}!{preparation.RELATIVE_ISF.as_posix()}'
            with patch.object(preparation, 'EXPECTED_SHA256', hashlib.sha256(data).hexdigest()), \
                 patch.object(SqliteCache, 'find_location', return_value=duplicate):
                result = preparation.prepare(symbols, cache)
                self.assertEqual(result['selected_uri'], duplicate)
                self.assertEqual(result['preferred_type_count'], 561)
                with zipfile.ZipFile(archive, 'w') as z:
                    z.writestr(preparation.RELATIVE_ISF.as_posix(), b'different')
                with self.assertRaisesRegex(ValueError, 'differs'):
                    preparation.prepare(symbols, cache)


if __name__ == '__main__':
    unittest.main()
