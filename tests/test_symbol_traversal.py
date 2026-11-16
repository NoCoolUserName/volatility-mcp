"""Descriptor inventory must reject raced directory identity and link swaps."""
import os
import json
import unittest
from unittest.mock import patch

import test_backend
from volatility_mcp.reuse import HashMeasurements, symbol_inventory
from volatility_mcp.relocation import ENV


class SymbolTraversalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend
        self.symbols = self.fixture.root / 'symbols'
        self.symbols.mkdir()
        self.hashes = HashMeasurements(lambda path: self.fail('Inventory must not hash symbol payloads'))

    def test_root_replacement_during_descriptor_walk_holds(self):
        (self.symbols / 'table.json').write_text('SYNTHETIC original')
        original_walk = os.fwalk

        def replace_after_root(*args, **kwargs):
            walker = original_walk(*args, **kwargs)
            try:
                yield next(walker)
                self.symbols.rename(self.fixture.root / 'old-symbols')
                self.symbols.mkdir()
                yield from walker
            finally:
                walker.close()

        with patch('volatility_mcp.reuse.os.fwalk', replace_after_root):
            with self.assertRaisesRegex(ValueError, 'root changed during inventory'):
                symbol_inventory(self.backend, [('supplemental', self.symbols)], self.hashes)

    def test_nested_directory_replaced_by_symlink_is_not_silently_omitted(self):
        child = self.symbols / 'nested'
        child.mkdir()
        (child / 'table.json').write_text('SYNTHETIC original')
        outside = self.fixture.root / 'outside'
        outside.mkdir()
        (outside / 'outside-sentinel.json').write_text('SYNTHETIC must not be visited')
        original_walk = os.fwalk
        visited_files = []

        def replace_after_parent(*args, **kwargs):
            walker = original_walk(*args, **kwargs)
            try:
                first = next(walker)
                visited_files.extend(first[2])
                yield first
                child.rename(self.fixture.root / 'old-nested')
                child.symlink_to(outside, target_is_directory=True)
                for item in walker:
                    visited_files.extend(item[2])
                    yield item
            finally:
                walker.close()

        with patch('volatility_mcp.reuse.os.fwalk', replace_after_parent):
            with self.assertRaisesRegex(ValueError, 'directory changed or disappeared'):
                symbol_inventory(self.backend, [('supplemental', self.symbols)], self.hashes)
        self.assertNotIn('outside-sentinel.json', visited_files)
        self.assertEqual(self.hashes.summary()['symbol_inventory']['content_bytes_read'], 0)

    def test_registered_ancestor_relocation_remains_supported(self):
        (self.symbols / 'table.json').write_text('SYNTHETIC relocated')
        original = self.fixture.root
        physical = original.with_name(original.name + '-moved')
        original.rename(physical)
        original.symlink_to(physical, target_is_directory=True)
        try:
            mapping = physical / 'relocation.json'
            mapping.write_text(json.dumps({'logical_root': str(original), 'physical_root': str(physical)}))
            with patch.dict(os.environ, {ENV: str(mapping)}):
                records = symbol_inventory(self.backend, [('supplemental', self.symbols)], self.hashes)
            self.assertEqual([record['path'] for record in records], ['.', 'table.json'])
            self.assertEqual(self.hashes.summary()['symbol_inventory']['content_bytes_read'], 0)
        finally:
            original.unlink()
            physical.rename(original)


if __name__ == '__main__':
    unittest.main()
