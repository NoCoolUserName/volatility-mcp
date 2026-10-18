"""Harmless AES/pool fixtures under the analyzer Python; no image or real keys.

Run installed plugin: /path/to/analyzer/python tests/addon_bitlocker_smoke.py -v
To test adaptation before staging, set VOLATILITY_BITLOCKER_SOURCE to the pinned
upstream bitlocker.py. The original source hash is verified before import.
"""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import platform
import struct
import types
import unittest
from unittest.mock import patch


HOST_ARCHITECTURE = platform.architecture()
DENY = contextlib.ExitStack()
DENY.enter_context(patch('platform.architecture', return_value=HOST_ARCHITECTURE))
for target in ('socket.socket.connect', 'socket.create_connection', 'socket.getaddrinfo',
               'urllib.request.urlopen', 'subprocess.Popen'):
    DENY.enter_context(patch(target, side_effect=AssertionError('Offline fixture boundary: ' + target)))

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.symbols.intermed import IntermediateSymbolTable
from volatility3.cli.text_renderer import JsonRenderer

if os.environ.get('VOLATILITY_BITLOCKER_SOURCE'):
    from volatility_mcp.addon_compat import replace_method
    from volatility_mcp.addon_bitlocker import adapt_bitlocker
    source = Path(os.environ['VOLATILITY_BITLOCKER_SOURCE']).read_bytes()
    assert hashlib.sha256(source).hexdigest() == '1cda3c680e665898051dba1f9a638c42a4a711b65da74c8539995ad543a7ffb7'
    adapted = adapt_bitlocker('bitlocker.py', source.decode(), replace_method)
    bitlocker = types.ModuleType('volatility3.plugins.windows.bitlocker')
    exec(compile(adapted, '<pinned-bitlocker-adaptation>', 'exec'), bitlocker.__dict__)
else:
    bitlocker = importlib.import_module('volatility3.plugins.windows.bitlocker')


# FIPS 197, Appendix A.1 / A.3 published AES key expansion examples.
AES128 = bytes.fromhex('''
2b7e151628aed2a6abf7158809cf4f3c a0fafe1788542cb123a339392a6c7605
f2c295f27a96b9435935807a7359f67f 3d80477d4716fe3e1e237e446d7a883b
ef44a541a8525b7fb671253bdb0bad00 d4d1c6f87c839d87caf2b8bc11f915bc
6d88a37a110b3efddbf98641ca0093fd 4e54f70e5f5fc9f384a64fb24ea6dc4f
ead27321b58dbad2312bf5607f8d292f ac7766f319fadc2128d12941575c006e
d014f9a8c9ee2589e13f0cc8b6630ca6''')
AES256 = bytes.fromhex('''
603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
9ba354118e6925afa51a8b5f2067fcde a8b09c1a93d194cdbe49846eb75d5b9a
d59aecb85bf3c917fee94248de8ebe96 b5a9328a2678a647983122292f6c79b3
812c81addadf48ba24360af2fab8b464 98c5bfc9bebd198e268c3ba709e04214
68007bacb2df331696e939e46c518d80 c814e20476a9fb8a5025c02d59c58239
de1369676ccc5a71fa2563959674ee15 5886ca5d2e2f31d77e0af1fa27cf73c3
749c47ab18501ddae2757e4f7401905a cafaaae3e4d59b349adf6acebd10190d
fe4890d1e6188d0b046df344706c631e''')


def pool(schedule=AES128, offset=16, size=None, tag=b'FVEc'):
    size = size or ((offset + len(schedule) + 15) // 16) * 16
    value = bytearray(size)
    value[2] = size // 16
    value[4:8] = tag
    value[offset:offset + len(schedule)] = schedule
    return bytes(value)


def fixture(data, values=None, bitfield=True, header_size=16):
    context = contexts.Context()
    field_type = {'kind': 'bitfield', 'bit_length': 8, 'bit_position': 16,
                  'type': {'kind': 'base', 'name': 'unsigned long'}} if bitfield else {'kind': 'base', 'name': 'unsigned char'}
    schema = {
        'metadata': {'format': '6.2.0'}, 'enums': {}, 'symbols': {},
        'base_types': {
            'unsigned long': {'kind': 'int', 'size': 4, 'signed': False, 'endian': 'little'},
            'unsigned char': {'kind': 'int', 'size': 1, 'signed': False, 'endian': 'little'}},
        'user_types': {'_POOL_HEADER': {'kind': 'struct', 'size': header_size, 'fields': {
            'BlockSize': {'offset': 0 if bitfield else 2, 'type': field_type},
            'PoolTag': {'offset': 4, 'type': {'kind': 'base', 'name': 'unsigned long'}}}}}}
    # Feed a generated local schema through the real symbol loader. It contains
    # no URLs, images or user data; the global network boundary remains denied.
    with patch('volatility3.framework.layers.resources.ResourceAccessor.open', return_value=io.BytesIO(json.dumps(schema).encode())):
        table = IntermediateSymbolTable(context, 'test.symbols', 'synthetic', 'file:///synthetic-pool-header.json')
    context.symbol_space.append(table)
    layer = BufferDataLayer(context, 'test.layer', 'memory', data)
    context.layers.add_layer(layer)
    module = context.module('synthetic', 'memory', 0)
    context.config['fixture.kernel'] = module.name
    context.config['fixture.start'] = 0
    context.config['fixture.length'] = len(data)
    for key, value in (values or {}).items():
        context.config['fixture.' + key] = value
    plugin = object.__new__(bitlocker.BitlockerFVEKScan)
    plugin._context, plugin._config_path = context, 'fixture'
    return plugin, layer, module


def render(plugin):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        JsonRenderer().render(plugin.run())
    return json.loads(output.getvalue())


class BitLockerTests(unittest.TestCase):
    def test_required_arguments_and_export_removed(self):
        requirements = {req.name: req for req in bitlocker.BitlockerFVEKScan.get_requirements()}
        for name in ('start', 'length', 'kernel'):
            self.assertFalse(requirements[name].optional)
        self.assertNotIn('dump', requirements)
        self.assertNotIn('dislocker', requirements)
        plugin, _, _ = fixture(pool())
        del plugin.context.config['fixture.start']
        with self.assertRaisesRegex(ValueError, 'explicit'):
            plugin.run()

    def test_published_aes_schedules_and_corruption(self):
        plugin, _, _ = fixture(pool())
        for schedule, key_size in ((AES128, 16), (AES256, 32)):
            self.assertTrue(plugin._valid_schedule(schedule, key_size, len(schedule)))
            self.assertFalse(plugin._valid_schedule(schedule[:-1], key_size, len(schedule)))
            for offset in (0, key_size, len(schedule) - 1):
                corrupt = bytearray(schedule)
                corrupt[offset] ^= 1
                self.assertFalse(plugin._valid_schedule(bytes(corrupt), key_size, len(schedule)))
        self.assertFalse(plugin._valid_schedule(b'', 0, 0))
        self.assertFalse(plugin._valid_schedule(b'x' * 208, 24, 208))

    def test_current_symbols_primitive_and_bitfield_provenance_json(self):
        for bitfield in (True, False):
            for schedule, key_size in ((AES128, 16), (AES256, 32)):
                plugin, layer, module = fixture(pool(schedule), bitfield=bitfield)
                original = layer.read
                with patch.object(module, 'object', wraps=module.object) as object_call, patch.object(bitlocker.vollog, 'info', side_effect=AssertionError('No key logging')):
                    rows = render(plugin)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['AESKeyCandidate'], schedule[:key_size].hex())
                self.assertEqual(rows[0]['ScheduleOffset'], '0x10')
                self.assertEqual(rows[0]['PoolOffset'], '0x0')
                self.assertEqual(rows[0]['Layer'], 'memory')
                self.assertIn('unconfirmed', rows[0]['Assessment'])
                self.assertEqual(object_call.call_args.kwargs, {'object_type': '_POOL_HEADER', 'offset': 0, 'absolute': True})
                self.assertEqual(layer.read, original)

    def test_two_keys_never_paired_or_mode_inferred(self):
        plugin, _, _ = fixture(pool(AES128 + AES256))
        rows = render(plugin)
        self.assertEqual(len(rows), 2)
        self.assertEqual([r['ScheduleOffset'] for r in rows], ['0x10', '0xc0'])
        for row in rows:
            self.assertNotIn('FVEK', row)
            self.assertNotIn('Tweak', row)
            self.assertNotIn('Cipher', row)
        self.assertFalse(hasattr(plugin, '_write_dislocker_file'))

    def test_last_possible_offset_and_tag_chunk_boundary(self):
        # AES-128 ends exactly at the allocation boundary (upstream missed it).
        plugin, _, _ = fixture(pool(AES128, size=192))
        self.assertEqual(len(render(plugin)), 1)
        # Start the range at 5 so the next 64 KB chunk splits a PoolTag.
        data = b'\0' * 65536 + pool(AES256)
        plugin, layer, _ = fixture(data, {'start': 5, 'length': len(data) - 5})
        with patch.object(layer, 'read', wraps=layer.read) as reading:
            rows = render(plugin)
        self.assertEqual(rows[0]['PoolOffset'], '0x10000')
        self.assertTrue(all(call.args[1] <= 65536 and not call.kwargs.get('pad', False) for call in reading.call_args_list))

    def test_empty_valid_pool_corrupt_schedule_and_malformed_pool(self):
        plugin, _, _ = fixture(b'\0' * 256)
        self.assertEqual(render(plugin), [])
        # A tag at the beginning cannot borrow a header from negative/outside
        # addresses. The scoped result remains empty without an invalid read.
        plugin, layer, _ = fixture(b'FVEc' + b'\0' * 252)
        with patch.object(layer, 'read', wraps=layer.read) as reading:
            self.assertEqual(render(plugin), [])
        self.assertTrue(all(call.args[0] >= 0 for call in reading.call_args_list))
        corrupt = bytearray(AES128)
        corrupt[-1] ^= 1
        plugin, _, _ = fixture(pool(bytes(corrupt)))
        self.assertEqual(render(plugin), [])
        malformed = bytearray(pool())
        malformed[2] = 0
        plugin, _, _ = fixture(bytes(malformed))
        with self.assertRaisesRegex(ValueError, 'Malformed'):
            list(plugin._generator())
        plugin, _, _ = fixture(pool()[:-1])
        with self.assertRaisesRegex(ValueError, 'exceeds selected range'):
            list(plugin._generator())
        plugin, _, _ = fixture(pool(), header_size=8)
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            list(plugin._generator())

    def test_bounds_bad_tags_and_results_are_errors(self):
        for values in ({'start': -1}, {'start': True}, {'length': 0}, {'length': 16777217},
                       {'max-results': 0}, {'max-pools': 4097}, {'tags': []}, {'tags': ['FVE']},
                       {'tags': ['FVEc', 'FVEc']}, {'tags': ['abcé']}, {'dislocker': True}, {'dump': True}):
            with self.subTest(values=values):
                plugin, _, _ = fixture(pool(), values)
                with self.assertRaises(ValueError):
                    list(plugin._generator())
        plugin, _, _ = fixture(pool(AES128 + AES256), {'max-results': 1})
        with self.assertRaisesRegex(ValueError, 'Result limit'):
            list(plugin._generator())
        plugin, _, _ = fixture(pool() + pool(), {'max-pools': 1})
        with self.assertRaisesRegex(ValueError, 'Pool limit'):
            list(plugin._generator())

    def test_read_failures_short_reads_and_budget_restore(self):
        plugin, layer, _ = fixture(pool())
        for failure in (exceptions.InvalidAddressException('memory', 0), ValueError('synthetic failure')):
            with patch.object(layer, 'read', side_effect=failure) as failing:
                with self.assertRaises(type(failure)):
                    list(plugin._generator())
                self.assertIs(layer.read, failing)
        with patch.object(layer, 'read', return_value=b''):
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                list(plugin._generator())
        original = layer.read
        with bitlocker._BoundedReads(layer, 0, 192) as bound:
            for args in ((-1, 1), (0, 65537), (192, 1), (0, 0)):
                with self.assertRaises(ValueError):
                    layer.read(*args)
            bound.remaining = 0
            with self.assertRaises(ValueError):
                layer.read(0, 1)
        self.assertEqual(layer.read, original)


if __name__ == '__main__':
    unittest.main()
