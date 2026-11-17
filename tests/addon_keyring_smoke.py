"""Offline synthetic contracts for the installed, adapted Linux keyring addon."""
import contextlib
import io
import json
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

DENY = contextlib.ExitStack()
for target in ('socket.socket.connect', 'socket.create_connection', 'socket.getaddrinfo',
               'urllib.request.urlopen', 'subprocess.Popen'):
    DENY.enter_context(patch(target, side_effect=AssertionError('Offline fixture: ' + target)))

from volatility3.framework import exceptions
from volatility3.framework.interfaces.configuration import HierarchicalDict
from volatility3.cli.text_renderer import JsonRenderer
from volatility3.plugins.linux.keyring import Keyring


class Memory:
    def __init__(self):
        self.data = bytearray(131072)
        self.reads = []

    def read(self, address, length, pad=False):
        self.reads.append((address, length, pad))
        if address < 0 or address + length > len(self.data):
            raise exceptions.InvalidAddressException('memory', address)
        return bytes(self.data[address:address + length])


def fixture(kind='user'):
    obj = object.__new__(Keyring)
    obj._config_path = 'fixture'
    memory = Memory()
    for address, value in ((16, kind.encode()), (64, b'synthetic'), (128, b'X509'), (160, b'rsa')):
        memory.data[address:address+len(value)+1] = value + b'\0'
    memory.data[512:516] = b'TEST'
    key = NS(state=1, flags=0, type=NS(name=16), description=64,
             payload=NS(data=[256]), datalen=4, serial=123, last_used_at=0,
             expiry=9223372036854775807, perm=0x3f, uid=NS(val=1000), gid=NS(val=1000),
             usage=NS(refs=NS(counter=1)), vol=NS(offset=992))
    payload = NS(data=NS(vol=NS(offset=512)), datalen=4, key=512, keylen=4,
                 id_type=128, pkey_algo=160, key_is_private=False)
    nodes = {1024: NS(rb_left=0, rb_right=0)}
    kernel = NS(layer_name='memory', symbol_table_name='symbols',
                has_symbol=lambda name: True, object_from_symbol=lambda name: NS(rb_node=1024))
    def create(name, offset, layer_name):
        if name.endswith('!rb_node'):
            return nodes[offset]
        if name.endswith('!key'):
            return key
        return payload
    obj._context = NS(config=HierarchicalDict(), layers={'memory':memory}, modules={'kernel':kernel},
                      object=create, symbol_space=NS(get_type=lambda name:NS(relative_child_offset=lambda name:32)))
    obj._context.config['fixture.kernel'] = 'kernel'
    return obj, key, payload, nodes, memory


class KeyringTests(unittest.TestCase):
    def test_requirements(self):
        req = Keyring.get_requirements()
        self.assertEqual([r.name for r in req], ['kernel'])
        self.assertEqual(Keyring.version, (1, 1, 0))

    def test_user_logon_asymmetric_and_rendered_provenance(self):
        for kind in ('user', 'logon', 'asymmetric'):
            obj, key, payload, nodes, memory = fixture(kind)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                JsonRenderer().render(obj.run())
            row = json.loads(out.getvalue())[0]
            self.assertTrue(row['Payload'].startswith('54455354'))
            self.assertEqual(row['Layer'], 'memory')
            self.assertEqual(row['Address'], 992)
            self.assertEqual(row['Last used (UTC)'], '1970-01-01 00:00:00+00:00')
            self.assertFalse(any(pad for _, _, pad in memory.reads))

    def test_payload_statuses_do_not_dereference_unsafe_unions(self):
        for state, flags, expected in ((0,0,'NOT_POSITIVELY'),(-5,0,'NOT_POSITIVELY'),
                                      (1,1,'DEAD_REVOKED'),(1,2,'DEAD_REVOKED'),(1,32,'DEAD_REVOKED')):
            obj, key, *_ = fixture()
            key.state, key.flags = state, flags
            key.payload = None
            self.assertTrue(obj.parse_key_payload(key).startswith(expected))
        for kind, expected in (('keyring','CONTAINER'),('.fscrypt','UNSUPPORTED_KEY_TYPE:.fscrypt'),
                               ('encrypted','UNSUPPORTED_KEY_TYPE:encrypted')):
            obj, key, *_ = fixture(kind)
            key.payload = None
            self.assertEqual(obj.parse_key_payload(key), expected)
        obj, key, *_ = fixture()
        key.payload.data[0] = 0
        self.assertEqual(obj.parse_key_payload(key), 'NO_PAYLOAD_POINTER')

    def test_per_payload_and_aggregate_bounds(self):
        obj, key, payload, _, memory = fixture()
        for size in (-1,65537):
            payload.datalen = size
            with self.assertRaisesRegex(ValueError, '65536'):
                obj.parse_key_payload(key)
        self.assertEqual(memory.reads[-1][1], 1)  # metadata only; no bad payload read
        self.assertEqual(len(obj._read_payload(512,65536)),65536)
        obj._payload_bytes = 4*1024*1024 - 4
        self.assertEqual(obj._read_payload(512,4), b'TEST')
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            obj._read_payload(512,1)

    def test_short_unreadable_and_null_reads_fail(self):
        obj, *_ = fixture()
        with self.assertRaises(exceptions.InvalidAddressException):
            obj._read_payload(131071,2)
        with patch.object(obj.context.layers['memory'], 'read', return_value=b''):
            with self.assertRaisesRegex(ValueError,'Short'):
                obj._read_payload(512,4)
            with self.assertRaisesRegex(ValueError,'Short'):
                obj._cstring(16,32)
        with self.assertRaisesRegex(ValueError,'Null'):
            obj._read_payload(0,4)
        self.assertEqual(obj._read_payload(0,0),b'')

    def test_strict_metadata_and_budget_reset(self):
        obj, key, _, _, memory = fixture()
        memory.data[16:48] = b'x'*32
        with self.assertRaisesRegex(ValueError, 'Unterminated'):
            obj.get_key_type(key)
        memory.data[16:21] = b'user\0'
        obj._payload_bytes = 4*1024*1024
        self.assertEqual(len(list(obj._generator())),1)
        self.assertEqual(obj._payload_bytes,4)

    def test_missing_symbol_empty_tree_and_cycle(self):
        obj, key, _, nodes, _ = fixture()
        obj.context.modules['kernel'].has_symbol = lambda name: False
        with self.assertRaisesRegex(exceptions.VolatilityException,'Missing'):
            list(obj.get_keys_in_keyring())
        obj.context.modules['kernel'].has_symbol = lambda name: True
        obj.context.modules['kernel'].object_from_symbol = lambda name:NS(rb_node=0)
        self.assertEqual(list(obj.get_keys_in_keyring()),[])
        obj.context.modules['kernel'].object_from_symbol = lambda name:NS(rb_node=1024)
        nodes[1024].rb_left = 1024
        with self.assertRaisesRegex(ValueError,'Repeated'):
            list(obj.get_keys_in_keyring())

    def test_unreadable_branch_and_misaligned_node_fail(self):
        obj, _, _, nodes, _ = fixture()
        nodes[1024].rb_right = 2048
        original = obj.context.object
        def create(name, offset, layer_name):
            if offset == 2048:
                raise exceptions.InvalidAddressException(layer_name,offset)
            return original(name,offset,layer_name)
        obj.context.object = create
        with self.assertRaises(exceptions.InvalidAddressException):
            list(obj.get_keys_in_keyring())
        nodes[1024].rb_right = 1025
        with self.assertRaisesRegex(ValueError,'Invalid'):
            list(obj.get_keys_in_keyring())

    def test_long_tree_fails_at_bound_without_recursion(self):
        obj, key, *_ = fixture()
        def create(name, offset, layer_name):
            if name.endswith('!rb_node'):
                return NS(rb_left=offset+64, rb_right=0)
            return key
        obj.context.object = create
        iterator = obj.get_keys_in_keyring()
        self.assertEqual(sum(1 for _ in range(4096) if next(iterator) is key),4096)
        with self.assertRaisesRegex(ValueError,'4096'):
            next(iterator)


if __name__ == '__main__':
    unittest.main()
