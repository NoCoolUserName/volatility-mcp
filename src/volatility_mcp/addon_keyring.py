"""Bounded adaptation of mischw's MIT Linux keyring plugin.

The installer retains the pinned original and its MIT license. These replacements
are applied only to that source; no upstream plugin is bundled in the core wheel.
"""
import textwrap


KEYS = """
def get_keys_in_keyring(self):
    kernel = self.context.modules[self.config['kernel']]
    if not kernel.has_symbol('key_serial_tree'):
        raise exceptions.VolatilityException('Missing key_serial_tree; unsupported kernel')
    root = kernel.object_from_symbol('key_serial_tree')
    key_type = self.context.symbol_space.get_type(kernel.symbol_table_name + '!key')
    relative = key_type.relative_child_offset('serial_node')
    pending, seen = [int(root.rb_node)], set()
    while pending:
        address = pending.pop()
        if not address:
            continue
        if address in seen:
            raise ValueError('Repeated key tree node; incomplete extraction')
        if len(seen) >= 4096:
            raise ValueError('Key tree exceeds 4096 nodes; incomplete extraction')
        if address <= relative or address % 8:
            raise ValueError('Invalid key tree node address')
        seen.add(address)
        node = self.context.object(kernel.symbol_table_name + '!rb_node',
            offset=address, layer_name=kernel.layer_name)
        pending.extend((int(node.rb_right), int(node.rb_left)))
        yield self.context.object(kernel.symbol_table_name + '!key',
            offset=address - relative, layer_name=kernel.layer_name)
"""

PAYLOAD = """
def parse_key_payload(self, key):
    # Negative/uninstantiated payload union members are not valid pointers.
    if int(key.state) != 1:
        return 'NOT_POSITIVELY_INSTANTIATED'
    if int(key.flags) & ((1 << 0) | (1 << 1) | (1 << 5)):
        return 'DEAD_REVOKED_OR_INVALIDATED'
    kernel = self.context.modules[self.config['kernel']]
    kind = self.get_key_type(key)
    if kind == 'keyring':
        return 'CONTAINER'
    if kind not in ('user', 'logon', 'asymmetric'):
        return 'UNSUPPORTED_KEY_TYPE:' + kind
    pointer = int(key.payload.data[0])
    if not pointer:
        return 'NO_PAYLOAD_POINTER'
    if kind in ('user', 'logon'):
        payload = self.context.object(kernel.symbol_table_name + '!user_key_payload',
            offset=pointer, layer_name=kernel.layer_name)
        return self._read_payload(int(payload.data.vol.offset), int(payload.datalen)).hex()
    payload = self.context.object(kernel.symbol_table_name + '!public_key',
        offset=pointer, layer_name=kernel.layer_name)
    data = self._read_payload(int(payload.key), int(payload.keylen)).hex()
    id_type = self._cstring(payload.id_type, 32)
    algorithm = self._cstring(payload.pkey_algo, 32)
    return f'{data} (Type: {id_type}, Private: {bool(payload.key_is_private)}, Algo: {algorithm})'
"""

HELPERS = r"""
def _read_payload(self, address, length):
    if not 0 <= length <= 65536:
        raise ValueError('Payload exceeds 65536-byte bound; incomplete extraction')
    used = getattr(self, '_payload_bytes', 0)
    if used + length > 4 * 1024 * 1024:
        raise ValueError('Payloads exceed 4 MiB aggregate bound; incomplete extraction')
    self._payload_bytes = used + length
    if length == 0:
        return b''
    if address <= 0:
        raise ValueError('Null/invalid payload address')
    kernel = self.context.modules[self.config['kernel']]
    data = self.context.layers[kernel.layer_name].read(address, length, pad=False)
    if len(data) != length:
        raise ValueError('Short payload read; incomplete extraction')
    return data

def _cstring(self, pointer, maximum):
    # Read through the terminator only; never accept a partial or padded string.
    address = int(pointer)
    if address <= 0:
        raise ValueError('Null/invalid key metadata pointer')
    kernel = self.context.modules[self.config['kernel']]
    layer = self.context.layers[kernel.layer_name]
    value = bytearray()
    for offset in range(maximum):
        byte = layer.read(address + offset, 1, pad=False)
        if len(byte) != 1:
            raise ValueError('Short key metadata read; incomplete extraction')
        if byte == b'\0':
            return value.decode('utf-8', errors='backslashreplace')
        value.extend(byte)
    raise ValueError('Unterminated key metadata; incomplete extraction')
"""


def adapt_keyring(filename, source, replace_method):
    if filename != 'keyring.py':
        raise ValueError('Unexpected keyring source')
    source = '# Adapted by volatility-mcp; upstream MIT copyright (c) 2026 mischw.\n' + source
    source = source.replace('import logging', 'from typing import List\nimport logging', 1)
    source = source.replace('architectures=["Intel32", "Intel64"]', 'architectures=["Intel64"]')
    source = source.replace('_version = (1, 0, 0)', '_version = (1, 1, 0)')
    for name, replacement in [('get_keys_in_keyring', KEYS), ('parse_key_payload', PAYLOAD)]:
        source = replace_method(source, name, replacement)
    source = source.replace('utility.pointer_to_string(', 'self._cstring(').replace('count=', 'maximum=')
    source = source.replace('def _generator(self):', 'def _generator(self):\n        self._payload_bytes = 0')
    source = source.replace('datetime.datetime.fromtimestamp(key.last_used_at)',
        'datetime.datetime.fromtimestamp(int(key.last_used_at), datetime.timezone.utc)')
    source = source.replace('("Last used", str)', '("Last used (UTC)", str)')
    source = source.replace('("Address", format_hints.Hex),', '("Layer", str),\n            ("Address", format_hints.Hex),')
    source = source.replace('fields = (', 'fields = (\n                self.context.modules[self.config["kernel"]].layer_name,')
    source += '\n' + textwrap.indent(textwrap.dedent(HELPERS).strip(), '    ') + '\n'
    return source
