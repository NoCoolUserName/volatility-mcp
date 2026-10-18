"""Deterministic adaptations of the pinned lorelyai BitLocker plugin.

The installer retrieves the attributed GPL upstream source and validates its
original/adapted hashes. This module contains compatibility replacements only.
"""
import ast


REQUIREMENTS = '''
def get_requirements(cls):
    return [requirements.ModuleRequirement(name='kernel', description='Windows x64 kernel with local symbols', architectures=['Intel64']),
        requirements.IntRequirement(name='start', description='Explicit kernel virtual start address of the pool range', optional=False),
        requirements.IntRequirement(name='length', description='Range length in bytes, 1 to 16777216; reads must all succeed', optional=False),
        requirements.ListRequirement(name='tags', description='One to sixteen exact four-character ASCII pool tags', element_type=str, optional=True),
        requirements.IntRequirement(name='max-results', description='Maximum AES schedule candidates, 1 to 1000', default=100, optional=True),
        requirements.IntRequirement(name='max-pools', description='Maximum matching pool allocations, 1 to 4096', default=1024, optional=True)]
'''

GENERATOR = '''
def _generator(self):
    start, length, maximum, pool_maximum, tags = self._scope()
    kernel = self.context.modules[self.config['kernel']]
    layer = self.context.layers[kernel.layer_name]
    header_type = kernel.get_type('_POOL_HEADER')
    header_size = header_type.size
    tag_offset = header_type.relative_child_offset('PoolTag')
    # Refuse unfamiliar layouts; byte alignment and pool sizes are x64-specific.
    if header_size != 16 or tag_offset != 4:
        raise ValueError('Unsupported x64 pool-header layout; analysis incomplete')
    count = pools = 0
    end = start + length
    allocation_end = start
    with _BoundedReads(layer, start, end) as reads:
        position, carry = start, b''
        while position < end:
            size = min(65536, end - position)
            block = carry + layer.read(position, size, pad=False)
            base = position - len(carry)
            matches = []
            for tag in tags:
                index = block.find(tag)
                while index >= 0:
                    absolute = base + index
                    if absolute + 4 > position:
                        matches.append((absolute - tag_offset, tag))
                    index = block.find(tag, index + 1)
            for address, tag in sorted(matches):
                if address < allocation_end or address % 16:
                    continue
                if address + header_size > end:
                    raise ValueError('Truncated matching pool header at range boundary')
                pools += 1
                if pools > pool_maximum:
                    raise ValueError('Pool limit exceeded; narrow the range')
                header = kernel.object(object_type='_POOL_HEADER', offset=address, absolute=True)
                pool_size = int(header.BlockSize) * 16
                if not header_size <= pool_size <= 65536:
                    raise ValueError('Malformed or oversized matching pool allocation')
                if address + pool_size > end:
                    raise ValueError('Matching pool allocation exceeds selected range; incomplete')
                data = layer.read(address, pool_size, pad=False)
                if data[tag_offset:tag_offset + 4] != tag:
                    raise ValueError('Matching pool tag changed during read')
                allocation_end = address + pool_size
                # Each schedule is an independent candidate. Neither adjacency
                # nor a pool tag establishes FVEK/tweak roles or CBC/XTS mode.
                for offset in range(header_size, pool_size - 176 + 1):
                    for key_size, expanded_len in ((16, 176), (32, 240)):
                        chunk = data[offset:offset + expanded_len]
                        if self._valid_schedule(chunk, key_size, expanded_len):
                            count += 1
                            if count > maximum:
                                raise ValueError('Result limit exceeded; analysis incomplete')
                            yield (0, (kernel.layer_name, hex(address), tag.decode('ascii'), pool_size,
                                hex(address + offset), expanded_len, key_size * 8, chunk[:key_size].hex(),
                                'AES schedule validated; BitLocker use, cipher mode and key role unconfirmed'))
            carry = block[-3:]
            position += size
'''

RUN = '''
def run(self):
    self._scope()
    return renderers.TreeGrid([('Layer', str), ('PoolOffset', str), ('PoolTag', str), ('PoolSize', int),
        ('ScheduleOffset', str), ('ScheduleBytes', int), ('KeyBits', int), ('AESKeyCandidate', str),
        ('Assessment', str)], self._generator())
'''

SCOPE = '''
def _scope(self):
    start, length = self.config.get('start'), self.config.get('length')
    if type(start) is not int or not 0 <= start < 2**64:
        raise ValueError('An explicit unsigned kernel virtual start address is required')
    if type(length) is not int or not 1 <= length <= 16777216 or start + length > 2**64:
        raise ValueError('An explicit range length between 1 and 16777216 is required')
    maximum, pools = self.config.get('max-results', 100), self.config.get('max-pools', 1024)
    if type(maximum) is not int or not 1 <= maximum <= 1000 or type(pools) is not int or not 1 <= pools <= 4096:
        raise ValueError('Invalid result or pool bound')
    tags = self.config.get('tags')
    if tags is None:
        tags = ['FVEc', 'Cngb', 'None', 'dFVE']
    if not isinstance(tags, (list, tuple)) or not 1 <= len(tags) <= 16:
        raise ValueError('Specify one to sixteen exact four-character ASCII pool tags')
    if any(not isinstance(tag, str) or len(tag) != 4 or any(not 32 <= ord(c) <= 126 for c in tag) for tag in tags):
        raise ValueError('Pool tags must have exactly four printable ASCII characters')
    if len(set(tags)) != len(tags):
        raise ValueError('Pool tags must be unique')
    if self.config.get('dump') or self.config.get('dislocker'):
        raise ValueError('Automatic FVEK/Dislocker export is unsupported: key role and mode are unconfirmed')
    return start, length, maximum, pools, [tag.encode('ascii') for tag in tags]
'''

READS = '''

class _BoundedReads:
    """Keep both direct reads and symbol-backed header reads inside the scope."""
    def __init__(self, layer, start, end):
        self.layer, self.start, self.end = layer, start, end
        self.remaining = 2 * (end - start) + 65536
        self.calls = 0

    def __enter__(self):
        self.original = self.layer.read
        self.previous = self.layer.__dict__.get('read')
        def read(offset, length, pad=False):
            self.calls += 1
            if (type(offset) is not int or type(length) is not int or not 0 < length <= 65536
                    or offset < self.start or offset + length > self.end or self.calls > 65536
                    or length > self.remaining):
                raise ValueError('BitLocker read scope or budget exceeded; analysis incomplete')
            self.remaining -= length
            data = self.original(offset, length, pad=False)
            if len(data) != length:
                raise ValueError('Incomplete BitLocker memory read')
            return data
        self.layer.read = read
        return self

    def __exit__(self, *args):
        if self.previous is None:
            del self.layer.read
        else:
            self.layer.read = self.previous
'''


def adapt_bitlocker(filename, source, replace_method):
    """Retain attribution/AES validation; replace unsafe scan and mode guesses."""
    if filename != 'bitlocker.py':
        return source
    plugin = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == 'BitlockerFVEKScan')
    doc = plugin.body[0]
    if not isinstance(doc, ast.Expr) or not isinstance(doc.value, ast.Constant) or not isinstance(doc.value.value, str):
        raise ValueError('Pinned BitLocker class documentation changed')
    lines = source.splitlines(keepends=True)
    lines[doc.lineno - 1:doc.end_lineno] = ['    """Find AES schedule candidates in an explicit bounded Windows x64 pool range.\n\n'
        '    Requires local kernel symbols and complete reads. BitLocker use, cipher\n'
        '    mode and key role remain unconfirmed. Manual sensitive extraction only.\n'
        '    """\n']
    source = ''.join(lines)
    for name, replacement in {'get_requirements': REQUIREMENTS, '_generator': GENERATOR, 'run': RUN}.items():
        source = replace_method(source, name, replacement)
    # Preserve the upstream AES recurrence, but reject unsupported key sizes.
    source = source.replace('if len(schedule) != expanded_len:',
        'if (key_size, expanded_len) not in ((16, 176), (32, 240)) or len(schedule) != expanded_len:')
    source = source.replace('_version = (1, 0, 0)', '_version = (1, 1, 0)')
    # Remove unused export/mode-guessing helpers from the installed plugin too.
    removable = {'_dislocker_header_xts', '_dislocker_header_cbc', '_write_dislocker_file', '_get_poolscanner'}
    nodes = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name in removable]
    if {n.name for n in nodes} != removable:
        raise ValueError('Pinned BitLocker helper methods changed')
    lines = source.splitlines(keepends=True)
    for node in sorted(nodes, key=lambda item: item.lineno, reverse=True):
        start = min([node.lineno] + [item.lineno for item in node.decorator_list])
        del lines[start - 1:node.end_lineno]
    source = ''.join(lines).rstrip() + '\n\n'
    source += '\n'.join('    ' + line if line else '' for line in SCOPE.strip().splitlines()) + '\n' + READS
    notice = ('# volatility-mcp adaptation: explicit bounded x64 range; strict offline reads.\n'
              '# Independent AES key candidates only; no FVEK/mode assertion or file export.\n')
    return source.replace('from __future__ import annotations\n', 'from __future__ import annotations\n\n' + notice, 1)
