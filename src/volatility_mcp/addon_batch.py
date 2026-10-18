"""Reviewed method adaptations for the first community3 batch.

The installer fetches the pinned original sources and verifies both hashes.
These replacements add bounded offline operation; they are not plugin copies.
"""

HELPERS = r'''

# volatility-mcp compatibility revision 3: strict bounded offline reads.
def _limit(config, name, default, maximum):
    value = config.get(name, default)
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _read(layer, address, length):
    if not 0 <= address < 2**64 or not 0 < length <= 65536:
        raise ValueError("Invalid or oversized bounded read")
    data = layer.read(address, length, pad=False)
    if len(data) != length:
        raise ValueError("Incomplete memory read; analysis did not complete")
    return data


def _scan(layer, sections, scanner, budget):
    # DataLayer.scan suppresses scan/read exceptions. Read directly so missing
    # pages and scanner errors cannot turn into a successful empty result.
    for index, (start, size) in enumerate(sections):
        if index >= 65536:
            raise ValueError("Too many scan sections; narrow the scope")
        if start < 0 or size < 0 or start + size > 2**64:
            raise ValueError("Invalid scan section")
        if size > budget[0]:
            raise ValueError("Scan byte limit exceeded; analysis incomplete")
        position, end, carry = start, start + size, b""
        while position < end:
            size = min(65536, end - position)
            data = _read(layer, position, size)
            budget[0] -= size
            block = carry + data
            for offset, rule, name, value in scanner(block, position - len(carry)):
                if offset + len(value) > position:
                    yield offset, rule, name, value, end
            carry = block[-4095:]
            position += size
'''

COBALT_PARSE = r'''
def parse_result(cls, rule, value):
    if not 8 <= len(value) <= 4096:
        raise ValueError("Cobalt Strike configuration size is invalid")
    key = 0x2e if value.startswith(b'././') else 0x69 if value.startswith(b'ihih') else None
    if key is None:
        raise ValueError("Unsupported Cobalt Strike configuration encoding")
    data = bytes(c ^ key for c in value)
    config, seen, position = {}, set(), 0
    text_fields = {'server,get-uri', 'post-uri', 'spawnto_x86', 'spawnto_x64', 'pipename'}
    integer_fields = {'port', 'sleeptime', 'jitter', 'license-id'}
    while position + 2 <= len(data):
        if data[position:position + 2] == b'\0\0':
            if not seen:
                raise ValueError("Empty Cobalt Strike configuration")
            return config
        if position + 6 > len(data):
            raise ValueError("Truncated Cobalt Strike field header")
        field, kind, size = struct.unpack('>HHH', data[position:position + 6])
        position += 6
        if field in seen or position + size > len(data):
            raise ValueError("Duplicate or truncated Cobalt Strike field")
        seen.add(field)
        raw = data[position:position + size]
        position += size
        name = CONFIG_STRUCT.get(field)
        if kind == 1 and size == 2:
            parsed = struct.unpack('>H', raw)[0]
        elif kind == 2 and size == 4:
            parsed = struct.unpack('>I', raw)[0]
        elif kind == 3:
            parsed = raw
        else:
            raise ValueError("Invalid Cobalt Strike field type or length")
        if name in integer_fields:
            if type(parsed) is not int:
                raise ValueError("Cobalt Strike numeric field has a non-numeric type")
            config[name] = parsed
        elif name in text_fields:
            if not isinstance(parsed, bytes):
                raise ValueError("Cobalt Strike text field has a non-text type")
            config[name] = parsed.rstrip(b'\0').decode('utf-8')
    raise ValueError("Unterminated Cobalt Strike configuration")
'''

COBALT_GENERATOR = r'''
def _generator(self, procs):
    budget = [_limit(self.config, 'max-scan-bytes', 67108864, 67108864)]
    process_limit = _limit(self.config, 'max-processes', 64, 1024)
    result_limit = _limit(self.config, 'max-results', 1000, 10000)
    scanner = yarascan.YaraScanner(rules=yara.compile(sources=signatures))
    count = 0
    for index, proc in enumerate(procs):
        if index >= process_limit:
            raise ValueError("Process limit exceeded; narrow the PID scope")
        layer_name = proc.add_process_layer()
        layer = self.context.layers[layer_name]
        for offset, rule, _name, _value, end in _scan(layer, vadyarascan.VadYaraScan.get_vad_maps(proc), scanner, budget):
            if rule != 'cobaltstrike_config':
                continue
            count += 1
            if count > result_limit:
                raise ValueError("Result limit exceeded; analysis incomplete")
            config = self.parse_result(rule, _read(layer, offset, min(4096, end - offset)))
            missing = renderers.NotAvailableValue()
            yield (0, (int(proc.UniqueProcessId), utility.array_to_string(proc.ImageFileName),
                       layer_name, hex(offset),
                       *(config.get(name, missing) for name in ('port', 'sleeptime', 'jitter',
                         'server,get-uri', 'post-uri', 'spawnto_x86', 'spawnto_x64', 'pipename', 'license-id'))))
'''

COBALT_RUN = '''
def run(self):
    return renderers.TreeGrid([
        ("PID", int), ("Process", str), ("Layer", str), ("Offset", str),
        ("Port", int), ("Sleep", int), ("Jitter", int), ("Server", str),
        ("POST_PATH", str), ("x86 Install_Path", str), ("x64 Install_Path", str),
        ("Pipe", str), ("License ID", int)],
        self._generator(pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config['kernel'],
            filter_func=pslist.PsList.create_pid_filter(self.config.get('pid')))))
'''

RICH_PARSE = r'''
def parse_result(cls, raw_data):
    if not 64 <= len(raw_data) <= 65536 or raw_data[:2] != b'MZ':
        raise ValueError("Invalid or oversized DOS header")
    marker = raw_data.rfind(b'Rich')
    if marker < 0:
        return None, None
    if marker % 4 or marker < 80 or marker + 8 > len(raw_data):
        raise ValueError("Malformed Rich marker or XOR key")
    key = raw_data[marker + 4:marker + 8]
    decoded = bytearray()
    for position in range(marker - 4, 63, -4):
        word = bytes(a ^ b for a, b in zip(raw_data[position:position + 4], key))
        decoded[:0] = word
        if word == b'DanS':
            if len(decoded) < 16 or decoded[4:16] != b'\0' * 12 or (len(decoded) - 16) % 8:
                raise ValueError("Malformed decoded Rich header")
            return key, hashlib.md5(decoded, usedforsecurity=False).hexdigest()
    raise ValueError("Rich marker without a valid DanS header")
'''

RICH_GENERATOR = r'''
def _generator(self):
    maximum = _limit(self.config, 'max-processes', 64, 1024)
    procs = pslist.PsList.list_processes(context=self.context,
        kernel_module_name=self.config['kernel'],
        filter_func=pslist.PsList.create_pid_filter(self.config.get('pid')))
    for index, proc in enumerate(procs):
        if index >= maximum:
            raise ValueError("Process limit exceeded; narrow the PID scope")
        layer_name = proc.add_process_layer()
        layer = self.context.layers[layer_name]
        peb = proc.get_peb()
        if peb is None:
            raise ValueError(f"PEB unavailable for PID {int(proc.UniqueProcessId)}; analysis incomplete")
        base = int(peb.ImageBaseAddress)
        dos = _read(layer, base, 64)
        size = int.from_bytes(dos[60:64], 'little')
        if dos[:2] != b'MZ' or not 64 <= size <= 65536:
            raise ValueError("Invalid or oversized PE header offset")
        data = _read(layer, base, size)
        key, digest = self.parse_result(data)
        if digest is not None:
            yield (0, (int(proc.UniqueProcessId), utility.array_to_string(proc.ImageFileName),
                       layer_name, hex(base), hex(base + data.rfind(b'Rich')), key.hex(), digest))
'''

RICH_RUN = '''
def run(self):
    return renderers.TreeGrid([("PID", int), ("Process", str), ("Layer", str),
        ("ImageBase", str), ("RichOffset", str), ("XOR Key", str),
        ("Rich Header Hash", str)], self._generator())
'''

ZONE_REQUIREMENTS = '''
def get_requirements(cls):
    return [requirements.TranslationLayerRequirement(name='primary',
        description='Memory layer to scan', architectures=['Intel32', 'Intel64']),
        requirements.VersionRequirement(name='yarascanner', component=yarascan.YaraScanner, version=(2, 1, 1)),
        requirements.IntRequirement(name='start', description='Start offset in the selected layer', optional=False),
        requirements.IntRequirement(name='length', description='Range length in bytes, 1 to 67108864', optional=False),
        requirements.IntRequirement(name='max-results', description='Maximum results, 1 to 10000', default=1000, optional=True)]
'''

ZONE_PARSE = r'''
@staticmethod
def parse_record(data):
    if len(data) > 1024 or not data.startswith(b'[ZoneTransfer]\r\nZoneId=3\r\n'):
        raise ValueError("Malformed or truncated ZoneId=3 header")
    # Never borrow a URL from the next carved record or after a NUL boundary.
    data = data.split(b'\0', 1)[0] + (b'\0' if b'\0' in data else b'')
    next_record = data.find(b'[ZoneTransfer]', 1)
    if next_record >= 0:
        data = data[:next_record]
    values = {}
    for name in (b'HostUrl', b'ReferrerUrl'):
        match = re.search(rb'(?:^|\r\n)' + name + rb'=([^\r\n\x00]*)(\r\n|\x00)', data)
        if match:
            values[name] = match.group(1).decode('utf-8')
        elif re.search(rb'(?:^|\r\n)' + name + rb'=', data):
            raise ValueError("Truncated Zone.Identifier URL; analysis incomplete")
    return values
'''

ZONE_GENERATOR = r'''
def _generator(self):
    start = self.config['start']
    length = _limit(self.config, 'length', 0, 67108864)
    maximum = _limit(self.config, 'max-results', 1000, 10000)
    if type(start) is not int or not 0 <= start < 2**64 or start + length > 2**64:
        raise ValueError("Invalid scan start/range")
    layer_name = self.config['primary']
    layer = self.context.layers[layer_name]
    rules = yara.compile(source='rule zone3 { strings: $a = { 5b 5a 6f 6e 65 54 72 61 6e 73 66 65 72 5d 0d 0a 5a 6f 6e 65 49 64 3d 33 } condition: $a }')
    count = 0
    for offset, _rule, _name, _value, end in _scan(layer, [(start, length)], yarascan.YaraScanner(rules=rules), [length]):
        data = _read(layer, offset, min(1024, end - offset))
        fields = self.parse_record(data)
        if not fields:
            continue
        count += 1
        if count > maximum:
            raise ValueError("Result limit exceeded; analysis incomplete")
        yield (0, (layer_name, hex(offset), len(data), 3,
                   fields.get(b'HostUrl', renderers.NotAvailableValue()),
                   fields.get(b'ReferrerUrl', renderers.NotAvailableValue())))
'''

ZONE_RUN = '''
def run(self):
    return renderers.TreeGrid([('Layer', str), ('Offset', str), ('BytesRead', int),
        ('ZoneID', int), ('Host URL', str), ('Referrer URL', str)], self._generator())
'''

PTE_RUN = '''
def run(self):
    selectors = [key for key in ('vaddr', 'pte_paddr', 'pte_vaddr', 'pte_value') if self.config.get(key) is not None]
    if len(selectors) != 1:
        raise ValueError('Specify exactly one of vaddr, pte-paddr, pte-vaddr, pte-value')
    mode = selectors[0]
    value = self.config[mode]
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('Address/PTE value must be an unsigned 64-bit integer')
    if mode in ('pte_paddr', 'pte_vaddr') and value % 8:
        raise ValueError('PTE address must be 8-byte aligned')
    pids = self.config.get('pid') or []
    if len(pids) > 1 or any(type(pid) is not int or pid < 0 for pid in pids):
        raise ValueError('Select at most one non-negative PID')
    if mode in ('vaddr', 'pte_vaddr') and len(pids) != 1:
        raise ValueError('A single PID is required for virtual address resolution')
    return renderers.TreeGrid([('PID', int), ('Process Name', str), ('InputKind', str),
        ('InputValue', str), ('Output', str)], self._generator(
        pslist.PsList.list_processes(self.context, kernel_module_name=self.config['kernel'],
            filter_func=pslist.PsList.create_pid_filter(pids))))
'''

PTE_GENERATOR = '''
def _generator(self, procs):
    with _ReadBudget(self.context) as budget:
        rows = list(self._resolve_generator(procs))
        if budget.failed:
            raise ValueError('PTE read failed or exceeded its bound; resolution incomplete')
    yield from rows

def _resolve_generator(self, procs):
    mode = next(key for key in ('vaddr', 'pte_paddr', 'pte_vaddr', 'pte_value') if self.config.get(key) is not None)
    value = self.config[mode]
    if mode in ('vaddr', 'pte_vaddr'):
        proc = next(iter(procs), None)
        if proc is None:
            raise ValueError('Selected PID is unavailable; PTE resolution incomplete')
        # Prepopulate a bounded VAD list before the shared initializer uses it.
        vads = []
        for index, vad in enumerate(proc.get_vad_root().traverse()):
            if index >= 65536:
                raise ValueError('VAD count limit exceeded')
            vads.append((vad.get_start(), vad.get_end(), vad))
        self._vad_dict[proc.vol.offset] = vads
        self.init_for_proc(proc)
    else:
        self._initialize_internals()
    resolver = {'vaddr': self.resolve_pte_by_vaddr, 'pte_vaddr': self.resolve_pte_by_pte_vaddr,
                'pte_paddr': self.resolve_pte_by_pte_paddr, 'pte_value': self.resolve_pte_by_pte_value}[mode]
    result = resolver(value)
    if result is None:
        raise ValueError('PTE could not be resolved; unavailable/unsupported, not an empty result')
    if result.state not in ('HARD', 'TRANS', 'SOFT', 'SOFTZERO', 'PROTOPOINT', 'PROTOVAD', 'SUBSEC') or result.length != 4096:
        raise ValueError('Unknown or large/huge PTE state is not supported by this adaptation')
    output = result.get_full_string_repr()
    if len(output.encode('utf-8')) > 65536:
        raise ValueError('PTE output exceeds 65536-byte bound')
    proc = result.proc
    yield (0, (int(result.pid) if result.pid is not None else -1,
               utility.array_to_string(proc.ImageFileName) if proc is not None else 'N/A',
               mode, hex(value), output))

def _ensure_mmpfn_db_raw(self):
    # Targeted resolution must not allocate/read the entire PFN database.
    return None

def _get_mmpfn_entry_raw(self, pfn):
    # Shared Ptenum derives _hpp from maximum_address >> page_bits: this is
    # the last valid PFN index, not a count.
    if not 0 <= pfn <= self._hpp or not 0 < self._mmpfn_entry_size <= 4096:
        raise ValueError('Invalid PFN entry size/index')
    return _read(self.kernel_layer, self.mmpfn_db.vol.offset + pfn * self._mmpfn_entry_size,
                 self._mmpfn_entry_size)

def _get_proc_for_pid(self, pid):
    for index, proc in enumerate(pslist.PsList.list_processes(
            self.context, kernel_module_name=self.config['kernel'])):
        if index >= 1024:
            raise ValueError('Process traversal limit exceeded')
        if int(proc.UniqueProcessId) == pid:
            return proc
    return None
'''

PTE_BUDGET = '''

class _ReadBudget:
    # Per-plugin subprocess context only. Restore instance methods even on
    # error. Existing lower layers bound reads through newly added process
    # translation layers too. Count nested requests conservatively.
    def __init__(self, context):
        self.layers = list(context.layers.values())
        self.saved = []
        self.remaining = 16777216
        self.calls = 0
        self.failed = False

    def __enter__(self):
        try:
            for layer in self.layers:
                original = layer.read
                self.saved.append((layer, layer.__dict__.get('read')))
                def read(offset, length, pad=False, _original=original):
                    try:
                        self.calls += 1
                        if (self.calls > 65536 or not 0 <= offset < 2**64
                                or not 0 < length <= 65536 or length > self.remaining):
                            raise ValueError('PTE read budget exceeded')
                        self.remaining -= length
                        data = _original(offset, length, pad=False)
                        if len(data) != length:
                            raise ValueError('Incomplete PTE read')
                        return data
                    except Exception:
                        self.failed = True
                        raise
                layer.read = read
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        for layer, previous in reversed(self.saved):
            if previous is None:
                del layer.read
            else:
                layer.read = previous
'''


def adapt_batch(filename, source, replace_method):
    """Replace known methods, retaining the original module and license notices."""
    if filename not in {'cobaltstrike.py', 'richheader.py', 'zoneid3.py', 'pte_resolve.py'}:
        return source
    if filename in {'cobaltstrike.py', 'richheader.py'}:
        source = source.replace("plugin = pslist.PsList, version = (2, 0, 0)",
                                "plugin = pslist.PsList, version = (3, 0, 0)")
        # Add explicit work bounds to the existing PID/module requirements.
        extra = "requirements.IntRequirement(name='max-processes', description='Maximum processes, 1 to 1024', default=64, optional=True),\n"
        if filename == 'cobaltstrike.py':
            extra += "requirements.IntRequirement(name='max-scan-bytes', description='Maximum scan bytes, 1 to 67108864', default=67108864, optional=True),\nrequirements.IntRequirement(name='max-results', description='Maximum results, 1 to 10000', default=1000, optional=True),\n"
        source = source.replace('return [\n', 'return [\n' + extra, 1)
    if filename == 'cobaltstrike.py':
        replacements = {'parse_result': COBALT_PARSE, '_generator': COBALT_GENERATOR, 'run': COBALT_RUN}
    elif filename == 'richheader.py':
        source = source.replace('Scans process memory for each process to identify CobaltStrike config', 'Recover bounded Rich Header hashes from process executable headers')
        replacements = {'parse_result': RICH_PARSE, '_generator': RICH_GENERATOR, 'run': RICH_RUN}
    elif filename == 'zoneid3.py':
        replacements = {'get_requirements': ZONE_REQUIREMENTS, '_generator': ZONE_GENERATOR, 'run': ZONE_RUN}
        source = source.rstrip() + '\n\n' + '\n'.join('    ' + line if line else '' for line in ZONE_PARSE.strip().splitlines()) + '\n'
    else:
        source = source.replace('architectures = ["Intel32", "Intel64"]', 'architectures = ["Intel64"]')
        # The subsection-walking option is intentionally deferred until bounded.
        import ast
        tree = ast.parse(source)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == 'BooleanRequirement' and any(k.arg == 'name' and isinstance(k.value, ast.Constant) and k.value.value == 'subsec_pte' for k in n.keywords))
        lines = source.splitlines(keepends=True)
        lines[node.lineno - 1:node.end_lineno] = [']\n']
        source = ''.join(lines)
        replacements = {'run': PTE_RUN, '_generator': PTE_GENERATOR}
    for name, replacement in replacements.items():
        source = replace_method(source, name, replacement)
    source = source.replace('_version = (1, 0, 0)', '_version = (1, 1, 0)')
    source = source.replace('_version = (0, 9, 0)', '_version = (0, 9, 1)')
    return source.rstrip() + '\n' + HELPERS + (PTE_BUDGET if filename == 'pte_resolve.py' else '')
