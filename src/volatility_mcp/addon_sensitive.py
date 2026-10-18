"""Pinned upstream adaptations for deliberately selected secret extraction."""
from .addon_batch import HELPERS, PTE_BUDGET

PASSWORD_REQUIREMENTS = '''
def get_requirements(cls):
    return [requirements.ModuleRequirement(name='kernel', description='Windows kernel', architectures=['Intel32', 'Intel64']),
        requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(3, 0, 0)),
        requirements.VersionRequirement(name='vadyarascan', component=vadyarascan.VadYaraScan, version=(1, 0, 0)),
        requirements.IntRequirement(name='pid', description='Explicit browser PID for sensitive extraction', optional=False),
        requirements.IntRequirement(name='max-scan-bytes', description='Maximum bytes, 1 to 67108864', default=16777216, optional=True),
        requirements.IntRequirement(name='max-results', description='Maximum rows, 1 to 1000', default=100, optional=True)]
'''

PASSWORD_PARSE = r'''
def parse_result(cls, rule, value):
    if not rule.startswith('lastpass') or not 0 < len(value) <= 4096:
        raise ValueError('Unsupported or oversized password-manager fragment')
    # Parse JSON string escapes strictly; never log recovered values. Restrict
    # fields to this matched fragment, rather than unrelated following memory.
    token = rb'("(?:\\.|[^"\\])*?")'
    patterns = [rb'"unencryptedUsername"\s*:\s*',
                rb'"(?:logonPassword|password)"\s*,\s*"value"\s*:\s*',
                rb'"(?:tld|topurl)"\s*:\s*']
    result = []
    for pattern in patterns:
        marker = re.search(pattern, value)
        match = re.search(pattern + token, value)
        if marker and not match:
            raise ValueError('Malformed password-manager string field')
        result.append(json.loads(match.group(1).decode('utf-8')) if match else None)
    return tuple(result)
'''

PASSWORD_GENERATOR = '''
def _generator(self, procs):
    budget = [_limit(self.config, 'max-scan-bytes', 16777216, 67108864)]
    maximum = _limit(self.config, 'max-results', 100, 1000)
    scanner = yarascan.YaraScanner(rules=yara.compile(sources=signatures))
    selected, count = False, 0
    for proc in procs:
        if selected:
            raise ValueError('Expected exactly one browser process')
        selected = True
        name = utility.array_to_string(proc.ImageFileName)
        if name.lower() not in browser_procs:
            raise ValueError('Selected PID is not a supported browser')
        layer_name = proc.add_process_layer()
        layer = self.context.layers[layer_name]
        for offset, rule, _name, value, _end in _scan(layer, vadyarascan.VadYaraScan.get_vad_maps(proc), scanner, budget):
            parsed = self.parse_result(rule, value)
            if all(item is None for item in parsed):
                continue
            count += 1
            if count > maximum:
                raise ValueError('Password-manager result limit exceeded; incomplete')
            yield (0, (int(proc.UniqueProcessId), name, layer_name, hex(offset), rule,
                *(item if item is not None else renderers.NotAvailableValue() for item in parsed)))
    if not selected:
        raise ValueError('Selected browser PID was not found')
'''

PASSWORD_RUN = '''
def run(self):
    pid = self.config.get('pid')
    if type(pid) is not int or not 1 <= pid <= 2**32 - 1:
        raise ValueError('An explicit positive browser PID is required')
    return renderers.TreeGrid([('PID', int), ('Process', str), ('Layer', str), ('Offset', str),
        ('Rule', str), ('Username', str), ('Password', str), ('Domain', str)],
        self._generator(pslist.PsList.list_processes(context=self.context,
            kernel_module_name=self.config['kernel'], filter_func=pslist.PsList.create_pid_filter([pid]))))
'''

SSH_REQUIREMENTS = '''
def get_requirements(cls):
    return [requirements.ModuleRequirement(name='kernel', description='Linux kernel', architectures=['Intel32', 'Intel64']),
        requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(4, 1, 1)),
        requirements.IntRequirement(name='pid', description='Explicit process PID for sensitive extraction', optional=False),
        requirements.IntRequirement(name='address', description='Virtual address of one suspected sshenc structure', optional=False)]
'''

SSH_PROBE = '''
def probe_address(self, ptr):
    if type(ptr) is not int or not 0 < ptr < 2**64:
        raise ValueError('A positive sshenc address is required')
    table = self.openssh_table_name + constants.BANG
    sshenc = self.context.object(table + 'sshenc_61p2', offset=ptr, layer_name=self.proc_layer_name)
    name = _cstring(self.proc_layer, int(sshenc.name))
    properties = lookup_enc(name)
    if properties is None:
        return None
    if int(sshenc.key_len) != properties[2]:
        raise ValueError('Recognized SSH cipher has a malformed key length')
    cipher = self.context.object(table + 'sshcipher', offset=int(sshenc.cipher), layer_name=self.proc_layer_name)
    if _cstring(self.proc_layer, int(cipher.name)) != name:
        raise ValueError('SSH cipher/name pointers disagree')
    if int(sshenc.block_size) != properties[1]:
        sshenc = self.context.object(table + 'sshenc_61p1', offset=ptr, layer_name=self.proc_layer_name)
    if int(sshenc.block_size) != properties[1]:
        raise ValueError('Unsupported SSH structure layout')
    iv_len = int(sshenc.iv_len) if sshenc.has_member('iv_len') else int(sshenc.block_size)
    if not 0 <= iv_len <= 32:
        raise ValueError('Invalid SSH IV length')
    return sshenc
'''

SSH_CONSTRUCT = '''
def construct_scraped_key(self, sshenc, ptr):
    key = ScrapedKey(self.task, sshenc, ptr)
    key.enc_name = _cstring(self.proc_layer, int(sshenc.name))
    properties = lookup_enc(key.enc_name)
    if properties is None or int(sshenc.key_len) != properties[2]:
        raise ValueError('Invalid SSH cipher or key length')
    key.key = _read(self.proc_layer, int(sshenc.key), int(sshenc.key_len)).hex()
    iv_len = int(sshenc.iv_len) if sshenc.has_member('iv_len') else int(sshenc.block_size)
    if not 0 <= iv_len <= 32:
        raise ValueError('Invalid SSH IV length')
    key.iv = _read(self.proc_layer, int(sshenc.iv), iv_len).hex() if iv_len else ''
    return key
'''

SSH_GENERATOR = '''
def _generator(self, tasks):
    kernel = self.context.modules[self.config['kernel']]
    filename = 'openssh64' if symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name) else 'openssh32'
    table = intermed.IntermediateSymbolTable.create(self.context, self.config_path, 'linux', filename)
    selected = False
    for task in tasks:
        if selected:
            raise ValueError('Expected exactly one SSH process')
        selected = True
        if not task.mm:
            raise ValueError('Selected PID has no userspace memory')
        layer_name = task.add_process_layer()
        with _ReadBudget(self.context) as budget:
            extractor = SSHKeyExtractor(self.context, table, layer_name, task, self._progress_callback)
            address = self.config['address']
            candidate = extractor.probe_address(address)
            key = extractor.construct_scraped_key(candidate, address) if candidate is not None else None
            if budget.failed:
                raise ValueError('Incomplete SSH memory reads')
        if key is not None:
            yield (0, (key.task_name, int(task.pid), layer_name, hex(address), key.enc_name, key.key, key.iv))
    if not selected:
        raise ValueError('Selected SSH PID was not found')
'''

SSH_RUN = '''
def run(self):
    pid, address = self.config.get('pid'), self.config.get('address')
    if type(pid) is not int or not 1 <= pid <= 2**32 - 1 or type(address) is not int or not 0 < address < 2**64:
        raise ValueError('Explicit positive PID and sshenc address are required')
    return renderers.TreeGrid([('Name', str), ('PID', int), ('Layer', str), ('Address', str),
        ('Cipher', str), ('Key', str), ('IV', str)],
        self._generator(pslist.PsList.list_tasks(self.context, self.config['kernel'],
            filter_func=pslist.PsList.create_pid_filter([pid]))))
'''

SSH_STRING = '''
def _cstring(layer, address):
    value = bytearray()
    for index in range(64):
        char = _read(layer, address + index, 1)
        if char == b'\\0':
            return value.decode('ascii')
        value.extend(char)
    raise ValueError('Unterminated SSH cipher name')
'''


def adapt_sensitive(filename, source, replace_method):
    if filename == 'passwordmanagers.py':
        source = source.replace('import re\n', 'import re\nimport json\n')
        replacements = {'get_requirements': PASSWORD_REQUIREMENTS, 'parse_result': PASSWORD_PARSE,
                        '_generator': PASSWORD_GENERATOR, 'run': PASSWORD_RUN}
        source = source.replace('Scan all processs for browsers and then scan the process memory for any password manager fragments',
                                'Manual sensitive extraction of historical LastPass browser fragments; requires an explicit PID')
    elif filename == 'openssh_sessionkeys.py':
        replacements = {'get_requirements': SSH_REQUIREMENTS, 'probe_address': SSH_PROBE,
                        'construct_scraped_key': SSH_CONSTRUCT, '_generator': SSH_GENERATOR, 'run': SSH_RUN,
                        '__str__': "def __str__(self):\n    return '<SSH key candidate; sensitive values omitted>'",
                        'write_output_file': "def write_output_file(self, *args):\n    raise ValueError('Use framework-managed output only')",
                        'extract': "def extract(self):\n    raise ValueError('Unbounded heap scanning is disabled; supply one address')",
                        'create_proc_filter': "def create_proc_filter(self):\n    return pslist.PsList.create_pid_filter([self.config['pid']])"}
        source = source.replace('class SSHKeys(interfaces.plugins.PluginInterface):',
            'class SSHKeys(interfaces.plugins.PluginInterface):\n    """Manual sensitive extraction at an explicit Linux PID/sshenc address; historical layouts only."""\n    _version = (1, 0, 0)')
    else:
        return source
    for name, replacement in replacements.items():
        source = replace_method(source, name, replacement)
    return source.rstrip() + '\n' + HELPERS + (PTE_BUDGET.replace('PTE', 'SSH') + SSH_STRING if filename == 'openssh_sessionkeys.py' else '')
