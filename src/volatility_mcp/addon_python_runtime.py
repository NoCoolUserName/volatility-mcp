"""Deterministic, bounded adaptation of the pinned Python runtime addon suite.

Upstream is AGPL-3.0. The installer obtains its source and layout separately;
this module contains the adaptation and does not vendor the upstream sources.
Only the CPython 3.8 x64 release-layout subset is decoded. A selected process,
known runtime address, and explicit layout verification are mandatory.
"""
import ast
from pathlib import PurePosixPath


PYTHON_COMMANDS = {
    'py_class.py': ('Py_Class', 'class'),
    'py_module.py': ('Py_Module', 'module'),
    'py_function.py': ('Py_Function', 'function'),
    'py_code.py': ('Py_Code', 'code'),
    'py_stack_call.py': ('Py_Stack_Call', 'stack_call'),
    'py_stack_var.py': ('Py_Stack_Var', 'stack_var'),
}


# Installed beside each OS-specific plugin, outside Volatility's native files.
# This helper deliberately does not reconstruct executable host CodeType objects.
PYTHON_RUNTIME_HELPER = r'''
"""Bounded adaptation of Hala Ali's AGPL-3.0 Python runtime analysis suite.

Source: https://github.com/HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis
Commit: d78a705e91a8f5146581e71062ae3e448f91b5de
Requires the examiner-verified pinned CPython 3.8 research layout, x64
little endian, 8-byte pointers, no Py_TRACE_REFS. Foreign bytecode remains raw.
The original pinned ISF is provenance data; only reviewed fields are used.
This is not a compatibility claim for every CPython 3.8 build.
"""
import hashlib
import json
import math
import struct
from pathlib import Path

LAYOUT_SHA256 = '459ba9b5beb8e426073c4c515c26d39e55bc8f6f25ac7e20da5a77f3e6abb13e'
LAYOUT_NAME = 'Pinned CPython 3.8 x64 research layout; explicit examiner verification'
# Reviewed against CPython v3.8.20 Include/internal/pycore_pystate.h and
# Include/internal/pycore_pymem.h. Standard x64 LP64/LLP64 alignment puts
# initialized at 12, finalizing at 16, interpreters.head at 32, gc at 344,
# and gc.generations at gc+24. Nonstandard build layouts are unsupported.
INTERPRETER_HEAD_OFFSET = 0x20
GC_HEAD_OFFSET = 0x170


def limit(config, name, default, ceiling):
    value = config.get(name, default)
    if type(value) is not int or not 1 <= value <= ceiling:
        raise ValueError(name + ' must be between 1 and ' + str(ceiling))
    return value


def address(value, name='address', nullable=False):
    if type(value) is not int or not (0 if nullable else 1) <= value < 2**64:
        raise ValueError('Invalid ' + name)
    return value


def load_layout():
    path = Path(__file__).with_name('python_data_structures.json')
    with path.open('rb') as handle:
        data = handle.read(1048577)
    if len(data) > 1048576 or hashlib.sha256(data).hexdigest() != LAYOUT_SHA256:
        raise ValueError('Python layout file differs from pinned reviewed ISF')
    return json.loads(data)


class Reader:
    def __init__(self, layer, layout, config):
        self.layer = layer
        self.layout = layout['user_types']
        self.remaining_bytes = limit(config, 'max-read-bytes', 16777216, 67108864)
        self.remaining_reads = limit(config, 'max-reads', 100000, 500000)
        self.remaining_steps = limit(config, 'max-objects', 10000, 100000)
        self.max_string = limit(config, 'max-string-bytes', 65536, 1048576)
        self.max_rows = limit(config, 'max-results', 1000, 10000)
        self.remaining_output = limit(config, 'max-output-bytes', 4194304, 16777216)
        self.records = []

    def step(self):
        self.remaining_steps -= 1
        if self.remaining_steps < 0:
            raise ValueError('Python object/traversal limit exceeded; incomplete')

    def read(self, offset, size):
        address(offset)
        if type(size) is not int or not 0 <= size <= self.max_string or offset + size > 2**64:
            raise ValueError('Invalid or excessive Python read size; incomplete')
        if size == 0:
            return b''
        self.remaining_reads -= 1
        self.remaining_bytes -= size
        if self.remaining_reads < 0 or self.remaining_bytes < 0:
            raise ValueError('Python memory read budget exceeded; incomplete')
        try:
            result = self.layer.read(offset, size, pad=False)
        except Exception as exc:
            raise ValueError('Unreadable Python memory at ' + hex(offset) + '; incomplete') from exc
        if len(result) != size:
            raise ValueError('Short Python memory read at ' + hex(offset) + '; incomplete')
        return result

    def uint(self, offset, size=8, signed=False):
        return int.from_bytes(self.read(offset, size), 'little', signed=signed)

    def field(self, offset, structure, name, size=8, signed=False):
        relative = self.layout[structure]['fields'][name]['offset']
        return self.uint(offset + relative, size, signed)

    def pointer(self, offset, structure, name, nullable=False):
        return address(self.field(offset, structure, name), name, nullable)

    def cstring(self, offset):
        data = bytearray()
        for index in range(min(self.max_string, 1024)):
            char = self.read(offset + index, 1)
            if char == b'\0':
                return data.decode('utf-8', errors='strict')
            data.extend(char)
        raise ValueError('Unterminated Python type name; incomplete')

    def typename(self, offset):
        type_offset = self.pointer(offset, 'PyObject', 'ob_type')
        name = self.cstring(self.pointer(type_offset, 'PyTypeObject', 'tp_name'))
        if not name:
            raise ValueError('Empty Python object type; unsupported layout or malformed record')
        return name

    def expect(self, offset, kind):
        if self.typename(offset) != kind:
            raise ValueError('Unexpected Python object type; unsupported layout or malformed record')

    def count(self, value, maximum=4096):
        if not 0 <= value <= maximum:
            raise ValueError('Python container/count bound exceeded or malformed; incomplete')
        return value

    def unicode(self, offset):
        self.expect(offset, 'str')
        count = self.count(self.field(offset, 'PyASCIIObject', 'length', signed=True), self.max_string)
        state = self.field(offset, 'PyASCIIObject', 'state', size=4)
        kind, compact, ascii_only, ready = (state >> 2) & 7, (state >> 5) & 1, (state >> 6) & 1, (state >> 7) & 1
        if not ready or kind not in (1, 2, 4) or (ascii_only and kind != 1):
            raise ValueError('Unsupported or malformed Python Unicode layout')
        data_offset = offset + (48 if ascii_only else 72) if compact else self.uint(offset + 72)
        data = self.read(data_offset, count * kind)
        if ascii_only and any(value > 127 for value in data):
            raise ValueError('ASCII Python string contains non-ASCII bytes')
        # PEP 393 stores code points, not UTF-16. Preserve adjacent surrogate
        # code points independently instead of combining them into a character.
        if kind == 1:
            return data.decode('latin-1')
        try:
            return ''.join(chr(int.from_bytes(data[index:index + kind], 'little'))
                           for index in range(0, len(data), kind))
        except ValueError as exc:
            raise ValueError('Malformed Python Unicode code point') from exc

    def bytes_value(self, offset):
        self.expect(offset, 'bytes')
        size = self.count(self.field(offset, 'PyVarObject', 'ob_size', signed=True), self.max_string)
        return self.read(offset + 32, size)

    def sequence(self, offset, kind='tuple'):
        self.expect(offset, kind)
        count = self.count(self.field(offset, 'PyVarObject', 'ob_size', signed=True))
        base = offset + 24 if kind == 'tuple' else self.pointer(offset, 'PyListObject', 'ob_item', nullable=(count == 0))
        result = []
        for index in range(count):
            self.step()
            result.append(address(self.uint(base + index * 8)))
        return result

    def dictionary(self, offset):
        self.expect(offset, 'dict')
        used = self.count(self.field(offset, 'PyDictObject', 'ma_used', signed=True))
        keys = self.pointer(offset, 'PyDictObject', 'ma_keys')
        values = self.pointer(offset, 'PyDictObject', 'ma_values', nullable=True)
        # Upstream ISF names CPython 3.8's dk_size field dk_log2_size. It is
        # the actual power-of-two table size, never an exponent in this layout.
        table_size = self.field(keys, 'PyDictKeysObject', 'dk_log2_size', signed=True)
        if not 1 <= table_size <= 65536 or table_size & (table_size - 1):
            raise ValueError('Malformed Python dictionary table size')
        entries = self.count(self.field(keys, 'PyDictKeysObject', 'dk_nentries', signed=True))
        if entries > table_size or used > entries:
            raise ValueError('Malformed Python dictionary entry counts')
        width = 1 if table_size <= 255 else 2 if table_size <= 65535 else 4
        base = keys + self.layout['PyDictKeysObject']['fields']['dk_indices']['offset'] + table_size * width
        result = []
        for index in range(entries):
            self.step()
            entry = base + index * 24
            key = self.pointer(entry, 'PyDictKeyEntry', 'me_key', nullable=True)
            value = self.uint(values + index * 8) if values else self.pointer(entry, 'PyDictKeyEntry', 'me_value', nullable=True)
            if key and value:
                result.append((key, value, entry))
            elif value:
                raise ValueError('Malformed Python dictionary key/value pair')
        if len(result) != used:
            raise ValueError('Python dictionary occupancy mismatch; incomplete')
        return result

    def named_dictionary(self, offset):
        result = {}
        for key, value, entry in self.dictionary(offset):
            name = self.unicode(key)
            if name in result:
                raise ValueError('Duplicate Python attribute name; malformed dictionary')
            result[name] = (value, entry)
        return result

    def value(self, offset, depth=0, seen=None):
        self.step()
        if offset == 0:
            return {'status': 'unbound'}
        address(offset)
        seen = set() if seen is None else seen
        kind = self.typename(offset)
        if offset in seen:
            return {'status': 'cycle-reference', 'type': kind, 'address': hex(offset)}
        if depth > 8:
            raise ValueError('Python value recursion limit exceeded; incomplete')
        seen = seen | {offset}
        if kind == 'str':
            return self.unicode(offset)
        if kind == 'bytes':
            return {'encoding': 'hex', 'bytes': self.bytes_value(offset).hex(), 'data_offset': hex(offset + 32)}
        if kind in ('int', 'bool'):
            size = self.field(offset, 'PyVarObject', 'ob_size', signed=True)
            if abs(size) > 128:
                raise ValueError('Python integer digit bound exceeded; incomplete')
            number = 0
            for index in range(abs(size)):
                self.step()
                digit = self.uint(offset + 24 + index * 4, 4)
                if digit >= 2**30:
                    raise ValueError('Malformed Python integer digit')
                number |= digit << (30 * index)
            number = number if size >= 0 else -number
            if kind == 'bool':
                if number not in (0, 1):
                    raise ValueError('Malformed Python bool')
                return bool(number)
            return number
        if kind == 'NoneType':
            return None
        if kind == 'float':
            number = struct.unpack('<d', self.read(offset + 16, 8))[0]
            return number if math.isfinite(number) else {'float': repr(number)}
        if kind in ('tuple', 'list'):
            return [self.value(item, depth + 1, seen) for item in self.sequence(offset, kind)]
        if kind == 'dict':
            return [{'key': self.value(key, depth + 1, seen), 'value': self.value(value, depth + 1, seen),
                     'entry_offset': hex(entry)} for key, value, entry in self.dictionary(offset)]
        return {'status': 'unsupported-value-type', 'type': kind, 'address': hex(offset)}

    def code(self, offset, include_bytes=False):
        self.expect(offset, 'code')
        names = self.sequence(self.pointer(offset, 'PyCodeObject', 'co_varnames'))
        locals_count = self.count(self.field(offset, 'PyCodeObject', 'co_nlocals', size=4, signed=True))
        if len(names) != locals_count:
            raise ValueError('Python locals/varnames mismatch; unsupported layout or malformed code')
        info = {'code_offset': hex(offset),
                'name': self.unicode(self.pointer(offset, 'PyCodeObject', 'co_name')),
                'filename': self.unicode(self.pointer(offset, 'PyCodeObject', 'co_filename')),
                'first_line': self.field(offset, 'PyCodeObject', 'co_firstlineno', size=4, signed=True),
                'argcount': self.count(self.field(offset, 'PyCodeObject', 'co_argcount', size=4, signed=True)),
                'nlocals': locals_count, 'varnames': [self.unicode(item) for item in names]}
        if info['first_line'] < 0 or info['argcount'] > locals_count:
            raise ValueError('Malformed Python code metadata')
        if include_bytes:
            byte_offset = self.pointer(offset, 'PyCodeObject', 'co_code')
            data = self.bytes_value(byte_offset)
            if len(data) % 2:
                raise ValueError('Malformed CPython 3.8 wordcode length')
            info.update({'bytecode_offset': hex(byte_offset + 32), 'bytecode_hex': data.hex(),
                         'bytecode_format': 'CPython 3.8 raw wordcode; no host disassembly or execution'})
        return info

    def gc(self, runtime):
        seen = set()
        result = []
        for generation in range(3):
            head = runtime + GC_HEAD_OFFSET + generation * 24
            current = self.uint(head)
            previous = head
            while current != head:
                self.step()
                if not current or current & 7 or current in seen:
                    raise ValueError('Broken or cyclic Python GC chain; incomplete')
                seen.add(current)
                if self.uint(current + 8) & ~3 != previous:
                    raise ValueError('Python GC backlinks disagree; incomplete')
                obj = current + 16
                result.append((generation, obj, self.typename(obj)))
                previous, current = current, self.uint(current)
            if self.uint(head + 8) & ~3 != previous:
                raise ValueError('Python GC generation tail disagrees; incomplete')
        return result

    def append(self, source, record):
        text = json.dumps(record, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        # Account for the JSON renderer escaping the RecordJSON string again.
        self.remaining_output -= len(json.dumps(text, ensure_ascii=True).encode('utf-8')) + 256
        if self.remaining_output < 0 or len(self.records) >= self.max_rows:
            raise ValueError('Python output limit exceeded; incomplete')
        self.records.append((hex(source), text))

    def inspect_gc(self, runtime, mode):
        objects = self.gc(runtime)
        classes = {obj for _, obj, kind in objects if kind == 'type'}
        visited_codes = set()
        for generation, obj, kind in objects:
            self.step()
            record = {'generation': generation, 'object_offset': hex(obj), 'type': kind}
            if mode == 'module' and kind == 'module':
                attrs = self.named_dictionary(self.pointer(obj, 'PyModuleObject', 'md_dict'))
                record['attributes'] = {name: {'value': self.value(attrs[name][0]),
                    'value_offset': hex(attrs[name][0]), 'entry_offset': hex(attrs[name][1])}
                    for name in ('__name__', '__package__', '__file__') if name in attrs}
            elif mode in ('function', 'code') and (kind == 'function' or (kind == 'code' and mode == 'code')):
                code = self.pointer(obj, 'PyFunctionObject', 'func_code') if kind == 'function' else obj
                if mode == 'code' and code in visited_codes:
                    continue
                visited_codes.add(code)
                record.update(self.code(code, include_bytes=(mode == 'code')))
                if kind == 'function':
                    module = self.pointer(obj, 'PyFunctionObject', 'func_module', nullable=True)
                    record['module'] = self.value(module) if module else {'status': 'unset'}
            elif mode == 'class' and kind == 'type':
                record['name'] = self.cstring(self.pointer(obj, 'PyTypeObject', 'tp_name'))
                attrs = self.pointer(obj, 'PyTypeObject', 'tp_dict', nullable=True)
                record['attributes'] = self.value(attrs) if attrs else {'status': 'unset'}
            elif mode == 'class' and self.pointer(obj, 'PyObject', 'ob_type') in classes:
                record['class_offset'] = hex(self.pointer(obj, 'PyObject', 'ob_type'))
                # Native extension and negative variable-sized instance dict layouts
                # are deliberately reported as unsupported, never guessed.
                class_offset = int(record['class_offset'], 16)
                dict_offset = self.field(class_offset, 'PyTypeObject', 'tp_dictoffset', signed=True)
                if dict_offset > 0:
                    if dict_offset > 1048576:
                        raise ValueError('Python instance dictionary offset exceeds bound')
                    attrs = self.uint(obj + dict_offset)
                    record['attributes'] = self.value(attrs) if attrs else {'status': 'unset'}
                else:
                    record['attributes'] = {'status': 'unsupported-instance-dict-layout'}
            else:
                continue
            self.append(obj, record)

    def chain(self, first, structure, member):
        seen = set()
        current = first
        while current:
            self.step()
            address(current)
            if current & 7 or current in seen:
                raise ValueError('Broken or cyclic Python linked list; incomplete')
            seen.add(current)
            yield current
            current = self.pointer(current, structure, member, nullable=True)

    def inspect_stack(self, runtime, mode, target_frame, thread_filter):
        interpreter = self.uint(runtime + INTERPRETER_HEAD_OFFSET)
        if not interpreter:
            raise ValueError('Initialized Python runtime has no interpreter; incomplete')
        selected_thread = False
        for interp in self.chain(interpreter, 'PyInterpreterState_head', 'next'):
            thread = self.pointer(interp, 'PyInterpreterState_head', 'tstate_head', nullable=True)
            for state in self.chain(thread, 'PyThreadState', 'next'):
                if self.pointer(state, 'PyThreadState', 'interp') != interp:
                    raise ValueError('Python thread/interpreter pointers disagree; incomplete')
                if thread_filter and state != thread_filter:
                    continue
                selected_thread = True
                frame = self.pointer(state, 'PyThreadState', 'frame', nullable=True)
                for depth, current in enumerate(self.chain(frame, 'PyFrameObject', 'f_back')):
                    self.expect(current, 'frame')
                    code = self.code(self.pointer(current, 'PyFrameObject', 'f_code'))
                    details = {'interpreter_offset': hex(interp), 'thread_state_offset': hex(state),
                               'frame_offset': hex(current), 'depth': depth, 'code': code,
                               'stored_frame_line': self.field(current, 'PyFrameObject', 'f_lineno', size=4, signed=True)}
                    if mode == 'stack_call':
                        self.append(current, details)
                    elif code['name'] == target_frame:
                        base = current + self.layout['PyFrameObject']['fields']['f_localsplus']['offset']
                        for index, name in enumerate(code['varnames']):
                            self.step()
                            slot = base + index * 8
                            value = self.uint(slot)
                            self.append(slot, dict(details, variable=name, slot_offset=hex(slot),
                                value_offset=hex(value), value=self.value(value)))
        if thread_filter and not selected_thread:
            raise ValueError('Selected Python thread-state address was not found')


def validate_config(config, mode):
    pid = config.get('pid')
    if type(pid) is not int or not 1 <= pid < 2**32:
        raise ValueError('Exactly one explicit positive PID is required')
    address(config.get('runtime-address'), '_PyRuntime address')
    if config.get('python-version') != '3.8' or config.get('layout-verified') is not True:
        raise ValueError('Requires examiner-verified pinned CPython 3.8 x64 research layout; other layouts unsupported')
    if mode == 'stack_var' and (not isinstance(config.get('target-frame'), str) or not 1 <= len(config['target-frame']) <= 1024):
        raise ValueError('An explicit target-frame name is required')
    if config.get('thread-address') is not None:
        address(config['thread-address'], 'thread-state address')
    return pid


def collect(layer, layout, config, mode):
    validate_config(config, mode)
    reader = Reader(layer, layout, config)
    runtime = config['runtime-address']
    if runtime & 7:
        raise ValueError('Unaligned Python runtime address')
    if reader.uint(runtime + 8, 4) != 1 or reader.uint(runtime + 12, 4) != 1 or reader.uint(runtime + 16) != 0:
        raise ValueError('Python runtime is uninitialized/finalizing or layout does not match')
    if mode in ('stack_call', 'stack_var'):
        reader.inspect_stack(runtime, mode, config.get('target-frame'), config.get('thread-address'))
    elif mode in ('class', 'module', 'function', 'code'):
        reader.inspect_gc(runtime, mode)
    else:
        raise ValueError('Unknown Python runtime analysis mode')
    # Build all rows before rendering: a bound/read/parse failure cannot become
    # a successful partial or empty result. Empty is explicit and scoped.
    status = 'complete-selected-scope' if reader.records else 'empty-selected-scope'
    rows = [('record', offset, text) for offset, text in reader.records]
    summary = json.dumps({'status': status, 'records': len(rows), 'layout': LAYOUT_NAME,
        'runtime_offset': hex(runtime), 'mode': mode,
        'scope': 'three reachable GC generations or active interpreter/thread frames; excludes frozen/permanent GC generation and untracked objects',
        'limitations': 'accuracy requires representative authorized image validation; unsupported values are marked'},
        ensure_ascii=True, separators=(',', ':'))
    if reader.remaining_output < len(json.dumps(summary, ensure_ascii=True).encode('utf-8')) + 256:
        raise ValueError('Python output limit exceeded; incomplete')
    rows.append((status, hex(runtime), summary))
    return rows
'''


def adapt_python_runtime(filename, source, target):
    """Return the deterministic reviewed adapter for this source/target pair."""
    filename = PurePosixPath(filename).name
    os_name = PurePosixPath(target).parts[0]
    if os_name not in {'linux', 'windows'}:
        raise ValueError('Python runtime addon target must be linux/ or windows/')
    if filename == 'python_data_structures.json':
        return source
    if filename == 'python_symbol_table.py':
        if 'class python_Symbol_Table' not in source or 'class PyCodeObject' not in source:
            raise ValueError('Unexpected Python runtime helper source')
        ast.parse(PYTHON_RUNTIME_HELPER)
        return PYTHON_RUNTIME_HELPER.lstrip()
    if filename not in PYTHON_COMMANDS:
        raise ValueError('Unknown Python runtime addon file')
    class_name, mode = PYTHON_COMMANDS[filename]
    tree = ast.parse(source)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1:
        raise ValueError('Unexpected Python runtime plugin class')
    process_call = ('pslist.PsList.list_processes(context=self.context, kernel_module_name=self.config["kernel"], '
                    'filter_func=pslist.PsList.create_pid_filter([pid]))' if os_name == 'windows' else
                    'pslist.PsList.list_tasks(self.context, self.config["kernel"], '
                    'filter_func=pslist.PsList.create_pid_filter([pid]))')
    result = f'''"""Bounded adaptation of Hala Ali's {class_name} (AGPL-3.0).
Source: https://github.com/HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis
Commit: d78a705e91a8f5146581e71062ae3e448f91b5de
Pinned CPython 3.8 research layout only; explicit PID, runtime address, layout verification.
Source-derived values are inert data. Bytecode is emitted as raw hex, never executed.
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.{os_name} import pslist
from volatility3.plugins.{os_name} import python_symbol_table as runtime


class {class_name}(interfaces.plugins.PluginInterface):
    """Manual CPython 3.8 x64 {mode.replace('_', ' ')} analysis; pinned research layout only."""
    _version = (1, 1, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        result = [
            requirements.ModuleRequirement(name='kernel', description='{os_name.title()} kernel', architectures=['Intel64']),
            requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=pslist.PsList.version),
            requirements.IntRequirement(name='pid', description='One explicit Python process PID', optional=False),
            requirements.IntRequirement(name='runtime-address', description='Verified process virtual address of _PyRuntime', optional=False),
            requirements.StringRequirement(name='python-version', description='Verified target CPython version; only 3.8 supported', optional=False),
            requirements.BooleanRequirement(name='layout-verified', description='Examiner verified exact pinned research layout, x64, no Py_TRACE_REFS; not all CPython 3.8 builds', default=False, optional=True),
            requirements.IntRequirement(name='max-read-bytes', description='Memory read budget, maximum 67108864', default=16777216, optional=True),
            requirements.IntRequirement(name='max-reads', description='Read count budget, maximum 500000', default=100000, optional=True),
            requirements.IntRequirement(name='max-objects', description='Object/traversal budget, maximum 100000', default=10000, optional=True),
            requirements.IntRequirement(name='max-string-bytes', description='Single value/read bound, maximum 1048576', default=65536, optional=True),
            requirements.IntRequirement(name='max-results', description='Maximum data rows, maximum 10000', default=1000, optional=True),
            requirements.IntRequirement(name='max-output-bytes', description='Output budget, maximum 16777216', default=4194304, optional=True),
        ]
        if {mode!r} in ('stack_call', 'stack_var'):
            result.append(requirements.IntRequirement(name='thread-address', description='Optional exact thread-state address', optional=True))
        if {mode!r} == 'stack_var':
            result.append(requirements.StringRequirement(name='target-frame', description='Exact function name to inspect', optional=False))
        return result

    def run(self):
        pid = runtime.validate_config(self.config, {mode!r})
        selected = None
        for index, process in enumerate({process_call}):
            if index >= 1:
                raise ValueError('More than one process matched selected PID')
            selected = process
        if selected is None:
            raise ValueError('Selected Python PID was not found')
        layer_name = selected.add_process_layer()
        if layer_name is None:
            raise ValueError('Selected Python PID has no readable process layer')
        rows = runtime.collect(self.context.layers[layer_name], runtime.load_layout(), self.config, {mode!r})
        return renderers.TreeGrid([('PID', int), ('Layer', str), ('Status', str), ('SourceOffset', str), ('RecordJSON', str)],
            ((0, (pid, layer_name, status, offset, record)) for status, offset, record in rows))
'''
    ast.parse(result)
    return result
