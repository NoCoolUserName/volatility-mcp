"""Harmless CPython runtime adapter fixtures; no private images or recovered code.

Run: /path/to/analyzer/bin/python tests/addon_python_runtime_smoke.py -v
By default this exercises installed plugins and their actual adjacent pinned ISF.
For preinstallation adapter checks only, set VOLATILITY_PYTHON_RUNTIME_ADAPTER_TEST=1.
"""
import ast
import contextlib
import ctypes
import hashlib
import importlib
import io
import json
import os
import platform
import struct
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

HOST_ARCHITECTURE = platform.architecture()
DENY = contextlib.ExitStack()
DENY.enter_context(patch('platform.architecture', return_value=HOST_ARCHITECTURE))
for target in ('socket.socket.connect', 'socket.create_connection', 'socket.getaddrinfo',
               'urllib.request.urlopen', 'subprocess.Popen'):
    DENY.enter_context(patch(target, side_effect=AssertionError('Offline fixture boundary: ' + target)))

from volatility3.framework import contexts
from volatility3.framework.interfaces.configuration import HierarchicalDict
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.cli.text_renderer import JsonRenderer

ADAPTER_MODE = os.environ.get('VOLATILITY_PYTHON_RUNTIME_ADAPTER_TEST') == '1'
PYTHON_COMMANDS = {
    'py_class.py': ('Py_Class', 'class'), 'py_module.py': ('Py_Module', 'module'),
    'py_function.py': ('Py_Function', 'function'), 'py_code.py': ('Py_Code', 'code'),
    'py_stack_call.py': ('Py_Stack_Call', 'stack_call'), 'py_stack_var.py': ('Py_Stack_Var', 'stack_var'),
}
if ADAPTER_MODE:
    # This is an explicit development mode. The default installed smoke does
    # not depend on the MCP package being present in the analyzer environment.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    from volatility_mcp.addon_python_runtime import PYTHON_RUNTIME_HELPER, adapt_python_runtime
    runtime = types.ModuleType('runtime_fixture')
    runtime.__file__ = __file__
    exec(compile(PYTHON_RUNTIME_HELPER, '<adapted-python-runtime>', 'exec'), runtime.__dict__)
    INSTALLED_LAYOUT = None
else:
    runtime = importlib.import_module('volatility3.plugins.windows.python_symbol_table')
    PYTHON_RUNTIME_HELPER = Path(runtime.__file__).read_text()
    INSTALLED_LAYOUT = runtime.load_layout()


def mini_layout():
    """Use the real installed ISF; a miniature layout is for adapter mode only."""
    if INSTALLED_LAYOUT is not None:
        return INSTALLED_LAYOUT
    fields = {
        'PyObject': {'ob_type': 8},
        'PyTypeObject': {'tp_name': 24, 'tp_dict': 264, 'tp_dictoffset': 288},
        'PyVarObject': {'ob_size': 16},
        'PyASCIIObject': {'length': 16, 'state': 32},
        'PyListObject': {'ob_item': 24},
        'PyDictObject': {'ma_used': 16, 'ma_keys': 32, 'ma_values': 40},
        'PyDictKeysObject': {'dk_log2_size': 8, 'dk_nentries': 32, 'dk_indices': 40},
        'PyDictKeyEntry': {'me_key': 8, 'me_value': 16},
        'PyModuleObject': {'md_dict': 16},
        'PyFunctionObject': {'func_code': 16, 'func_module': 88},
        'PyCodeObject': {'co_argcount': 16, 'co_nlocals': 28, 'co_firstlineno': 40,
                         'co_code': 48, 'co_varnames': 72, 'co_filename': 104, 'co_name': 112},
        'PyInterpreterState_head': {'next': 0, 'tstate_head': 8},
        'PyThreadState': {'next': 8, 'interp': 16, 'frame': 24},
        'PyFrameObject': {'f_back': 24, 'f_code': 32, 'f_lineno': 108, 'f_localsplus': 360},
    }
    return {'user_types': {name: {'fields': {field: {'offset': offset} for field, offset in mapping.items()}}
                           for name, mapping in fields.items()}}


class Fixture:
    def __init__(self):
        self.data = bytearray(262144)
        self.next = 4096
        self.types = {}
        self.runtime = 256
        self.config = {'pid': 123, 'runtime-address': self.runtime, 'python-version': '3.8',
                       'layout-verified': True}
        self.put(self.runtime + 8, 1, 4)
        self.put(self.runtime + 12, 1, 4)
        self.gc([])

    def alloc(self, count):
        result = self.next
        self.next = (self.next + count + 7) & ~7
        if self.next >= len(self.data):
            raise AssertionError('Fixture allocation exceeded')
        return result

    def put(self, offset, value, size=8, signed=False):
        self.data[offset:offset + size] = value.to_bytes(size, 'little', signed=signed)

    def typename(self, name):
        if name not in self.types:
            offset = self.alloc(400)
            self.types[name] = offset
            raw = name.encode() + b'\0'
            text = self.alloc(len(raw))
            self.data[text:text + len(raw)] = raw
            self.put(offset + 24, text)
            self.put(offset + 8, offset if name == 'type' else self.typename('type'))
        return self.types[name]

    def obj(self, kind, size=64):
        offset = self.alloc(size + 16) + 16
        self.put(offset + 8, self.typename(kind))
        return offset

    def string(self, value):
        raw = value.encode('ascii')
        offset = self.obj('str', 48 + len(raw))
        self.put(offset + 16, len(raw))
        self.put(offset + 32, 228, 4)
        self.data[offset + 48:offset + 48 + len(raw)] = raw
        return offset

    def integer(self, value):
        offset = self.obj('int')
        self.put(offset + 16, 1 if value >= 0 else -1, signed=True)
        self.put(offset + 24, abs(value), 4)
        return offset

    def sequence(self, values, kind='tuple'):
        offset = self.obj(kind, 40 + len(values) * 8)
        self.put(offset + 16, len(values))
        base = offset + 24 if kind == 'tuple' else offset + 40
        if kind == 'list':
            self.put(offset + 24, base)
        for index, value in enumerate(values):
            self.put(base + index * 8, value)
        return offset

    def dictionary(self, pairs, split=False):
        offset = self.obj('dict')
        keys = self.alloc(48 + len(pairs) * 24)
        self.put(offset + 16, len(pairs))
        self.put(offset + 32, keys)
        self.put(keys + 8, 8)
        self.put(keys + 32, len(pairs))
        values = self.alloc(len(pairs) * 8) if split else 0
        self.put(offset + 40, values)
        for index, (key, value) in enumerate(pairs):
            self.put(keys + 48 + index * 24 + 8, key)
            self.put(values + index * 8 if split else keys + 48 + index * 24 + 16, value)
        return offset

    def code(self):
        offset = self.obj('code', 176)
        self.put(offset + 16, 1, 4)
        self.put(offset + 28, 1, 4)
        self.put(offset + 40, 3, 4)
        self.put(offset + 72, self.sequence([self.string('value')]))
        self.put(offset + 104, self.string('synthetic.py'))
        self.put(offset + 112, self.string('fixture_function'))
        bytecode = self.obj('bytes')
        self.put(bytecode + 16, 4)
        self.data[bytecode + 32:bytecode + 36] = b'\x64\x00\x53\x00'
        self.put(offset + 48, bytecode)
        return offset

    def gc(self, objects):
        for generation in range(3):
            head = self.runtime + 0x170 + generation * 24
            nodes = [obj - 16 for obj in objects] if generation == 0 else []
            chain = [head] + nodes
            for index, node in enumerate(chain):
                self.put(node, chain[(index + 1) % len(chain)])
                self.put(node + 8, chain[index - 1])

    def populated(self):
        code = self.code()
        function = self.obj('function', 120)
        self.put(function + 16, code)
        self.put(function + 88, self.string('synthetic'))
        module = self.obj('module')
        self.put(module + 16, self.dictionary([(self.string('__name__'), self.string('synthetic')),
                                               (self.string('__file__'), self.string('synthetic.py'))]))
        klass = self.obj('type', 400)
        name = self.alloc(8)
        self.data[name:name + 8] = b'Fixture\0'
        self.put(klass + 24, name)
        self.put(klass + 264, self.dictionary([(self.string('answer'), self.integer(42))]))
        self.gc([function, module, klass])
        interp = self.alloc(16)
        self.put(self.runtime + 0x20, interp)
        thread = self.alloc(32)
        self.put(interp + 8, thread)
        self.put(thread + 16, interp)
        frame = self.obj('frame', 368)
        self.put(thread + 24, frame)
        self.put(frame + 32, code)
        self.put(frame + 108, 4, 4)
        self.put(frame + 360, self.integer(42))
        return NS(code=code, function=function, module=module, klass=klass,
                  interp=interp, thread=thread, frame=frame)

    def layer(self):
        context = contexts.Context()
        layer = BufferDataLayer(context, 'fixture.layer', 'synthetic', bytes(self.data))
        context.layers.add_layer(layer)
        return layer

    def reader(self, **values):
        return runtime.Reader(self.layer(), mini_layout(), dict(self.config, **values))

    def collect(self, mode, **values):
        return runtime.collect(self.layer(), mini_layout(), dict(self.config, **values), mode)


def adapted_plugins():
    result = []
    for os_name in ('windows', 'linux'):
        sys.modules['volatility3.plugins.' + os_name + '.python_symbol_table'] = runtime
        setattr(importlib.import_module('volatility3.plugins.' + os_name), 'python_symbol_table', runtime)
        for filename, (name, mode) in PYTHON_COMMANDS.items():
            source = 'class ' + name + ':\n    pass\n'
            adapted = adapt_python_runtime(filename, source, os_name + '/' + filename)
            module = types.ModuleType('python_fixture_' + os_name + '_' + name)
            exec(compile(adapted, '<adapted-python-plugin>', 'exec'), module.__dict__)
            result.append((os_name, name, mode, module, adapted))
    return result


def installed_plugins():
    result = []
    for os_name in ('windows', 'linux'):
        for filename, (name, mode) in PYTHON_COMMANDS.items():
            module = importlib.import_module('volatility3.plugins.' + os_name + '.' + filename[:-3])
            result.append((os_name, name, mode, module, Path(module.__file__).read_text()))
    return result


PLUGINS = adapted_plugins() if ADAPTER_MODE else installed_plugins()


class RuntimeTests(unittest.TestCase):
    def test_primary_header_runtime_prefix_offsets_lp64_and_llp64(self):
        # CPython v3.8.20 pycore_pystate.h / pycore_pymem.h prefix fields.
        # This ABI calculation checks our fixed offsets; it does not claim
        # compatibility with a captured interpreter or nonstandard builds.
        class Interpreters(ctypes.Structure):
            _fields_ = [('mutex', ctypes.c_uint64), ('head', ctypes.c_uint64),
                        ('main', ctypes.c_uint64), ('next_id', ctypes.c_int64)]
        class GCHead(ctypes.Structure):
            _fields_ = [('next', ctypes.c_uint64), ('previous', ctypes.c_uint64)]
        class Generation(ctypes.Structure):
            _fields_ = [('head', GCHead), ('threshold', ctypes.c_int32), ('count', ctypes.c_int32)]
        class GC(ctypes.Structure):
            _fields_ = [('trash_delete_later', ctypes.c_uint64), ('trash_delete_nesting', ctypes.c_int32),
                        ('enabled', ctypes.c_int32), ('debug', ctypes.c_int32), ('generations', Generation * 3)]
        for c_ulong in (ctypes.c_uint32, ctypes.c_uint64):
            class Prefix(ctypes.Structure):
                _fields_ = [('preinitializing', ctypes.c_int32), ('preinitialized', ctypes.c_int32),
                            ('core_initialized', ctypes.c_int32), ('initialized', ctypes.c_int32),
                            ('finalizing', ctypes.c_uint64), ('interpreters', Interpreters),
                            ('xid_mutex', ctypes.c_uint64), ('xid_head', ctypes.c_uint64),
                            ('main_thread', c_ulong), ('exitfuncs', ctypes.c_uint64 * 32),
                            ('nexitfuncs', ctypes.c_int32), ('gc', GC)]
            self.assertEqual(Prefix.core_initialized.offset, 8)
            self.assertEqual(Prefix.initialized.offset, 12)
            self.assertEqual(Prefix.finalizing.offset, 16)
            self.assertEqual(Prefix.interpreters.offset + Interpreters.head.offset, runtime.INTERPRETER_HEAD_OFFSET)
            self.assertEqual(Prefix.gc.offset + GC.generations.offset, runtime.GC_HEAD_OFFSET)
            self.assertEqual(ctypes.sizeof(Generation), 24)

    def test_all_twelve_import_requirements_and_api_signatures(self):
        self.assertEqual(len(PLUGINS), 12)
        for os_name, name, mode, module, source in PLUGINS:
            cls = getattr(module, name)
            requirements = {item.name: item for item in cls.get_requirements()}
            for required in ('pid', 'runtime-address', 'python-version'):
                self.assertFalse(requirements[required].optional)
            self.assertFalse(requirements['layout-verified'].default)
            if mode == 'stack_var':
                self.assertFalse(requirements['target-frame'].optional)
            self.assertFalse(requirements['pslist'].unsatisfied(contexts.Context(), 'fixture'))
            fixture = Fixture()
            fixture.populated()
            config = dict(fixture.config, **{'target-frame': 'fixture_function'})
            plugin = object.__new__(cls)
            plugin._config_path = 'fixture'
            plugin._context = NS(config=HierarchicalDict(), layers={'synthetic': fixture.layer()})
            plugin._context.config['fixture.kernel'] = 'kernel'
            for key, value in config.items():
                plugin._context.config['fixture.' + key] = value
            process = NS(add_process_layer=lambda: 'synthetic')
            method = 'list_processes' if os_name == 'windows' else 'list_tasks'
            output = io.StringIO()
            layout_scope = (patch.object(module.runtime, 'load_layout', return_value=mini_layout())
                            if ADAPTER_MODE else contextlib.nullcontext())
            with patch.object(module.pslist.PsList, method, autospec=True, return_value=[process]) as listing, \
                    layout_scope, contextlib.redirect_stdout(output):
                JsonRenderer().render(plugin.run())
            rows = json.loads(output.getvalue())
            self.assertEqual(rows[-1]['Status'], 'complete-selected-scope')
            self.assertEqual(rows[0]['PID'], 123)
            self.assertEqual(rows[0]['Layer'], 'synthetic')
            self.assertTrue(rows[0]['SourceOffset'].startswith('0x'))
            self.assertIsInstance(json.loads(rows[0]['RecordJSON']), dict)
            if os_name == 'windows':
                self.assertIn('kernel_module_name', listing.call_args.kwargs)
            else:
                self.assertEqual(listing.call_args.args[1], 'kernel')
            with patch.object(module.pslist.PsList, method, autospec=True, return_value=[]):
                with self.assertRaisesRegex(ValueError, 'PID was not found'):
                    plugin.run()
            with patch.object(module.pslist.PsList, method, autospec=True, return_value=[process, process]):
                with self.assertRaisesRegex(ValueError, 'More than one process'):
                    plugin.run()

    def test_valid_gc_and_stack_records_have_exact_source_offsets(self):
        fixture = Fixture()
        obj = fixture.populated()
        for mode, source in (('class', obj.klass), ('module', obj.module),
                             ('function', obj.function), ('code', obj.function),
                             ('stack_call', obj.frame), ('stack_var', obj.frame + 360)):
            rows = fixture.collect(mode, **{'target-frame': 'fixture_function'})
            self.assertEqual(rows[0][1], hex(source))
            self.assertEqual(rows[-1][0], 'complete-selected-scope')
        code = json.loads(fixture.collect('code')[0][2])
        self.assertEqual(code['bytecode_hex'], '64005300')
        self.assertEqual(code['code_offset'], hex(obj.code))
        var = json.loads(fixture.collect('stack_var', **{'target-frame': 'fixture_function'})[0][2])
        self.assertEqual(var['value'], 42)
        self.assertEqual(var['variable'], 'value')
        self.assertEqual(var['thread_state_offset'], hex(obj.thread))

    def test_empty_is_explicit_but_invalid_runtime_is_error(self):
        fixture = Fixture()
        self.assertEqual(fixture.collect('module')[0][0], 'empty-selected-scope')
        fixture.put(fixture.runtime + 12, 0, 4)
        with self.assertRaisesRegex(ValueError, 'uninitialized'):
            fixture.collect('module')
        fixture = Fixture()
        with self.assertRaisesRegex(ValueError, 'no interpreter'):
            fixture.collect('stack_call')

    def test_argument_and_layout_gates_before_reads(self):
        fixture = Fixture()
        for values in ({'pid': 0}, {'pid': [123]}, {'pid': True}, {'pid': 2**32},
                       {'runtime-address': 0}, {'runtime-address': -1}, {'runtime-address': 2**64},
                       {'python-version': '3.12'}, {'layout-verified': False}, {'layout-verified': 'yes'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                fixture.collect('module', **values)
        with self.assertRaisesRegex(ValueError, 'target-frame'):
            fixture.collect('stack_var')
        with self.assertRaisesRegex(ValueError, 'Unaligned'):
            fixture.collect('module', **{'runtime-address': 257})

    def test_read_traversal_output_and_container_bounds(self):
        fixture = Fixture()
        fixture.populated()
        for option in ('max-read-bytes', 'max-reads', 'max-objects', 'max-output-bytes'):
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, 'limit|budget'):
                fixture.collect('module', **{option: 1})
        for option, value in (('max-read-bytes', 67108865), ('max-results', 10001),
                              ('max-string-bytes', 1048577), ('max-objects', 0)):
            with self.assertRaises(ValueError):
                fixture.collect('module', **{option: value})
        reader = fixture.reader()
        with self.assertRaisesRegex(ValueError, 'read size'):
            reader.read(1, 65537)
        with self.assertRaisesRegex(ValueError, 'Unreadable'):
            reader.read(262140, 8)
        seq = fixture.sequence([])
        fixture.put(seq + 16, 500000)
        with self.assertRaisesRegex(ValueError, 'bound'):
            fixture.reader().sequence(seq)

    def test_malformed_gc_interpreter_and_frame_cycles_fail(self):
        fixture = Fixture()
        obj = fixture.populated()
        fixture.put(obj.function - 8, 0)
        with self.assertRaisesRegex(ValueError, 'backlinks'):
            fixture.collect('module')
        fixture = Fixture()
        obj = fixture.populated()
        fixture.put(obj.interp, obj.interp)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            fixture.collect('stack_call')
        fixture.put(obj.interp, 0)
        fixture.put(obj.frame + 24, obj.frame)
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            fixture.collect('stack_call')
        fixture.put(obj.frame + 24, 0)
        fixture.put(obj.thread + 16, 1)
        with self.assertRaisesRegex(ValueError, 'pointers disagree'):
            fixture.collect('stack_call')

    def test_unicode_integers_split_dicts_and_unsupported_values(self):
        fixture = Fixture()
        val = fixture.integer(-42)
        self.assertEqual(fixture.reader().value(val), -42)
        text = fixture.string('hello')
        self.assertEqual(fixture.reader().unicode(text), 'hello')
        for split in (False, True):
            dictionary = fixture.dictionary([(text, val)], split=split)
            parsed = fixture.reader().value(dictionary)
            self.assertEqual(parsed[0]['key'], 'hello')
            self.assertEqual(parsed[0]['value'], -42)
        unsupported = fixture.obj('native_fixture_type')
        self.assertEqual(fixture.reader().value(unsupported)['status'], 'unsupported-value-type')
        fixture.put(text + 32, 0, 4)
        with self.assertRaisesRegex(ValueError, 'Unicode layout'):
            fixture.reader().unicode(text)

    def test_unicode_code_points_ascii_validation_and_legacy_ready(self):
        fixture = Fixture()
        text = fixture.obj('str', 80)
        fixture.put(text + 16, 2)
        fixture.put(text + 32, (2 << 2) | (1 << 5) | (1 << 7), 4)
        fixture.data[text + 72:text + 76] = b'\0\xd8\0\xdc'
        self.assertEqual(fixture.reader().unicode(text), '\ud800\udc00')
        self.assertEqual(len(fixture.reader().unicode(text)), 2)
        legacy = fixture.obj('str', 80)
        fixture.put(legacy + 16, 3)
        fixture.put(legacy + 32, (1 << 2) | (1 << 6) | (1 << 7), 4)
        data = fixture.alloc(3)
        fixture.put(legacy + 72, data)
        fixture.data[data:data + 3] = b'abc'
        self.assertEqual(fixture.reader().unicode(legacy), 'abc')
        fixture.data[data] = 255
        with self.assertRaisesRegex(ValueError, 'non-ASCII'):
            fixture.reader().unicode(legacy)

    def test_malformed_dict_bytes_code_and_recursive_value(self):
        fixture = Fixture()
        dictionary = fixture.dictionary([])
        fixture.put(dictionary + 16, 1)
        with self.assertRaisesRegex(ValueError, 'entry counts'):
            fixture.reader().dictionary(dictionary)
        obj = fixture.populated()
        fixture.put(obj.code + 28, 2, 4)
        with self.assertRaisesRegex(ValueError, 'locals/varnames'):
            fixture.collect('code')
        fixture.put(obj.code + 28, 1, 4)
        bytecode = int.from_bytes(fixture.data[obj.code + 48:obj.code + 56], 'little')
        fixture.put(bytecode + 16, 3)
        with self.assertRaisesRegex(ValueError, 'wordcode length'):
            fixture.collect('code')
        recursive = fixture.sequence([val := fixture.integer(1)], kind='list')
        fixture.put(recursive + 40, recursive)
        parsed = fixture.reader().value(recursive)
        self.assertEqual(parsed[0]['status'], 'cycle-reference')

    def test_thread_selection_and_no_execution_or_network_calls(self):
        fixture = Fixture()
        obj = fixture.populated()
        self.assertEqual(fixture.collect('stack_call', **{'thread-address': obj.thread})[-1][0], 'complete-selected-scope')
        with self.assertRaisesRegex(ValueError, 'was not found'):
            fixture.collect('stack_call', **{'thread-address': 8192})
        forbidden = {'eval', 'exec', 'compile', 'CodeType', 'get_instructions', 'urlopen', 'system', 'Popen', 'connect', 'loads'}
        # json.loads parses the pinned local layout; it is not marshal/pickle.
        forbidden.remove('loads')
        for source in [PYTHON_RUNTIME_HELPER] + [item[4] for item in PLUGINS]:
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Call):
                    name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ''
                    self.assertNotIn(name, forbidden)

    def test_hash_mismatch_fails_and_source_attribution(self):
        with patch('pathlib.Path.open', return_value=io.BytesIO(b'{}')):
            with self.assertRaisesRegex(ValueError, 'pinned reviewed ISF'):
                runtime.load_layout()
        for source in [PYTHON_RUNTIME_HELPER] + [item[4] for item in PLUGINS]:
            self.assertIn('https://github.com/HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis', source)
            self.assertIn('d78a705e91a8f5146581e71062ae3e448f91b5de', source)
            self.assertIn('AGPL-3.0', source)
        if not ADAPTER_MODE:
            for os_name in ('windows', 'linux'):
                helper = importlib.import_module('volatility3.plugins.' + os_name + '.python_symbol_table')
                path = Path(helper.__file__).with_name('python_data_structures.json')
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), helper.LAYOUT_SHA256)
                self.assertEqual(helper.load_layout(), INSTALLED_LAYOUT)
                self.assertEqual(Path(helper.__file__).read_text(), PYTHON_RUNTIME_HELPER)

    @unittest.skipUnless(ADAPTER_MODE, 'Deterministic generation is tested in explicit preinstallation adapter mode')
    def test_deterministic_adapter(self):
        stub = 'class Py_Code:\n    pass\n'
        self.assertEqual(adapt_python_runtime('py_code.py', stub, 'linux/py_code.py'),
                         adapt_python_runtime('py_code.py', stub, 'linux/py_code.py'))
        with self.assertRaises(ValueError):
            adapt_python_runtime('py_code.py', 'class Other: pass', 'linux/py_code.py')
        with self.assertRaises(ValueError):
            adapt_python_runtime('py_code.py', stub, 'mac/py_code.py')


if __name__ == '__main__':
    unittest.main()
