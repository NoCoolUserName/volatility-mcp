"""Harmless Go parser fixtures; no images, private cases or executed Go binaries.

Use the analyzer Python. Before installing, set VOLATILITY_GO_SOURCE to the pinned
Go-Memory-Forensics checkout and PYTHONPATH=src. Otherwise test installed commands.
"""
import ast
import builtins
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import platform
import struct
import symtable
import types
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch


HOST_ARCHITECTURE = platform.architecture()
DENY = contextlib.ExitStack()
DENY.enter_context(patch("platform.architecture", return_value=HOST_ARCHITECTURE))
for target in ("socket.socket.connect", "socket.create_connection", "socket.getaddrinfo",
               "urllib.request.urlopen", "subprocess.Popen"):
    DENY.enter_context(patch(target, side_effect=AssertionError("Offline fixture boundary: " + target)))

from volatility3.framework import exceptions
from volatility3.framework.interfaces.configuration import HierarchicalDict
from volatility3.cli.text_renderer import JsonRenderer


HASHES = {
    'Linux_Plugins/go_entire_heap.py': 'ba713cf42bf33f16682f7eeda7ff2ac49ce43f115bb2c7b36c9e52dffe2e2e68',
    'Linux_Plugins/go_functions.py': '5de3b8f478a78a70f29b82a9944e8971c38475361423718f5747949be5dbef3e',
    'Linux_Plugins/go_goroutines.py': '2fa6047bf01b820cd92ea7325f158a8485daea43f5337af55b79520f2e828cb9',
    'Linux_Plugins/go_strings.py': '8086287cfa4b65d3ef22882b4c384f59f73723203fe8f99a174b023e3515408f',
    'Linux_Plugins/go_strings_obfuscated.py': '17b3de2a5cead0be08db091dfccfb05f3a9534c16909c5a5403b7f3c494c45db',
    'Windows_Plugins/go_entire_heap.py': 'dd70c8db1e4c1fc187071bececdd679ed81fef028caa7767df90125a5a57e1a1',
    'Windows_Plugins/go_functions.py': '5cae53dc147447a9fd834e5124f7e6431c58948e1a3ac9a4a6f70b096294d3f8',
    'Windows_Plugins/go_goroutines.py': 'fce3592f9e25316d74f97a44938b1a16ab893e11aa096e8b11ec73ed11a98acb',
    'Windows_Plugins/go_strings.py': '2dd09ba2367104fd04cca374cd907b980f177d9449b66694f18f0a031acfb9a0',
    'Windows_Plugins/go_strings_obfuscated.py': 'c827e47ba82133320e7e8b854bd9c3aa2bbc1d044c156ef651ef31f9d48c985e',
}
MODULES = {}
SOURCES = {}
for relative, expected_hash in HASHES.items():
    os_name = relative.split("_")[0].lower()
    filename = Path(relative).name
    name = "volatility3.plugins." + os_name + "." + Path(filename).stem
    if os.environ.get("VOLATILITY_GO_SOURCE"):
        from volatility_mcp.addon_go import adapt_go
        original = (Path(os.environ["VOLATILITY_GO_SOURCE"]) / relative).read_bytes()
        assert hashlib.sha256(original).hexdigest() == expected_hash
        source = adapt_go(filename, original.decode(), os_name + "/" + filename)
        assert source == adapt_go(filename, original.decode(), os_name + "/" + filename)
        module = types.ModuleType(name)
        exec(compile(source, "<pinned-go-adaptation>", "exec"), module.__dict__)
    else:
        module = importlib.import_module(name)
        source = Path(module.__file__).read_text()
    MODULES[os_name + "/" + Path(filename).stem] = module
    SOURCES[name] = source


class BytesLayer:
    def __init__(self, data):
        self.data, self.reads = data, []

    def read(self, offset, length, pad=False):
        self.reads.append((offset, length, pad))
        if offset < 0 or offset + length > len(self.data):
            raise exceptions.InvalidAddressException("synthetic", offset)
        return bytes(self.data[offset:offset + length])


def instance(module, data=None, values=None):
    cls = next(value for name, value in vars(module).items() if name.startswith("Go_"))
    plugin = object.__new__(cls)
    plugin._config_path = "fixture"
    layer = BytesLayer(data if data is not None else bytearray(65536))
    plugin._context = NS(config=HierarchicalDict(), layers={"memory": layer})
    for name, value in {"kernel": "kernel", "pid": [123], **(values or {})}.items():
        plugin._context.config["fixture." + name] = value
    plugin.layer_name = "memory"
    plugin._go_pid = 123
    plugin.go_version_str = "go1.20.0"
    plugin.go_version_tuple = (1, 20, 0)
    plugin._go_version_source = "synthetic fixture"
    plugin.types_cache = {}
    plugin.locals = {}
    plugin.heap_spans = []
    plugin.mspan_profile = None
    plugin.pclntab = {"ptrSize": 8, "minLC": 1, "address": 0x40, "nfunc": 1, "version": "Go 1.20+"}
    plugin.moduledata = {
        "ftab": {"ptr": 0x100, "len": 2},
        "funcnametab": {"ptr": 0x400, "len": 256, "cap": 256},
        "pclntable": {"ptr": 0x800, "len": 512},
        "pctab": {"ptr": 0x1000, "len": 1024},
        "text": 0x10000, "etext": 0x10100,
        "types": 0x5000, "etypes": 0x6000,
        "data_start": 0x1000, "edata": 0x1100,
        "rodata": 0x2000, "erodata": 0x2100,
    }
    plugin.types_start = plugin.moduledata["types"]
    return plugin, layer


def function_bytes():
    data = bytearray(65536)
    struct.pack_into("<IIII", data, 0x100, 0, 0, 0x20, 44)
    data[0x400:0x40e] = b"synthetic.main"
    struct.pack_into("<IIIIIIIIII4B", data, 0x800, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0)
    data[0x1000:0x1003] = b"\x02\x20\x00"
    return data


def runtime_image(os_name):
    """Synthetic executable mappings and a Go 1.20 module, never executable code."""
    data = bytearray(65536)
    base = 0x1000
    if os_name == "linux":
        data[base:base + 6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HHIQQQIHHHHHH", data, base + 16, 2, 62, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
        for index, (address, flags) in enumerate(((0x4000, 5), (0x6000, 4), (0x8000, 6))):
            struct.pack_into("<IIQQQQQQ", data, base + 64 + index * 56, 1, flags, 0, address, 0, 4096, 4096, 4096)
    else:
        data[base:base + 2] = b"MZ"
        struct.pack_into("<I", data, base + 60, 64)
        data[base + 64:base + 68] = b"PE\0\0"
        struct.pack_into("<HH", data, base + 68, 0x8664, 3)
        struct.pack_into("<H", data, base + 84, 112)
        data[base + 88:base + 90] = b"\x0b\x02"
        for index, (name, address, flags) in enumerate(((b".text", 0x4000, 0x60000000), (b".rdata", 0x6000, 0x40000000), (b".data", 0x8000, 0xc0000000))):
            section = base + 200 + index * 40
            data[section:section + 8] = name.ljust(8, b"\0")
            struct.pack_into("<II", data, section + 8, 4096, address - base)
            struct.pack_into("<I", data, section + 36, flags)
    data[0x6000:0x6008] = b"go1.20.0"
    data[0x6100:0x6108] = b"\xf1\xff\xff\xff\0\0\x01\x08"
    struct.pack_into("<QQ", data, 0x6108, 1, 1)
    data[0x6200:0x620e] = b"synthetic.main"
    data[0x6300:0x6303] = b"\x02\x20\0"
    struct.pack_into("<IIII", data, 0x6500, 0, 0, 32, 44)
    struct.pack_into("<Q", data, 0x8100, 0x6100)
    for index, (ptr, count) in enumerate(((0x6200, 256), (0x6600, 1), (0x6700, 64), (0x6300, 128), (0x6400, 64), (0x6500, 2))):
        struct.pack_into("<QQQ", data, 0x8108 + index * 24, ptr, count, count)
    fields = {160: 0x4000, 168: 0x5000, 176: 0x4000, 184: 0x5000,
              208: 0x8000, 216: 0x8800, 224: 0x8800, 232: 0x9000,
              296: 0x6800, 304: 0x6900, 312: 0x6000}
    for offset, value in fields.items():
        struct.pack_into("<Q", data, 0x8100 + offset, value)
    task = NS(add_process_layer=lambda: "memory", mm=NS(get_vma_iter=lambda: iter([NS(vm_start=base)])),
              get_peb=lambda: NS(ImageBaseAddress=base), get_vad_root=lambda: NS(traverse=lambda: iter(())))
    return data, task


class GoTests(unittest.TestCase):
    def test_requirements_imports_attribution_and_static_names(self):
        self.assertEqual(len(MODULES), 10)
        for name, module in MODULES.items():
            plugin, _ = instance(module)
            with self.subTest(name=name):
                req = {value.name: value for value in plugin.get_requirements()}
                self.assertFalse(req["pid"].optional)
                self.assertEqual(req["kernel"].requirements["layer_name"].architectures, ["Intel64"])
                self.assertNotIn("output", req)
                source = SOURCES[module.__name__]
                self.assertIn("68c4d93edcdea9f584ad855cf963eb803b4ca328", source)
                self.assertIn("Apache-2.0", source)
                table = symtable.symtable(source, "adapted", "exec")
                defined = set(table.get_identifiers()) | set(dir(builtins))
                def verify(scope):
                    for key in scope.get_identifiers():
                        symbol = scope.lookup(key)
                        if symbol.is_global() and symbol.is_referenced():
                            self.assertIn(key, defined)
                    for child in scope.get_children():
                        verify(child)
                verify(table)
                for node in ast.walk(ast.parse(source)):
                    if isinstance(node, ast.Import):
                        self.assertFalse({alias.name for alias in node.names} & {"os", "subprocess", "openai", "socket", "requests"})
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        self.assertNotIn(node.func.id, {"open", "exec", "eval", "print", "__import__"})

    def test_pcheader_uses_uintptr_counts_and_rejects_malformed(self):
        for module in MODULES.values():
            data = bytearray(64)
            data[:8] = b"\xf1\xff\xff\xff\0\0\x01\x08"
            struct.pack_into("<QQ", data, 8, 7, 11)
            plugin, layer = instance(module, data)
            self.assertEqual(plugin._validate_pcheader(0)["nfiles"], 11)
            layer.data[7] = 4
            self.assertIsNone(plugin._validate_pcheader(0))
            layer.data[7] = 8
            struct.pack_into("<Q", layer.data, 8, 2**40)
            self.assertIsNone(plugin._validate_pcheader(0))
            with self.assertRaises(exceptions.InvalidAddressException):
                plugin._validate_pcheader(60)
            self.assertTrue(all(not read[2] for read in layer.reads))

    def test_elf_headers_use_bounded_real_bytes(self):
        for name, module in MODULES.items():
            if not name.startswith("linux/"):
                continue
            data = bytearray(512)
            data[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 0, 0x1000, 0, 128, 128, 4096)
            plugin, layer = instance(module, data)
            segments = plugin._parse_program_headers("", plugin._parse_elf_header("", 0))
            self.assertEqual(segments[0]["runtime_vaddr"], 0)
            self.assertEqual(segments[0]["runtime_end"], 128)
            self.assertEqual(segments[0]["p_flags_str"], "R--")
            layer.data[5] = 2
            with self.assertRaises(ValueError):
                plugin._parse_elf_header("", 0)

    def test_pe_headers_require_amd64_and_bounded_sections(self):
        for name, module in MODULES.items():
            if not name.startswith("windows/"):
                continue
            data = bytearray(1024)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"
            struct.pack_into("<HH", data, 68, 0x8664, 1)
            struct.pack_into("<H", data, 84, 112)
            data[88:90] = b"\x0b\x02"
            data[200:208] = b".rdata\0\0"
            struct.pack_into("<II", data, 208, 64, 0x1000)
            struct.pack_into("<I", data, 236, 0x40000000)
            plugin, layer = instance(module, data)
            self.assertEqual(plugin._parse_pe_sections(plugin._parse_pe_header(0))[0]["name"], ".rdata")
            struct.pack_into("<H", layer.data, 68, 0xaa64)
            with self.assertRaises(ValueError):
                plugin._parse_pe_header(0)

    def test_original_function_parsers_and_correct_pc_tables(self):
        for name, module in MODULES.items():
            if not name.endswith(("go_functions", "go_goroutines")):
                continue
            plugin, layer = instance(module, function_bytes())
            rows = list(plugin._extract_functions("memory", plugin.pclntab, plugin.moduledata))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["name"], "synthetic.main")
            self.assertEqual(rows[0]["pc"], 0x10000)
            self.assertEqual(rows[0]["size"], 32)
            self.assertEqual(plugin._pcvalue(b"\x02\x08\0", 7, 0), 0)
            self.assertIsNone(plugin._pcvalue(b"\x02\x08\0", 8, 0))
            self.assertEqual(plugin._pcvalue(b"\0\x08\0", 0, 0), -1)
            for bad in (b"\x80", b"\xff" * 6, b"\x02\0"):
                with self.assertRaises(ValueError):
                    plugin._pcvalue(bad, 0, 0)
            struct.pack_into("<i", layer.data, 0x804, -1)
            self.assertEqual(list(plugin._extract_functions("memory", plugin.pclntab, plugin.moduledata)), [])

    def test_goroutine_layouts_and_stack_unwind(self):
        for name, module in MODULES.items():
            if not name.endswith("go_goroutines"):
                continue
            for minor in (16, 18, 20, 23, 24, 25):
                plugin, layer = instance(module, function_bytes())
                plugin.go_version_tuple = (1, minor, 0)
                struct.pack_into("<QQ", layer.data, 0x200, 0x3000, 0x3100)
                struct.pack_into("<QQ", layer.data, 0x238, 0x3000, 0x10000)
                status_offset, id_offset = (0x90, 0x98) if minor < 18 or minor >= 24 else (0x98, 0xa0)
                struct.pack_into("<I", layer.data, 0x200 + status_offset, 4)
                struct.pack_into("<Q", layer.data, 0x200 + id_offset, 42)
                info = plugin._parse_goroutine("memory", 0x200, 8)
                self.assertEqual(info["goid"], 42)
                frames = plugin._unwind_goroutine_stack(info, {0x10000: {"pc": 0x10000, "size": 32, "pcsp": 0, "name": "synthetic.main"}})
                self.assertEqual(frames[0]["ret_pc_addr"], 0x3000)
                struct.pack_into("<Q", layer.data, 0x208, 0)
                self.assertIsNone(plugin._parse_goroutine("memory", 0x200, 8))

    def test_original_static_string_parser_valid_empty_and_malformed(self):
        for name, module in MODULES.items():
            if "go_strings" not in name:
                continue
            plugin, layer = instance(module)
            struct.pack_into("<QQ", layer.data, 0x1000, 0x2000, 14)
            layer.data[0x2000:0x200e] = b"synthetic text"
            rows = plugin._extract_rodata_data_strings(8)
            self.assertEqual(rows[0]["value"], "synthetic text")
            self.assertEqual(rows[0]["struct_addr"], 0x1000)
            self.assertEqual(rows[0]["data_addr"], 0x2000)
            struct.pack_into("<Q", layer.data, 0x1008, 2**60)
            self.assertEqual(plugin._extract_rodata_data_strings(8), [])
            layer.data[:] = bytes(len(layer.data))
            self.assertEqual(plugin._extract_rodata_data_strings(8), [])

    def test_original_heap_slots_and_iteration_bounds(self):
        for name, module in MODULES.items():
            if not ("go_strings" in name or name.endswith("go_entire_heap")):
                continue
            plugin, layer = instance(module)
            layer.data[0x3000:0x3008] = b"fixture!"
            layer.data[0x4000] = 1
            span = {"startAddr": 0x3000, "nelems": 2, "elemsize": 8,
                    "span_addr": 0x200, "allocBits_ptr": 0x4000, "allocCount": 1}
            records = plugin._extract_objects_from_span(span)
            self.assertEqual(records[0]["address"], 0x3000)
            plugin._go_budget_state = module._GoBudget({"max_steps": 3})
            span["nelems"] = 100
            with self.assertRaisesRegex(ValueError, "bound"):
                plugin._extract_objects_from_span(span)

    def test_read_and_output_bounds_cannot_be_swallowed(self):
        for module in MODULES.values():
            plugin, layer = instance(module)
            with self.assertRaisesRegex(ValueError, "oversized"):
                module._go_read(plugin, layer, 0, 16777217)
            self.assertEqual(layer.reads, [])
            plugin._go_budget_state = module._GoBudget({"max_bytes": 2})
            with self.assertRaisesRegex(ValueError, "cumulative"):
                module._go_read(plugin, layer, 0, 3)
            plugin._go_budget_state = module._GoBudget({"max_rows": 1})
            module._go_row(plugin, "fixture", 8, {"value": "safe"})
            with self.assertRaisesRegex(ValueError, "row/byte"):
                module._go_row(plugin, "fixture", 16, {"value": "safe"})
            cycle = []
            cycle.append(cycle)
            with self.assertRaisesRegex(ValueError, "Cyclic"):
                module._go_safe_data(cycle)
            plugin._go_budget_state = module._GoBudget({})
            @module._go_call_guard
            def recursive(obj, addr):
                return recursive(obj, addr)
            with self.assertRaisesRegex(ValueError, "Cyclic"):
                recursive(plugin, 123)
            safe = module._go_safe_data({"nan": float("nan"), "infinity": float("inf")})
            self.assertEqual(safe["nan"], {"nonfinite_float": "nan"})
            json.dumps(safe, allow_nan=False)

    def test_real_executable_pclntab_moduledata_discovery(self):
        for name, module in MODULES.items():
            os_name = name.split("/")[0]
            data, task = runtime_image(os_name)
            plugin, layer = instance(module, data)
            with self.subTest(command=name):
                segments = plugin._go_prepare(task)
                self.assertEqual(len(segments), 3)
                self.assertEqual(plugin.pclntab["address"], 0x6100)
                self.assertEqual(plugin.moduledata["address"], 0x8100)
                self.assertEqual(plugin.go_version_tuple, (1, 20, 0))
                self.assertEqual(module._go_budget(plugin).parser_failures, 0)
                if name.endswith("go_functions"):
                    api = "list_tasks" if os_name == "linux" else "list_processes"
                    with patch.object(module.pslist.PsList, api, autospec=True, return_value=[task]):
                        rows = list(plugin._generator())
                    self.assertEqual([row[1][2] for row in rows], ["runtime", "function", "status"])
                    self.assertEqual(rows[1][1][3], 0x6400)
                    self.assertEqual(json.loads(rows[1][1][4])["name"], "synthetic.main")

    def test_unresolved_unwind_is_error_and_missing_saved_stack_is_empty(self):
        for name, module in MODULES.items():
            if not name.endswith("go_goroutines"):
                continue
            plugin, _ = instance(module, function_bytes())
            record = {"sched_pc": 0x10000, "sched_sp": 0x3000, "stack_lo": 0x3000, "stack_hi": 0x3100}
            with self.assertRaisesRegex(ValueError, "Unresolved"):
                plugin._unwind_goroutine_stack(record, {})
            record.update(sched_pc=0, sched_sp=0)
            self.assertEqual(plugin._unwind_goroutine_stack(record, {}), [])

    def test_heap_bitmap_conflicts_and_intermediate_object_bounds(self):
        for name, module in MODULES.items():
            if not name.endswith("go_entire_heap"):
                continue
            plugin, layer = instance(module)
            span = {"startAddr": 0x3000, "nelems": 2, "elemsize": 8,
                    "span_addr": 0x200, "allocBits_ptr": 0x4000, "allocCount": 1}
            with self.assertRaisesRegex(ValueError, "contradicts"):
                plugin._extract_objects_from_span(span)
            plugin._go_budget_state = module._GoBudget({"max_rows": 1})
            target = []
            module._go_append(plugin, target, 1)
            with self.assertRaisesRegex(ValueError, "intermediate"):
                module._go_extend(plugin, target, [2])

    def test_ambiguous_heap_profiles_and_older_heap_versions_fail(self):
        for name, module in MODULES.items():
            if not name.endswith("go_entire_heap") and "obfuscated" not in name:
                continue
            plugin, layer = instance(module)
            struct.pack_into("<QQQ", layer.data, 0x100, 0x2000, 0x2100, 0x2200)
            with patch.object(plugin, "_validate_span_with_profile", return_value=True):
                with self.assertRaisesRegex(ValueError, "Ambiguous"):
                    plugin._detect_mspan_profile(0x100, 3)
            plugin.go_version_tuple = (1, 16, 0)
            with self.assertRaisesRegex(ValueError, "before 1.18"):
                plugin._go_heap([])

    def test_single_pid_missing_process_and_current_api(self):
        for name, module in MODULES.items():
            for bad in ([], [0], [1, 2]):
                plugin, _ = instance(module, values={"pid": bad})
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    list(plugin._generator())
            plugin, _ = instance(module)
            api = "list_tasks" if name.startswith("linux/") else "list_processes"
            with patch.object(module.pslist.PsList, api, autospec=True, return_value=[]) as listing:
                with self.assertRaisesRegex(ValueError, "not found"):
                    list(plugin._generator())
                self.assertEqual(listing.call_count, 1)

    def test_json_rows_and_function_count_failure(self):
        for name, module in MODULES.items():
            if not name.endswith("go_functions"):
                continue
            plugin, layer = instance(module, function_bytes())
            api = "list_tasks" if name.startswith("linux/") else "list_processes"
            output = io.StringIO()
            with patch.object(module.pslist.PsList, api, autospec=True, return_value=[NS()]), \
                 patch.object(plugin, "_go_prepare", return_value=[]), \
                 patch("builtins.open", side_effect=AssertionError("no host file reads")), \
                 contextlib.redirect_stdout(output):
                JsonRenderer().render(plugin.run())
            rows = json.loads(output.getvalue())
            self.assertEqual([row["Kind"] for row in rows], ["runtime", "function", "status"])
            self.assertEqual(rows[1]["Offset"], 0x800)
            self.assertEqual(rows[1]["Layer"], "memory")
            self.assertEqual(json.loads(rows[1]["Details"])["name"], "synthetic.main")
            struct.pack_into("<i", layer.data, 0x804, -1)
            with patch.object(module.pslist.PsList, api, autospec=True, return_value=[NS()]), patch.object(plugin, "_go_prepare", return_value=[]):
                with self.assertRaisesRegex(ValueError, "count mismatch"):
                    list(plugin._generator())


if __name__ == "__main__":
    unittest.main()
