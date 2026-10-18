"""Deterministic adapters for the pinned Go runtime research plugins.

Upstream parsers are fetched by the addon installer, never vendored here.  The
adapter replaces their print-only orchestration, removes unreachable host/network
helpers, and instruments every retained parser loop and memory read.
"""

import ast
from pathlib import PurePosixPath


GO_COMMANDS = {
    "go_strings.py": "Go_Strings",
    "go_strings_obfuscated.py": "Go_Strings",
    "go_functions.py": "Go_Functions",
    "go_goroutines.py": "Go_Goroutines",
    "go_entire_heap.py": "Go_Entire_Heap",
}


_SUPPORT = r'''
import json as _go_json
import math as _go_math
import re as _go_re
import struct as _go_struct
import time as _go_time
from volatility3.framework.renderers import format_hints as _go_hints


class _GoAbort(ValueError):
    """A bound was reached; parsers must not swallow this as an absent record."""


class _GoBudget:
    def __init__(self, config):
        limits = {"max_bytes": (268435456, 1073741824),
                  "max_rows": (20000, 100000), "max_seconds": (60, 300),
                  "max_steps": (2000000, 10000000)}
        for name, (default, ceiling) in limits.items():
            value = config.get(name, default)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
                raise ValueError("Invalid bounded Go option: " + name)
            setattr(self, name, value)
        self.deadline = _go_time.monotonic() + self.max_seconds
        self.steps = self.bytes = self.rows = self.output_bytes = self.read_failures = self.parser_failures = 0
        self.active = set()

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps or _go_time.monotonic() > self.deadline:
            raise _GoAbort("Go parser step/time bound reached; analysis incomplete")


def _go_budget(plugin):
    if not hasattr(plugin, "_go_budget_state"):
        plugin._go_budget_state = _GoBudget(plugin.config)
    return plugin._go_budget_state


def _go_tick(plugin):
    _go_budget(plugin).tick()


def _go_iter(plugin, values):
    for value in values:
        _go_tick(plugin)
        yield value


def _go_append(plugin, target, value):
    if len(target) >= _go_budget(plugin).max_rows:
        raise _GoAbort("Go intermediate object bound reached; analysis incomplete")
    target.append(value)


def _go_extend(plugin, target, values):
    for value in _go_iter(plugin, values):
        _go_append(plugin, target, value)


def _go_read(plugin, layer, offset, length, *args, **kwargs):
    budget = _go_budget(plugin)
    budget.tick()
    offset, length = int(offset), int(length)
    if offset < 0 or length < 0 or offset + length > (1 << 64) or length > 16777216:
        raise _GoAbort("Invalid or oversized Go memory read; analysis incomplete")
    budget.bytes += length
    if budget.bytes > budget.max_bytes:
        raise _GoAbort("Go cumulative read bound reached; analysis incomplete")
    try:
        data = layer.read(offset, length, pad=False)
        if len(data) != length:
            raise ValueError("Short Go memory read; analysis incomplete")
        return data
    except Exception:
        budget.read_failures += 1
        raise


def _go_call_guard(method):
    """Bound nested parser recursion and reject cycles instead of guessing."""
    def guarded(self, *args, **kwargs):
        budget = _go_budget(self)
        budget.tick()
        token = (method.__name__, tuple(x if isinstance(x, (int, str, bytes, type(None))) else id(x)
                                       for x in args[:3]))
        if len(budget.active) >= 96 or token in budget.active:
            raise _GoAbort("Cyclic or excessive Go parser recursion; analysis incomplete")
        budget.active.add(token)
        try:
            return method(self, *args, **kwargs)
        finally:
            budget.active.remove(token)
    return guarded


def _go_safe_data(value, depth=0, seen=None):
    if depth > 12:
        raise _GoAbort("Go record nesting bound reached; analysis incomplete")
    if isinstance(value, float) and not _go_math.isfinite(value):
        return {"nonfinite_float": str(value)}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > 131072:
            raise _GoAbort("Go string output bound reached; analysis incomplete")
        return value
    if isinstance(value, bytes):
        if len(value) > 131072:
            raise _GoAbort("Go byte output bound reached; analysis incomplete")
        return value.hex()
    seen = set() if seen is None else seen
    if id(value) in seen:
        raise _GoAbort("Cyclic Go output record; analysis incomplete")
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            if len(value) > 10000:
                raise _GoAbort("Go object output bound reached; analysis incomplete")
            return {str(k): _go_safe_data(v, depth + 1, seen) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            if len(value) > 10000:
                raise _GoAbort("Go array output bound reached; analysis incomplete")
            return [_go_safe_data(v, depth + 1, seen) for v in value]
        raise ValueError("Unexpected Go parser output type: " + type(value).__name__)
    finally:
        seen.remove(id(value))


def _go_row(plugin, kind, address, data):
    budget = _go_budget(plugin)
    budget.tick()
    budget.rows += 1
    details = _go_json.dumps(_go_safe_data(data), ensure_ascii=True, sort_keys=True, allow_nan=False)
    budget.output_bytes += len(details)
    if budget.rows > budget.max_rows or len(details) > 1048576 or budget.output_bytes > 33554432:
        raise _GoAbort("Go output row/byte bound reached; analysis incomplete")
    return 0, (plugin._go_pid, plugin.layer_name, kind, _go_hints.Hex(int(address)), details)
'''


_METHODS = r'''
def get_requirements(cls):
    return [requirements.ModuleRequirement(name="kernel", description="__OS__ kernel symbols", architectures=["Intel64"]),
            requirements.ListRequirement(name="pid", description="Exactly one target process PID", element_type=int, optional=False),
            requirements.StringRequirement(name="go_version", description="Exact Go version override for obfuscated metadata (for example go1.24.10)", optional=True),
            requirements.IntRequirement(name="max_bytes", description="Cumulative memory read limit, at most 1073741824 bytes", default=268435456, optional=True),
            requirements.IntRequirement(name="max_rows", description="Output row limit, at most 100000", default=20000, optional=True),
            requirements.IntRequirement(name="max_seconds", description="Parser time limit, at most 300 seconds", default=60, optional=True),
            requirements.IntRequirement(name="max_steps", description="Parser iteration limit, at most 10000000", default=2000000, optional=True)]

def _go_prepare(self, task):
    self.layer_name = task.add_process_layer()
    if not self.layer_name:
        raise ValueError("Cannot create Go process layer; analysis incomplete")
    layer = self.context.layers[self.layer_name]
    if "__OS__" == "linux":
        segments = []
        for vma in _go_iter(self, task.mm.get_vma_iter()):
            base = int(vma.vm_start)
            try:
                if _go_read(self, layer, base, 4) != b"\x7fELF":
                    continue
                segments = self._parse_program_headers("", self._parse_elf_header("", base))
                if segments:
                    break
            except exceptions.InvalidAddressException:
                continue
    else:
        base = self._find_pe_base(task)
        if not base:
            raise ValueError("No process PE found; unsupported or incomplete Go analysis")
        header = self._parse_pe_header(base)
        if not header.get("valid") or not header.get("is_64bit"):
            raise ValueError("Go integration requires a valid AMD64 PE")
        segments = self._parse_pe_sections(header)
    if not segments:
        raise ValueError("No executable segments found; unsupported or incomplete Go analysis")
    if len(segments) > 256:
        raise _GoAbort("Executable segment count bound reached")
    for segment in segments:
        start, end = int(segment["runtime_vaddr"]), int(segment["runtime_end"])
        if start < 0 or end < start or end - start > 268435456:
            raise _GoAbort("Invalid or oversized executable segment; analysis incomplete")
    detected = self._extract_go_version(segments)
    override = self.config.get("go_version", None)
    version = override or detected
    match = _go_re.fullmatch(r"go(1)\.(1[6-9]|2[0-5])(?:\.(\d{1,3}))?", version or "")
    if not match:
        raise ValueError("Exact Go 1.16 through 1.25 version required; unknown, guessed, older and future layouts are unsupported")
    self.go_version_str = version
    self.go_version_tuple = (int(match[1]), int(match[2]), int(match[3] or 0))
    self.pclntab = self._find_pclntab(segments)
    if not self.pclntab or self.pclntab.get("ptrSize") != 8:
        raise ValueError("No valid 64-bit Go pclntab found; unsupported or incomplete analysis")
    self.moduledata = self._find_moduledata(segments, self.pclntab["address"], 8, self.go_version_str)
    if not self.moduledata:
        raise ValueError("Go moduledata not found; unsupported or incomplete analysis")
    self.types_start = self.moduledata["types"]
    self._go_version_source = "explicit override" if override else "memory string; candidate version"
    return segments

def _go_heap(self, segments):
    if self.go_version_tuple[1] < 18:
        raise ValueError("Go heap layouts before 1.18 require separate validation")
    heap = self._find_mheap_global(segments)
    if not heap:
        raise ValueError("Go mheap not found; heap coverage incomplete")
    spans = self._enumerate_spans(heap)
    if not spans:
        raise ValueError("No validated Go heap spans; heap coverage incomplete")
    self.heap_spans = spans
    objects_found = self._extract_all_objects(spans)
    return objects_found

def _generator(self):
    pids = self.config.get("pid", [])
    if len(pids) != 1 or isinstance(pids[0], bool) or int(pids[0]) <= 0:
        raise ValueError("Go runtime commands require exactly one positive --pid")
    self._go_pid = int(pids[0])
    self._go_budget_state = _GoBudget(self.config)
    pid_filter = pslist.PsList.create_pid_filter([self._go_pid])
    if "__OS__" == "linux":
        tasks = pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func=pid_filter)
    else:
        tasks = pslist.PsList.list_processes(context=self.context, kernel_module_name=self.config["kernel"], filter_func=pid_filter)
    found = False
    for task in _go_iter(self, tasks):
        if found:
            raise ValueError("Duplicate PID process candidates; selection is ambiguous")
        found = True
        segments = self._go_prepare(task)
        yield _go_row(self, "runtime", self.pclntab["address"], {"version": self.go_version_str,
                         "version_source": self._go_version_source, "moduledata": self.moduledata.get("address"),
                         "offset_space": "process virtual address", "assessment": "heuristic candidate records; accuracy not established for this build"})
        mode = "__MODE__"
        if mode in ("go_functions", "go_goroutines"):
            functions = {}
            function_count = 0
            for info in _go_iter(self, self._extract_functions(self.layer_name, self.pclntab, self.moduledata)):
                function_count += 1
                address = self.moduledata["pclntable"]["ptr"] + info["funcoff"]
                if mode == "go_functions":
                    yield _go_row(self, "function", address, info)
                else:
                    functions[info["pc"]] = info
                if len(functions) > 100000:
                    raise _GoAbort("Go function count bound reached; analysis incomplete")
            if function_count != self.pclntab["nfunc"]:
                raise ValueError("Go function table count mismatch; analysis incomplete")
            if mode == "go_goroutines":
                allgs = self._find_allgs_via_scan(self.layer_name, segments, 8)
                if not allgs or not 0 < allgs["len"] <= 10000:
                    raise ValueError("Go allgs not found or invalid; goroutine analysis incomplete")
                raw = _go_read(self, self.context.layers[self.layer_name], allgs["ptr"], allgs["len"] * 8)
                seen = set()
                for index in _go_iter(self, range(allgs["len"])):
                    pointer = int.from_bytes(raw[index * 8:index * 8 + 8], "little")
                    if pointer in seen or not pointer:
                        raise ValueError("Duplicate/null goroutine pointer; analysis incomplete")
                    seen.add(pointer)
                    info = self._parse_goroutine(self.layer_name, pointer, 8)
                    if not info:
                        raise ValueError("Malformed/unreadable goroutine record; analysis incomplete")
                    yield _go_row(self, "goroutine", pointer, info)
                    frames = self._unwind_goroutine_stack(info, functions, max_frames=256)
                    for frame in _go_iter(self, frames):
                        frame.pop("func_info", None)
                        yield _go_row(self, "frame", frame["ret_pc_addr"], frame)
                    if len(frames) == 256:
                        raise _GoAbort("Go stack frame limit reached; unwind incomplete")
        else:
            types = self._extract_types_by_scanning(8)
            itabs = self._extract_itabs(8)
            heap_objects = self._go_heap(segments)
            if mode == "go_entire_heap":
                records = self.heap_objects_extraction(heap_objects, types, itabs)
                for address, record in _go_iter(self, records.items()):
                    yield _go_row(self, "heap_object", address, record)
            else:
                for record in _go_iter(self, self.heap_strings_extraction(heap_objects, types, itabs)):
                    yield _go_row(self, "heap_string", record["struct_addr"], record)
                for record in _go_iter(self, self._extract_rodata_data_strings(8)):
                    yield _go_row(self, "static_string", record["struct_addr"], record)
        budget = _go_budget(self)
        if budget.read_failures or budget.parser_failures:
            raise ValueError("Go parser encountered failed/short records; returned rows are partial and analysis is incomplete")
        yield _go_row(self, "status", 0, {"status": "completed_bounded", "artifact_rows": budget.rows - 1,
                        "bytes_read": budget.bytes, "steps": budget.steps,
                        "limitations": "heuristic layouts; recovered heap slots may be stale; no third-party signature downloads, external heap files, or speculative call-argument reconstruction"})
    if not found:
        raise ValueError("Requested Go PID was not found; no analysis was performed")

def run(self):
    return renderers.TreeGrid([("PID", int), ("Layer", str), ("Kind", str), ("Offset", _go_hints.Hex), ("Details", str)], self._generator())

def _validate_pcheader(self, address):
    data = _go_read(self, self.context.layers[self.layer_name], address, 24)
    if data[:4] not in self.GO_MAGICS or data[4:6] != b"\0\0" or data[6] not in (1, 2, 4) or data[7] != 8:
        return None
    nfunc, nfiles = _go_struct.unpack_from("<QQ", data, 8)
    if not 0 < nfunc <= 100000 or nfiles > 100000:
        return None
    info = self.GO_MAGICS[data[:4]]
    return {"address": address, "magic": data[:4], "version": info["version"],
            "has_textstart": info["has_textstart"], "minLC": data[6], "ptrSize": 8,
            "nfunc": nfunc, "nfiles": nfiles}

def _parse_elf_header(self, table, address):
    data = _go_read(self, self.context.layers[self.layer_name], address, 64)
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Go integration requires a little-endian ELF64 executable")
    fields = _go_struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if fields[1] != 62 or fields[0] not in (2, 3) or fields[8] != 56 or not 1 <= fields[9] <= 256:
        raise ValueError("Invalid or unsupported AMD64 ELF program header")
    return {"valid": True, "base_addr": address, "e_type": fields[0], "e_phoff": fields[4], "e_phnum": fields[9]}

def _parse_program_headers(self, table, header):
    result = []
    loads = []
    for index in _go_iter(self, range(header["e_phnum"])):
        data = _go_read(self, self.context.layers[self.layer_name], header["base_addr"] + header["e_phoff"] + index * 56, 56)
        kind, flags, fileoff, vaddr, paddr, filesz, memsz, align = _go_struct.unpack("<IIQQQQQQ", data)
        if kind != 1:
            continue
        if filesz > memsz or memsz > 268435456:
            raise ValueError("Invalid or oversized ELF segment")
        loads.append((index, kind, flags, fileoff, vaddr, memsz))
    bias = 0
    if header["e_type"] == 3:
        origins = [load for load in loads if load[3] == 0]
        if len(origins) != 1:
            raise ValueError("Cannot establish an unambiguous ELF load bias")
        bias = header["base_addr"] - origins[0][4]
    for index, kind, flags, fileoff, vaddr, memsz in _go_iter(self, loads):
        start = vaddr + bias
        if start < 0:
            raise ValueError("Invalid ELF load address")
        result.append({"index": index, "p_type": kind, "p_flags": flags,
                       "p_flags_str": ("R" if flags & 4 else "-") + ("W" if flags & 2 else "-") + ("X" if flags & 1 else "-"),
                       "runtime_vaddr": start, "runtime_end": start + memsz, "p_memsz": memsz})
    return result

def _parse_pe_header(self, address):
    layer = self.context.layers[self.layer_name]
    dos = _go_read(self, layer, address, 64)
    if dos[:2] != b"MZ":
        return {"valid": False}
    pe_offset = int.from_bytes(dos[60:64], "little")
    if not 64 <= pe_offset <= 1048576:
        raise ValueError("Invalid PE header offset")
    header = _go_read(self, layer, address + pe_offset, 24)
    if header[:4] != b"PE\0\0":
        return {"valid": False}
    machine, count = _go_struct.unpack_from("<HH", header, 4)
    optional_size = int.from_bytes(header[20:22], "little")
    if machine != 0x8664 or not 1 <= count <= 96 or not 112 <= optional_size <= 4096:
        raise ValueError("Go integration requires a bounded AMD64 PE32+ header")
    optional = _go_read(self, layer, address + pe_offset + 24, optional_size)
    if optional[:2] != b"\x0b\x02":
        raise ValueError("Go integration requires PE32+")
    return {"valid": True, "is_64bit": True, "base_addr": address, "num_sections": count,
            "image_base": int.from_bytes(optional[24:32], "little"),
            "entry_point": int.from_bytes(optional[16:20], "little"),
            "section_table_offset": address + pe_offset + 24 + optional_size}

def _read_varint(self, data):
    value = 0
    for index, byte in enumerate(data[:5]):
        _go_tick(self)
        value |= (byte & 127) << (index * 7)
        if not byte & 128:
            if value > 0xffffffff:
                raise ValueError("Go PC table varint overflow")
            return value, index + 1
    raise ValueError("Truncated or oversized Go PC table varint")

def _read_varint_zigzag(self, data):
    value, count = self._read_varint(data)
    return (value >> 1) ^ -(value & 1), count

def _pcvalue(self, pctab_data, target_pc, entry_pc, func_name=""):
    # Go runtime/symtab.go step(): zero is the terminator after the first pair;
    # every nonterminal pair includes both a value delta and a PC delta.
    if target_pc < entry_pc:
        raise ValueError("Target PC precedes its Go function")
    position, pc, value, first = 0, entry_pc, -1, True
    while position < len(pctab_data):
        _go_tick(self)
        encoded, count = self._read_varint(pctab_data[position:])
        position += count
        if encoded == 0 and not first:
            return None
        value += (encoded >> 1) ^ -(encoded & 1)
        delta, count = self._read_varint(pctab_data[position:])
        position += count
        if delta <= 0:
            raise ValueError("Nonadvancing Go PC table")
        pc += delta * self.pclntab.get("minLC", 1)
        if target_pc < pc:
            return value
        first = False
    raise ValueError("Unterminated Go PC table")

def _unwind_goroutine_stack(self, g_info, func_lookup, max_frames=256):
    if not 1 <= max_frames <= 256:
        raise ValueError("Go unwind requires a frame bound between 1 and 256")
    self._current_func_lookup = func_lookup
    pc, sp = g_info["sched_pc"], g_info["sched_sp"]
    if pc == 0 and sp == 0:
        return []  # The record contains no saved scheduled stack.
    stack_lo, stack_hi = g_info["stack_lo"], g_info["stack_hi"]
    frames = []
    seen = set()
    for depth in _go_iter(self, range(max_frames)):
        if (pc, sp) in seen:
            raise ValueError("Cyclic Go unwind; stack coverage incomplete")
        seen.add((pc, sp))
        if not stack_lo <= sp < stack_hi:
            raise ValueError("Go stack pointer outside stack; unwind incomplete")
        info = self._find_function_by_pc(pc, func_lookup)
        if not info:
            raise ValueError("Unresolved Go frame function; unwind incomplete")
        delta = self.calculate_frame_size(info, pc)
        if delta is None or delta < 0 or delta % 8:
            raise ValueError("Missing or invalid Go PCSP metadata; unwind incomplete")
        return_address = sp + delta
        if return_address + 8 > stack_hi:
            raise ValueError("Go return-PC slot outside stack; unwind incomplete")
        raw = _go_read(self, self.context.layers[self.layer_name], return_address, 8)
        return_pc = int.from_bytes(raw, "little")
        frames.append({"depth": depth, "function": info.get("name", ""), "pc": pc, "sp": sp,
                       "sp_delta": delta, "ret_pc_addr": return_address, "arg_base": return_address + 8,
                       "return_pc": return_pc, "func_info": info})
        if return_pc == 0:
            return frames
        if not self.moduledata["text"] <= return_pc < self.moduledata["etext"]:
            raise ValueError("Return PC outside known Go text; unwind incomplete")
        pc, sp = return_pc, return_address + 8
    raise _GoAbort("Go frame bound reached; unwind incomplete")

def _detect_mspan_profile(self, allspans_ptr, allspans_len):
    minor = self.go_version_tuple[1]
    if not 18 <= minor <= 25:
        raise ValueError("Unsupported Go heap profile version")
    expected = "go1.18-1.20" if minor <= 20 else ("go1.21-1.23" if minor <= 23 else "go1.24+")
    scores = {key: 0 for key in self.MSPAN_PROFILES}
    count = min(allspans_len, 20)
    if count < 3:
        raise ValueError("Too few Go spans to validate a heap profile")
    layer = self.context.layers[self.layer_name]
    pointers = _go_read(self, layer, allspans_ptr, count * 8)
    for index in _go_iter(self, range(count)):
        address = int.from_bytes(pointers[index * 8:index * 8 + 8], "little")
        if address < 0x1000:
            continue
        data = _go_read(self, layer, address, 128)
        for key, profile in self.MSPAN_PROFILES.items():
            if self._validate_span_with_profile(data, profile):
                scores[key] += 1
    best = max(scores.values())
    matches = [key for key in scores if scores[key] == best]
    if best < 3 or matches != [expected]:
        raise ValueError("Ambiguous or version-inconsistent Go heap profile; analysis incomplete")
    return expected
'''


class _BoundParsers(ast.NodeTransformer):
    def visit_Expr(self, node):
        # Print-only diagnostics can interpolate untrusted giant structures.  Drop
        # the expression rather than evaluating arguments and redirecting stdout.
        if isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Name) and call.func.id == "print":
                return ast.copy_location(ast.Pass(), node)
            if isinstance(call.func, ast.Attribute) and call.func.attr == "print_exc":
                return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read":
            return ast.copy_location(ast.Call(func=ast.Name(id="_go_read", ctx=ast.Load()),
                args=[ast.Name(id="self", ctx=ast.Load()), node.func.value, *node.args], keywords=node.keywords), node)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"append", "extend"}:
            return ast.copy_location(ast.Call(func=ast.Name(id="_go_" + node.func.attr, ctx=ast.Load()),
                args=[ast.Name(id="self", ctx=ast.Load()), node.func.value, *node.args], keywords=node.keywords), node)
        return node

    def visit_For(self, node):
        node = self.generic_visit(node)
        node.iter = ast.Call(func=ast.Name(id="_go_iter", ctx=ast.Load()),
                             args=[ast.Name(id="self", ctx=ast.Load()), node.iter], keywords=[])
        return node

    def visit_While(self, node):
        node = self.generic_visit(node)
        node.body.insert(0, ast.parse("_go_tick(self)").body[0])
        return node

    def visit_comprehension(self, node):
        node = self.generic_visit(node)
        node.iter = ast.Call(func=ast.Name(id="_go_iter", ctx=ast.Load()),
                             args=[ast.Name(id="self", ctx=ast.Load()), node.iter], keywords=[])
        return node

    def visit_ExceptHandler(self, node):
        node = self.generic_visit(node)
        if node.type is None:
            node.type = ast.Name(id="BaseException", ctx=ast.Load())
        node.name = node.name or "_go_caught_error"
        node.body[:0] = ast.parse(f"if isinstance({node.name}, _GoAbort):\n    raise\n_go_budget(self).parser_failures += 1").body
        return node

    def visit_If(self, node):
        node = self.generic_visit(node)
        # Reject the upstream heap profile default when detection failed.
        if ast.unparse(node.test) == "not self.mspan_profile" and any(
            isinstance(child, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "mspan_profile" for t in child.targets)
            for child in node.body
        ):
            node.body = ast.parse('raise ValueError("Go heap profile could not be validated; analysis incomplete")').body
        if ast.unparse(node.test) == "set_bits == 0 and allocCount > 0":
            node.body = ast.parse('raise _GoAbort("Go allocation bitmap contradicts allocation count; heap analysis incomplete")').body
        return node


def adapt_go(filename, source, target=None):
    """Adapt a verified pinned source. ``target`` may be linux/name.py or windows/name.py."""
    filename = PurePosixPath(filename).name
    if filename not in GO_COMMANDS:
        return source
    os_name = "windows" if (target and "windows/" in target) or "volatility3.plugins.windows import pslist" in source else "linux"
    tree = ast.parse(source)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == GO_COMMANDS[filename]]
    if len(classes) != 1:
        raise ValueError("Unexpected pinned Go plugin class")
    plugin = classes[0]
    replacements = ast.parse(_METHODS.replace("__OS__", os_name).replace("__MODE__", filename[:-3])).body
    for method in replacements:
        if method.name == "get_requirements":
            method.decorator_list = [ast.Name(id="classmethod", ctx=ast.Load())]
    replacement_names = {node.name for node in replacements}
    plugin.body = [node for node in plugin.body if not isinstance(node, ast.FunctionDef) or node.name not in replacement_names] + replacements

    # Keep only reachable parser methods.  This deliberately excludes upstream
    # file extraction, host-specific JSON, subprocess, OpenAI and download paths.
    methods = {node.name: node for node in plugin.body if isinstance(node, ast.FunctionDef)}
    needed = {"__init__", "get_requirements", "run"}
    while True:
        before = set(needed)
        for name in before:
            needed.update(node.attr for node in ast.walk(methods[name])
                          if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                          and node.value.id == "self" and node.attr in methods)
        if before == needed:
            break
    retained = []
    for node in plugin.body:
        if isinstance(node, ast.FunctionDef):
            if node.name not in needed:
                continue
            if node.name not in replacement_names:
                if os_name == "linux" and node.name == "_find_mheap_global" and filename.startswith("go_strings"):
                    # Both upstream Linux string variants name this parameter
                    # sections but reference the nonexistent global segments.
                    node.args.args[1].arg = "segments"
                node = _BoundParsers().visit(node)
                if node.name != "__init__" and not any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(node)):
                    node.decorator_list.append(ast.Name(id="_go_call_guard", ctx=ast.Load()))
        retained.append(node)
    plugin.body = [ast.Expr(value=ast.Constant(value=(
        "Experimental bounded offline Go runtime candidate recovery. Requires one PID and AMD64 symbols; "
        "Go 1.16–1.25 layouts are candidates, not validated OS/build support. Structured process-virtual "
        "offsets; no host files, external signature downloads or speculative call-argument reconstruction."
    )))] + retained
    imports = ast.parse("""import logging
from typing import List, Tuple, Generator, Optional, Dict, Set
from volatility3.framework import interfaces, exceptions, constants, renderers, objects
from volatility3.framework.configuration import requirements
from volatility3.plugins.__OS__ import pslist
""".replace("__OS__", os_name)).body
    body = imports + ast.parse(_SUPPORT).body + ast.parse("vollog = logging.getLogger(__name__)").body + [plugin]
    adapted = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
    # Static fail-closed check: the retained source has no host-file API, process
    # execution or socket import.  Dependencies can only be framework and stdlib.
    for node in ast.walk(adapted):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"open", "exec", "eval", "compile", "__import__", "print"}:
            raise ValueError("Unsafe retained Go call: " + node.func.id)
    notice = (
        "# Adapted by volatility-mcp; source: HalaAli198/Go-Memory-Forensics\n"
        "# Upstream pin: 68c4d93edcdea9f584ad855cf963eb803b4ca328; Apache-2.0\n"
        "# Original source and license attribution are recorded in the versioned addon inventory.\n"
        "# Changes: bounded offline orchestration, structured output, parser guards and format corrections.\n"
    )
    return notice + ast.unparse(adapted) + "\n"
