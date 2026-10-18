"""Small, versioned adaptations of pinned upstream addons; never analyze evidence."""
import ast
import textwrap


REVISION = 4


def replace_method(source, name, replacement):
    nodes = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise ValueError(f'Expected exactly one {name} method')
    node = nodes[0]
    lines = source.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [textwrap.indent(textwrap.dedent(replacement).strip(), '    ') + '\n']
    return ''.join(lines)


def adapt(filename, source):
    """Only known pinned files enter here; installed hashes are checked separately."""
    if filename in {'prefetch.py', 'anydesk.py', 'evtxlog.py'}:
        source = source.replace('filescan.FileScan.scan_files(self.context, kernel.layer_name, kernel.symbol_table_name)',
                                'filescan.FileScan.scan_files(self.context, self.config["kernel"])')
        source = source.replace('kernel.layer_name,\n                                                kernel.symbol_table_name)', 'self.config["kernel"])')
        source = source.replace('version=(0, 0, 0)', 'version=filescan.FileScan.version')
        variable = 'prefetch_raw' if filename == 'prefetch.py' else 'file_raw'
        old = f'{variable} += layer.read(mem_offset, datasize, pad=True)\n'
        lines = source.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.lstrip() == old:
                indent = line[:len(line) - len(line.lstrip())]
                code = [
                    'if file_offset < 0 or file_offset + datasize > 512 * 1024 * 1024:',
                    '    raise ValueError("Reconstruction exceeds 536.87 MB bound")',
                    'segment = layer.read(mem_offset, datasize, pad=True)',
                    f'if file_offset > len({variable}):',
                    '    vollog.warning("Sparse cached-file reconstruction; completeness unknown")',
                    f'{variable} = {variable}.ljust(file_offset + len(segment), b"\\0")',
                    f'{variable} = {variable}[:file_offset] + segment + {variable}[file_offset + len(segment):]',
                ]
                lines[index] = ''.join(indent + statement + '\n' for statement in code)
        source = ''.join(lines).replace(f'bytes_read += len({variable})', 'bytes_read += len(segment)')
    if filename in {'ptenum.py', 'ptemalfind.py', 'simple_pteenum.py', 'imgmalfind.py', 'apisearch.py', 'pe_parser.py'}:
        source = source.replace('architectures = ["Intel32", "Intel64"]', 'architectures = ["Intel64"]')
    if filename == 'simple_pteenum.py':
        source = source.replace('architectures = ["Intel64"]),\n                   requirements.SymbolTableRequirement(name = "nt_symbols",\n                                                       description = "Windows kernel symbols")]\nelse:',
                                'architectures = ["Intel64"])]\nelse:')
    if filename == 'keepass.py':
        source = source.replace('layer_name=kernel.layer_name,\n                    symbol_table=kernel.symbol_table_name,',
                                'kernel_module_name=self.config["kernel"],')
        source = source.replace('version=(2, 0, 0)', 'version=pslist.PsList.version')
        source = source.replace('file_handle.preferred_filename,', '"process memory",')
    if filename == 'prefetch.py':
        source = source.replace('print(i + offset)', 'vollog.debug("Invalid compressed offset: %s", i + offset)')
        source = source.replace('decompressed_size = int.from_bytes(stream.read(4), "little")',
                                'decompressed_size = int.from_bytes(stream.read(4), "little")\n'
                                '            if not 0 < decompressed_size <= 64 * 1024 * 1024:\n'
                                '                raise ValueError("Prefetch decompression exceeds 67.11 MB bound")')
        source = source.replace('vollog.info("Wrong signature, should be SCCA")\n            return',
                                'raise ValueError("Invalid Prefetch signature; not an empty result")')
        source = source.replace('if file_version == WinXpOrWin2K3:',
                                'if file_version not in (17, 23, 26, 30):\n'
                                '            raise ValueError("Unsupported Prefetch format")\n'
                                '        if len(prefetch_file) < {17: 148, 23: 156, 26: 212, 30: 212}[file_version]:\n'
                                '            raise ValueError("Truncated Prefetch header")\n'
                                '        if file_version == WinXpOrWin2K3:')
    if filename == 'evtxlog.py':
        source = source.replace('fh = evtx.FileHeader(file_raw, 0x0)',
                                'fh = evtx.FileHeader(file_raw, 0x0)\n'
                                '            if not fh.check_magic():\n'
                                '                raise ValueError("Invalid EVTX header; not an empty result")')
        source = source.replace('"test", record.xml()', '"not recovered", record.xml()')
        source = source.replace('file_name, "full")', 'file_name, "reconstructed; completeness unknown")')
        source = source.replace('file_name, "broken")', 'file_name, "partial; read failure")')
        source = source.replace('except Evtx.BinaryParser.OverrunBufferException:\n                pass',
                                'except Evtx.BinaryParser.OverrunBufferException as exc:\n'
                                '                raise ValueError("Truncated EVTX; parsing incomplete") from exc')
    if filename == 'browserhistoryextractor.py':
        source = source.replace('from datetime import datetime, timedelta', 'from datetime import datetime, timedelta, timezone\nfrom pathlib import Path')
        source = source.replace('datetime.fromtimestamp(timestamp_seconds)', 'datetime.fromtimestamp(timestamp_seconds, timezone.utc)')
        source = source.replace('dt.strftime("%Y-%m-%d %H:%M:%S")', 'dt.strftime("%Y-%m-%d %H:%M:%S UTC")')
        source = source.replace('con = sqlite3.connect(db_path)',
                                'con = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)')
        source = source.replace('vollog.debug(f"Database error in {db_path}: {e}")\n            return []',
                                'if "con" in locals(): con.close()\n'
                                '            raise ValueError("Recovered browser database is unparseable; not an empty result") from e')
        source = source.replace('full_paths_list = [os.path.join(output_dir, name) for name in file_names_list]',
                                'full_paths_list = []\n'
                                '        root = Path(output_dir).resolve()\n'
                                '        for name in file_names_list:\n'
                                '            candidate = root / name\n'
                                '            if Path(name).name != name or candidate.is_symlink() or not candidate.is_file() or candidate.resolve().parent != root:\n'
                                '                raise ValueError("Extracted browser file escapes this run output directory")\n'
                                '            full_paths_list.append(str(candidate))')
        source = replace_method(source, 'print_summary', '''
            def print_summary(self, target_browser, processes, total_entries, files, browser_stats):
                vollog.info("Browser extraction: browser=%s processes=%d files=%d rows=%d; completeness not established",
                            target_browser, len(processes), len(files), total_entries)
        ''')
        source = replace_method(source, 'find_output_directory', '''
            def find_output_directory(self):
                for frame_info in inspect.stack():
                    instance = frame_info.frame.f_locals.get('self')
                    if isinstance(instance, CommandLine) and instance.output_dir:
                        return str(Path(instance.output_dir).resolve(strict=True))
                raise ValueError("No framework-managed output directory; refusing host-file fallback")
        ''')
    from .addon_batch import adapt_batch
    source = adapt_batch(filename, source, replace_method)
    from .addon_sensitive import adapt_sensitive
    source = adapt_sensitive(filename, source, replace_method)
    ast.parse(source)
    return source
