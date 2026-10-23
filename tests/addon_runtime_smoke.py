"""Optional installed-analyzer checks using synthetic bytes only, never memory images.

Run with the configured Volatility Python. --plugin-root is for a temporary
developer staging tree; it is not an MCP argument or runtime plugin-dir feature.
"""
import argparse
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--plugin-root')
args = parser.parse_args()
from volatility3 import framework, plugins
from volatility3.framework import constants, contexts
if args.plugin_root:
    constants.PLUGINS_PATH[:0] = [args.plugin_root]
    plugins.__path__ = constants.PLUGINS_PATH
failures = framework.import_files(plugins, True)
assert not failures, failures
profile = json.loads((Path(__file__).resolve().parents[1] / 'src/volatility_mcp/resources/addons.json').read_text())
expected = {name for source in profile['sources'] for name in source['plugins']}
runtime_sources = {'NoCoolUserName/volatility3-cryptomem', 'lorelyai/volatility3-bitlocker', 'HalaAli198/Go-Memory-Forensics',
                   'HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis'}
legacy = {name for source in profile['sources'] if source['repository'] not in runtime_sources
          for name in source['plugins']}
available = framework.list_plugins()
assert expected <= available.keys(), expected - available.keys()
for name in expected:
    for requirement in available[name].get_requirements():
        if type(requirement).__name__ in {'PluginRequirement', 'VersionRequirement'}:
            assert not requirement.unsatisfied(contexts.Context(), 'synthetic'), (name, requirement.name)

with patch('subprocess.Popen', side_effect=AssertionError('Subprocess forbidden')), \
     patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')):
    from volatility3.framework.interfaces.configuration import HierarchicalDict
    from volatility3.plugins.windows import filescan, pslist
    from volatility3.plugins.linux import pslist as linux_pslist
    # Legacy run-wrapper contracts. Runtime addons have required address/layout
    # checks and their own installed fixture suites; every import is checked above.
    for name in legacy:
        cls = available[name]
        obj = object.__new__(cls)
        context = SimpleNamespace(config=HierarchicalDict(), modules={'kernel': SimpleNamespace(layer_name='layer', symbol_table_name='symbols')})
        context.config['synthetic.kernel'] = 'kernel'
        context.config['synthetic.pid'] = [123] if any(r.name == 'pid' and type(r).__name__ == 'ListRequirement' for r in cls.get_requirements()) else 123
        if name == 'linux.openssh_sessionkeys.SSHKeys':
            context.config['synthetic.address'] = 4096
        if name == 'windows.pte_resolve.PteResolve':
            context.config['synthetic.vaddr'] = 4096
        obj._context = context; obj._config_path = 'synthetic'
        with patch.object(filescan.FileScan, 'scan_files', autospec=True, return_value=iter(())), \
             patch.object(pslist.PsList, 'list_processes', autospec=True, return_value=iter(())), \
             patch.object(linux_pslist.PsList, 'list_tasks', autospec=True, return_value=iter(())), \
             patch.object(cls, '_generator', return_value=iter(())):
            obj.run()  # This verifies argument contracts, not the plugin's forensic algorithm.

    prefetch = available['windows.prefetch.Prefetch']
    data = bytearray(256); struct.pack_into('<I', data, 0, 17); data[4:8] = b'SCCA'
    struct.pack_into('<I', data, 12, 256); data[16:36] = 'EXAMPLE.EXE'.encode('utf-16le')
    struct.pack_into('<I', data, 0x4c, 0x1234); struct.pack_into('<I', data, 0x90, 7)
    rows = list(prefetch.parse_prefetch(bytes(data)))
    assert rows[0][0] == 'EXAMPLE.EXE' and rows[0][-1] == 7
    for bad in (b'bad data', struct.pack('<I', 17) + b'SCCA'):
        try: list(prefetch.parse_prefetch(bad))
        except (ValueError, UnicodeError): pass
        else: raise AssertionError('Malformed prefetch became an empty success')
    anydesk = available['windows.anydesk.AnyDesk']
    rows = list(anydesk.parse_trace_file(b'info 2026-01-01 12:34:56.123 front synthetic - test message\n', 'synthetic.trace'))
    assert rows[0][-1] == 'test message'
    keepass = object.__new__(available['windows.keepass.KeePass'])
    assert keepass.format_match({1:['x'], 2:['y']}) == 'xy'
    evtx = available['windows.evtxlog.evtxlog']
    try: list(evtx.parse_evtx_file(b'invalid' * 600, 'synthetic.evtx', 'synthetic'))
    except Exception: pass
    else: raise AssertionError('Malformed EVTX became an empty success')
    browser = object.__new__(available['windows.browserhistoryextractor.BrowserHistoryExtractor'])
    browser._context = SimpleNamespace(config=HierarchicalDict()); browser._config_path = 'synthetic'
    browser._context.config['synthetic.full-urls'] = True
    with tempfile.TemporaryDirectory() as temp:
        db = Path(temp) / 'History'
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER,last_visit_time INTEGER,hidden INTEGER)')
            connection.execute('INSERT INTO urls VALUES(1,?,?,?,?,?,0)', ('https://example.invalid/synthetic','Synthetic',2,1,13380163200000000))
        original = db.read_bytes()
        rows = browser.parse_browser_history(str(db), 'chrome', 'Chrome')
        assert rows[0][3] == 'https://example.invalid/synthetic' and rows[0][-2].endswith('UTC')
        assert db.read_bytes() == original and not list(Path(temp).glob('*-wal'))
        malformed = Path(temp) / 'malformed'; malformed.write_bytes(b'not sqlite')
        try: browser.parse_browser_history(str(malformed), 'chrome', 'Chrome')
        except ValueError: pass
        else: raise AssertionError('Malformed database became an empty success')
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout): browser.print_summary('all', [], 0, [], {})
    assert not stdout.getvalue()
    try: browser.find_output_directory()
    except ValueError: pass
    else: raise AssertionError('Host directory fallback accepted')
print('PASS: profile import/requirement/run-wrapper contracts; synthetic Prefetch, AnyDesk, KeePass, EVTX and SQLite checks; zero analysis subprocesses/network. PTE/ImageMalfind algorithms not evaluated here; first-batch fixtures are separate.')
