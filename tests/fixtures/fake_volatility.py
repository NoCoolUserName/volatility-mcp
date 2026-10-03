"""Harmless CLI simulator for tests only. It never analyzes a real memory image."""
import json
from pathlib import Path
import sys
import time

option = lambda flag, kind='str', nargs=None, action='store', is_path=False: dict(
    flag=flag, dest=flag[2:].replace('-', '_'), required=False, nargs=nargs,
    type=kind, action=action, choices=None, help='SYNTHETIC fixture option', is_path=is_path)
options = [option('--pid', 'int', '*'), option('--dump', action='store_true', nargs=0),
           option('--input', is_path=True), option('--text')]
plugins = {name: {'description': 'SYNTHETIC ONLY', 'options': options,
                 'origin': 'installed_volatility', 'plugin_version': [0, 0, 0]}
           for name in ('windows.pslist.PsList', 'windows.info.Info', 'banners.Banners',
                        'windows.registry.printkey.PrintKey')}
plugins['windows.registry.printkey.PrintKey']['options'] = [option('--key')]
if any(arg.endswith('catalog.py') for arg in sys.argv):
    print(json.dumps({'version': 'SYNTHETIC', 'architecture': 'arm64',
                      'import_failures': [], 'plugins': plugins}))
    raise SystemExit(0)
image = Path(sys.argv[sys.argv.index('-f') + 1])
files = Path(sys.argv[sys.argv.index('-o') + 1])
mode = image.read_text().strip()
(files / 'invocation.txt').write_text('SYNTHETIC invocation\n')
if mode == 'timeout':
    print('SYNTHETIC partial stdout', flush=True)
    time.sleep(20)
elif mode == 'error':
    print('Unsatisfied requirement plugins.Info.kernel.symbol_table_name', file=sys.stderr)
    raise SystemExit(1)
elif mode == 'badjson':
    print('[{"incomplete":')
elif mode == 'mutate':
    image.write_text('SYNTHETIC changed by test fixture')
    print('[]')
elif mode == 'huge':
    print(json.dumps([{'SYNTHETIC': True, 'PID': i, 'Name': 'x' * 1000} for i in range(1000)]))
else:
    if '--dump' in sys.argv:
        (files / 'synthetic-dump.txt').write_text('Harmless synthetic derived bytes\n')
    print(json.dumps([{'SYNTHETIC': True, 'PID': 42, 'ImageFileName': 'example.exe'}]))
