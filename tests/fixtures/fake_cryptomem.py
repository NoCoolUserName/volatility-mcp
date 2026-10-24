"""Harmless backend contract simulator; does NOT load CryptoMem or analyze memory.

The image contains only a test mode. Address rows are fixed synthetic output for
testing core artifact/provenance handling, not address-detection test vectors.
"""
import json
import os
from pathlib import Path
import sys
import time


def option(flag, kind='str', required=False, choices=None, nargs=None):
    return dict(flag=flag, dest=flag[2:].replace('-', '_'), required=required,
                nargs=nargs, type=kind, action='store', choices=choices,
                help='SYNTHETIC backend contract', is_path=False)


plugin = 'windows.cryptomem.CryptoMem'
root = Path(sys.argv[0]).parent
source = root / 'installed-cryptomem.py'
plugins = {
    'windows.pslist.PsList': {
        'description': 'SYNTHETIC PsList baseline', 'plugin_version': [0, 0, 0],
        'origin': 'installed_volatility', 'options': [option('--pid', 'int', nargs='*')]},
    plugin: {
        'description': 'SYNTHETIC CryptoMem backend contract', 'plugin_version': [0, 2, 0],
        'origin': 'installed_volatility', 'source_file': str(source), 'target_os': 'windows',
        'manual_only': True,
        'source': {'kind': 'third_party', 'label': 'NoCoolUserName/volatility3-cryptomem',
                   'url': 'https://github.com/NoCoolUserName/volatility3-cryptomem',
                   'basis': 'SYNTHETIC fixture metadata, not verified installation'},
        'options': [option('--pid', 'int', required=True),
                    option('--currency', choices=['all', 'btc', 'eth', 'xrp', 'xmr']),
                    option('--max-scan-bytes', 'int'), option('--max-results', 'int')]},
}
linux = 'linux.cryptomem.CryptoMem'
plugins[linux] = {**plugins[plugin], 'target_os': 'linux'}
if any(arg.endswith('catalog.py') for arg in sys.argv):
    if '--xpnet' in sys.argv:
        plugins['xpnet.XpNetScan'] = {
            'description': 'SYNTHETIC XP addon', 'plugin_version': [0, 0, 0],
            'origin': 'local_compatibility', 'options': []}
    if (root / 'missing-dependency').exists():
        del plugins[plugin]
        del plugins[linux]
        failures = ['volatility3.plugins.windows.cryptomem', 'volatility3.plugins.linux.cryptomem']
    else:
        failures = []
    print(json.dumps({'version': 'SYNTHETIC', 'architecture': 'SYNTHETIC',
                      'import_failures': failures, 'plugins': plugins,
                      'runtime_files': [str(source)]}))
    raise SystemExit(0)

image = Path(sys.argv[sys.argv.index('-f') + 1])
files = Path(sys.argv[sys.argv.index('-o') + 1])
with (root / 'analysis-count.jsonl').open('a') as counter:
    counter.write(json.dumps({'argv': sys.argv[1:]}) + '\n')
(root / 'analysis-started').write_text(str(os.getpid()))
(files / 'invocation.txt').write_text('SYNTHETIC execution; no memory analyzed\n')
mode = image.read_text().strip()
if mode == 'timeout':
    print('SYNTHETIC partial output', flush=True)
    time.sleep(20)
elif mode == 'corrupt':
    print('Unsatisfied requirement plugins.CryptoMem.kernel.layer_name', file=sys.stderr)
    raise SystemExit(1)
elif mode == 'symbols':
    print('Unsatisfied requirement plugins.CryptoMem.kernel.symbol_table_name', file=sys.stderr)
    raise SystemExit(1)
elif mode == 'incomplete':
    print('ScanIncomplete: Unreadable process memory; scan stopped', file=sys.stderr)
    raise SystemExit(1)
elif mode == 'dependency':
    print("ModuleNotFoundError: No module named 'Crypto.Hash.keccak'", file=sys.stderr)
    raise SystemExit(1)
elif mode == 'unsupported':
    print('SYNTHETIC unsupported memory layer; no scan completed', file=sys.stderr)
    raise SystemExit(1)
elif mode == 'badjson':
    print('[{"PID":')
elif mode == 'mutate':
    image.write_text('SYNTHETIC unexpected source change')
    print('[]')
elif plugin not in sys.argv and linux not in sys.argv:
    print(json.dumps([{'PID': 42, 'ImageFileName': 'synthetic.exe'}]))
elif mode == 'empty':
    print('[]')
else:
    address = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
    print(json.dumps([
        {'PID': 42, 'Process': 'synthetic.exe', 'Layer': 'SYNTHETIC process layer',
         'Offset': offset, 'ByteLength': len(address), 'Kind': 'address',
         'Currency': 'BTC', 'Value': address, 'Canonical': address,
         'Format': 'Base58Check-P2PKH', 'Validation': 'checksum_valid',
         'Reason': 'SYNTHETIC fixed row, not a detector result', 'Encoding': 'ascii',
         'Context': '', 'Network': 'bitcoin-mainnet-compatible', 'Amount': ''}
        for offset in (4096, 8192)]))
