"""Synthetic CLI entry for the INSTALLED detector, never a captured kernel.

Used only by cryptomem_extended_mcp_smoke.py. Catalog discovery still uses the
real installed Volatility API; this entry supplies generated process mappings.
"""
from pathlib import Path
import runpy
import sys
import time

from volatility3.cli import CommandLine
from volatility3.cli.text_renderer import JsonRenderer

helpers = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'addon_cryptomem_smoke.py'))
image = Path(sys.argv[sys.argv.index('-f')+1])
outputs = Path(sys.argv[sys.argv.index('-o')+1])
plugin_name = next(arg for arg in sys.argv if arg.endswith('.cryptomem.CryptoMem'))
os_name = plugin_name.split('.')[0]
plugin_arguments = sys.argv[sys.argv.index(plugin_name)+1:]
config = {}
for index, flag in enumerate(plugin_arguments):
    if not flag.startswith('--'):
        continue
    name = flag[2:].replace('-','_')
    config[name] = True if name in ('detect_mnemonics','detect_private_keys','detect_txids','extract_secrets') else int(plugin_arguments[index+1]) if name in ('pid','max_results','max_scan_bytes') else plugin_arguments[index+1]
data = image.read_bytes()
with helpers['fixture'](data,os_name,**config) as (plugin,_):
    cli = CommandLine.__new__(CommandLine); cli.output_dir=str(outputs)
    plugin.set_open_method(cli.file_handler_class_factory())
    JsonRenderer().render(plugin.run())
    sys.stdout.flush()
(outputs / '.synthetic-ready').write_text('Synthetic installed plugin finished rendering\n')
if data.startswith(b'SYNTHETIC TIMEOUT\n'):
    time.sleep(30)
