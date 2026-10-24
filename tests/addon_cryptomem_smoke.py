"""Installed CryptoMem with synthetic process/VADs and real Volatility layers.

Run: /path/to/analyzer/bin/python tests/addon_cryptomem_smoke.py -v
No standalone checkout import or real-memory analysis is performed. This checks
the installed release and core row consumption, not Windows acquisition support.
"""
import contextlib
import io
import json
from pathlib import Path
import platform
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch


# Resolve trusted host metadata before forbidding any network/process action.
HOST_ARCHITECTURE = platform.architecture()
DENY = contextlib.ExitStack()
DENY.enter_context(patch('platform.architecture', return_value=HOST_ARCHITECTURE))
for target in ('socket.socket.connect', 'socket.create_connection', 'socket.getaddrinfo',
               'urllib.request.urlopen', 'subprocess.Popen'):
    DENY.enter_context(patch(target, side_effect=AssertionError('Offline fixture boundary: ' + target)))

from volatility3 import framework
from volatility3.cli.text_renderer import JsonRenderer
from volatility3.framework import contexts, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.plugins.windows import cryptomem, pslist
from volatility3.plugins.linux import cryptomem as linux_cryptomem
from volatility3.plugins.linux import pslist as linux_pslist

# Only core row/schema helpers come from this checkout; detector code must be
# imported normally from the analyzer installation above.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from volatility_mcp.catalog import option_spec
from volatility_mcp.json_rows import iter_rows


BTC = b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
# Generated from an arbitrary bytes(range(64)) payload, not a real wallet.
XMR = '41d7ke5VQnR2BDNSgrTE9j3X8QQ5Bnbbs4s3SMTX7y416CxUJqrTLW97YsWGEBnhxH8tnYDcX85QRAEhaAzrTSrZ89rbBUS'


class CapturedFile(interfaces.plugins.FileHandlerInterface):
    outputs = {}

    def __init__(self, filename):
        super().__init__(filename)
        self.buffer = io.BytesIO()

    def write(self, data):
        return self.buffer.write(data)

    def flush(self):
        pass

    def close(self):
        if not self.closed:
            self.outputs[self.preferred_filename] = self.buffer.getvalue()
        super().close()


@contextlib.contextmanager
def fixture(data, os_name='windows', **config):
    context = contexts.Context()
    layer = BufferDataLayer(context, 'layers.process', 'synthetic-process', data)
    context.layers.add_layer(layer)
    module = context.module('synthetic', layer.name, 0)
    context.config['fixture.kernel'] = module.name
    context.config['fixture.pid'] = 42
    context.config['fixture.currency'] = 'btc'
    for name, value in config.items():
        context.config['fixture.' + name] = value
    vad = NS(get_start=lambda: 0, get_end=lambda: len(data) - 1)
    process = NS(UniqueProcessId=42,
        ImageFileName=NS(vol=NS(count=16), cast=lambda *args, **kwargs: 'synthetic.exe'),
        add_process_layer=lambda: layer.name,
        get_vad_root=lambda: NS(traverse=lambda: iter([vad])))
    CapturedFile.outputs = {}

    def processes(passed_context, kernel_module_name):
        assert passed_context is context
        assert kernel_module_name == module.name
        return iter([process])

    with contextlib.ExitStack() as stack:
        if os_name == 'linux':
            process.pid = process.tgid = 42
            process.is_kernel_thread = False
            process.comm = 'synthetic.exe'
            process.mm = NS(get_vma_iter=lambda: iter([NS(vm_start=0,vm_end=len(data))]))
            def tasks(ctx, kernel, *, include_threads):
                assert include_threads is False
                return processes(ctx, kernel)
            stack.enter_context(patch.object(linux_pslist.PsList, 'list_tasks', side_effect=tasks))
            stack.enter_context(patch.object(linux_cryptomem.utility, 'array_to_string', return_value=process.comm))
            plugin_type = linux_cryptomem.CryptoMem
        else:
            stack.enter_context(patch.object(pslist.PsList, 'list_processes', side_effect=processes))
            plugin_type = cryptomem.CryptoMem
        plugin = plugin_type(context, 'fixture')
        plugin.set_open_method(CapturedFile)
        yield plugin, layer


def render(plugin):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        JsonRenderer().render(plugin.run())
    return json.loads(output.getvalue())


def summary():
    return json.loads(CapturedFile.outputs['cryptomem-scan-summary.json'])


class InstalledCryptoMemTests(unittest.TestCase):
    os_name = 'windows'
    module = cryptomem
    pslist_module = pslist
    region = 'VAD'

    def fixture(self, data, **config):
        return fixture(data, os_name=self.os_name, **config)

    def test_registration_native_pslist_and_core_requirement_schema(self):
        registered = framework.list_plugins()
        self.assertIs(registered[self.os_name + '.cryptomem.CryptoMem'], self.module.CryptoMem)
        self.assertIs(registered[self.os_name + '.pslist.PsList'], self.pslist_module.PsList)
        reqs = {req.name: req for req in self.module.CryptoMem.get_requirements()}
        self.assertIsInstance(reqs['kernel'], requirements.ModuleRequirement)
        self.assertIs(reqs['pslist']._component, self.pslist_module.PsList)
        pid = option_spec(reqs['pid'])
        self.assertTrue(pid['required'])
        self.assertEqual(pid['type'], 'int')
        self.assertIsNone(pid['nargs'])
        self.assertEqual(option_spec(reqs['currency'])['choices'], ['all', 'btc', 'eth', 'xrp', 'xmr'])
        self.assertEqual({req.name for req in reqs.values() if option_spec(req) is not None},
                         {'pid', 'currency', 'max_scan_bytes', 'max_results'})

    def test_real_renderer_artifacts_offsets_and_core_row_consumption(self):
        data = b'prefix ' + BTC + b' suffix'
        with self.fixture(data) as (plugin, layer):
            original = layer.read(0, len(data))
            rows = render(plugin)
            self.assertEqual(layer.read(0, len(data)), original)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['PID'], 42)
        self.assertEqual(rows[0]['Process'], 'synthetic.exe')
        self.assertEqual(rows[0]['Offset'], 7)
        self.assertEqual(rows[0]['Value'], BTC.decode())
        self.assertEqual(rows[0]['Validation'], 'checksum_valid')
        exported = [json.loads(line) for line in
                    CapturedFile.outputs['cryptomem-findings.jsonl'].splitlines()]
        self.assertEqual(exported[0]['offset'], 7)
        self.assertEqual(exported[0]['value'], rows[0]['Value'])
        self.assertEqual(summary()['completion_state'], 'complete')
        self.assertEqual(summary()['bytes_evaluated'], len(data))
        self.assertEqual(summary()['findings'], 1)
        with tempfile.TemporaryDirectory(prefix='cryptomem-row-smoke-') as temporary:
            output = Path(temporary) / 'stdout.json'
            output.write_text(json.dumps(rows))
            self.assertEqual(list(iter_rows(output)), rows)

    def test_monero_filter_renderer_and_artifacts(self):
        for currency in ('xmr', 'all'):
            for encoding in ('ascii', 'utf-16le'):
                with self.subTest(currency=currency, encoding=encoding):
                    data = b'prefix ' + XMR.encode(encoding) + b' suffix'
                    with self.fixture(data, currency=currency) as (plugin, layer):
                        rows = render(plugin)
                        self.assertEqual(layer.read(0, len(data)), data)
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]['Currency'], 'XMR')
                    self.assertEqual(rows[0]['Offset'], 7)
                    self.assertEqual(rows[0]['Validation'], 'checksum_valid')
                    self.assertEqual(rows[0]['Format'], 'Monero-standard')
                    exported = json.loads(CapturedFile.outputs['cryptomem-findings.jsonl'].splitlines()[0])
                    self.assertEqual(exported['value'], XMR)
                    self.assertEqual(summary()['completion_state'], 'complete')

    def test_no_match_and_invalid_parameters(self):
        with self.fixture(b'ordinary synthetic memory without addresses') as (plugin, _):
            self.assertEqual(render(plugin), [])
        self.assertEqual(summary()['completion_state'], 'complete')
        self.assertIn(f'Selected process {self.region}s only', summary()['scope'])
        for config in ({'pid': 0}, {'pid': [42]}, {'currency': 'doge'},
                       {'max_scan_bytes': 0}, {'max_results': 10001}):
            with self.subTest(config=config), self.assertRaises(
                    (ValueError, exceptions.PluginRequirementException)):
                with self.fixture(b'synthetic memory', **config):
                    self.fail('Invalid plugin configuration was accepted')

    def test_short_reads_and_limits_leave_incomplete_artifacts(self):
        with self.fixture(b' ' + BTC + b' ') as (plugin, layer):
            with patch.object(layer, 'read', return_value=b''):
                with self.assertRaisesRegex(cryptomem.ScanIncomplete, 'Short memory read'):
                    render(plugin)
        self.assertEqual(summary()['completion_state'], 'incomplete')
        self.assertEqual(summary()['bytes_evaluated'], 0)
        with self.fixture(b' ' + BTC + b' ' + BTC + b' ', max_results=1) as (plugin, _):
            with self.assertRaisesRegex(cryptomem.ScanIncomplete, 'Result limit'):
                render(plugin)
        self.assertEqual(summary()['completion_state'], 'incomplete')
        self.assertEqual(summary()['findings'], 1)

    def test_missing_keccak_fails_selected_eth_before_empty_success(self):
        missing = {'Crypto': None, 'Crypto.Hash': None, 'Crypto.Hash.keccak': None}
        with patch.dict(sys.modules, missing):
            with self.fixture(b'ordinary memory', currency='eth') as (plugin, _):
                with self.assertRaisesRegex(ImportError, 'pycryptodome'):
                    render(plugin)
            self.assertEqual(summary()['completion_state'], 'incomplete')
            with self.fixture(b' ' + BTC + b' ', currency='btc') as (plugin, _):
                self.assertEqual(len(render(plugin)), 1)
        self.assertEqual(summary()['completion_state'], 'complete')


class InstalledLinuxCryptoMemTests(InstalledCryptoMemTests):
    os_name = 'linux'
    module = linux_cryptomem
    pslist_module = linux_pslist
    region = 'VMA'


if __name__ == '__main__':
    unittest.main()
