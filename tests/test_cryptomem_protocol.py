"""Real stdio MCP exchanges; analyzer output is a harmless CLI simulation."""
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import unittest

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.cli import decode_result
import test_backend


class CryptoMemProtocolTests(unittest.IsolatedAsyncioTestCase):
    PLUGIN = "linux.cryptomem.CryptoMem"
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        simulator = Path(__file__).parent / 'fixtures/fake_cryptomem.py'
        self.fixture.fake.write_text('#!' + sys.executable + '\n' + simulator.read_text())
        (self.fixture.root / 'installed-cryptomem.py').write_text('# SYNTHETIC plugin identity\n')

    def transport(self, *, xp=False, timeout=2):
        config = replace(self.fixture.config, enable_xpnet=xp, command_timeout=timeout)
        path = self.fixture.root / 'protocol.json'
        path.write_text(json.dumps(config.to_dict()))
        return StdioServerParameters(command=sys.executable,
            args=['-m', 'volatility_mcp', 'serve', '--config', str(path)])

    async def test_all_commands_discovery_invocation_and_failures(self):
        for xp in (False, True):
            async with Client(self.transport(xp=xp), mode='legacy', read_timeout_seconds=20) as client:
                self.assertEqual(len((await client.list_tools()).tools), 10)
                catalog = decode_result(await client.call_tool('list_plugins', {'query':'cryptomem'}))
                self.assertEqual({p['name'] for p in catalog['plugins']},
                                 {'linux.cryptomem.CryptoMem','windows.cryptomem.CryptoMem','mac.cryptomem.CryptoMem'})
                self.assertTrue(all(p['manual_only'] for p in catalog['plugins']))
                for os_name in ('windows', 'linux', 'mac'):
                    plugin = os_name + '.cryptomem.CryptoMem'
                    args = {'image':'example.raw','plugin':plugin,'arguments':['--pid','42']}
                    for mode, status in (('positive','success'), ('empty','success'),
                                         ('symbols','error'), ('incomplete','error')):
                        self.fixture.image.write_text(mode)
                        run = decode_result(await client.call_tool('run_plugin', args))
                        self.assertEqual(run['status'],status)
                        self.assertTrue(run['integrity_verified'])
                        self.assertIn('--offline',run['commands'][0]['argv'])
                        if status == 'success':
                            self.assertEqual(run['row_count'], 0 if mode == 'empty' else 2)
                        else:
                            self.assertFalse(run['reuse_eligible'])
                    invalid = await client.call_tool('run_plugin', {**args,'arguments':['--pid','42','--currency','doge']})
                    self.assertTrue(invalid.is_error)

    async def test_timeout_retains_partial_output_and_reaps_child(self):
        self.fixture.image.write_text('timeout')
        async with Client(self.transport(timeout=1), mode='auto', read_timeout_seconds=20) as client:
            run = decode_result(await client.call_tool('run_plugin', {'image':'example.raw',
                'plugin':self.PLUGIN,'arguments':['--pid','42']}))
            self.assertEqual(run['status'],'timeout')
            self.assertFalse(run['reuse_eligible'])
            self.assertTrue(run['integrity_verified'])
            self.assertIn('SYNTHETIC partial output',Path(run['commands'][0]['stdout_path']).read_text())
            self.assert_child_gone()

    async def test_secret_extraction_output_readers_remain_masked(self):
        for mode in ('auto','legacy'):
            async with Client(self.transport(timeout=10),mode=mode,read_timeout_seconds=20) as client:
                for os_name in ('windows','linux','mac'):
                    run=decode_result(await client.call_tool('run_plugin',{'image':'example.raw',
                        'plugin':os_name+'.cryptomem.CryptoMem',
                        'arguments':['--pid','42','--detect-mnemonics','--extract-secrets']}))
                    self.assertEqual(run['status'],'success')
                    self.assertNotIn('abandon '*11+'about',json.dumps(run))
                    path=Path(run['commands'][0]['files_directory'])/'cryptomem-secrets-v1.jsonl'
                    operations=[('read_output',{'path':str(path),'offset':5,'limit':10}),
                        ('query_output',{'image':'example.raw','run_id':run['run_id'],'artifact':'json/files/'+path.name}),
                        ('get_evidence',{'reference':{'source':{'image':'example.raw','run_id':run['run_id'],'artifact':'json/files/'+path.name}}}),
                        ('inspect_artifact',{'image':'example.raw','run_id':run['run_id'],'artifact':'json/files/'+path.name,'operation':'strings'})]
                    for tool,args in operations:
                        result=await client.call_tool(tool,args)
                        self.assertTrue(result.is_error,(tool,result))
                        self.assertIn('local-only',str(result))
                        self.assertNotIn('abandon '*11+'about',str(result))

    async def test_secret_cancellation_preserves_private_output(self):
        self.fixture.image.write_text('timeout')
        async with Client(self.transport(timeout=10),mode='auto',read_timeout_seconds=20) as client:
            task=asyncio.create_task(client.call_tool('run_plugin',{'image':'example.raw',
                'plugin':self.PLUGIN,'arguments':['--pid','42','--detect-mnemonics','--extract-secrets']}))
            for _ in range(250):
                if (self.fixture.root/'analysis-started').exists():
                    break
                await asyncio.sleep(0.02)
            self.assertTrue((self.fixture.root/'analysis-started').exists())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            for _ in range(50):
                await asyncio.sleep(0.1)
                manifests=list(self.fixture.backend.outputs.glob('*/runs/*/manifest.json'))
                if manifests:
                    record=json.loads(manifests[0].read_text())
                    if record['status']=='cancelled':
                        break
            self.assertEqual(record['status'],'cancelled')
            self.assert_child_gone()
            files=Path(record['commands'][0]['files_directory'])
            for name in ('tmp_synthetic.vol3','cryptomem-secrets-v1.jsonl'):
                result=await client.call_tool('read_output',{'path':str(files/name)})
                self.assertTrue(result.is_error)

    def assert_child_gone(self):
        pid = int((self.fixture.root / 'analysis-started').read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    async def test_cancellation_finalizes_manifest_in_both_protocol_modes(self):
        for mode in ('legacy', 'auto'):
            (self.fixture.root / 'analysis-started').unlink(missing_ok=True)
            self.fixture.image.write_text('timeout')
            previous = set(self.fixture.backend.outputs.glob('*/runs/*/manifest.json'))
            async with Client(self.transport(timeout=10), mode=mode, read_timeout_seconds=20) as client:
                task = asyncio.create_task(client.call_tool('run_plugin', {'image':'example.raw',
                    'plugin':self.PLUGIN,'arguments':['--pid','42']}))
                for _ in range(250):
                    if (self.fixture.root / 'analysis-started').exists():
                        break
                    await asyncio.sleep(0.02)
                self.assertTrue((self.fixture.root / 'analysis-started').exists())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                manifest = {}
                for _ in range(50):
                    await asyncio.sleep(0.1)
                    paths = set(self.fixture.backend.outputs.glob('*/runs/*/manifest.json')) - previous
                    if paths:
                        manifest = json.loads(next(iter(paths)).read_text())
                        if manifest['status'] != 'running':
                            break
                self.assertEqual(manifest['status'],'cancelled')
                self.assertTrue(manifest['integrity_verified'])
                self.assertTrue(manifest['completed_at'])
                self.assertFalse(manifest['reuse_eligible'])
                self.assertIn('SYNTHETIC partial output',Path(manifest['commands'][0]['stdout_path']).read_text())
                self.assert_child_gone()


class MacCryptoMemProtocolTests(CryptoMemProtocolTests):
    PLUGIN = 'mac.cryptomem.CryptoMem'


if __name__ == '__main__':
    unittest.main()
