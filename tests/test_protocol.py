"""Real stdio MCP exchanges against a harmless fake analyzer, independent of reporting."""
import asyncio
import json
import os
from pathlib import Path
import sys
import unittest
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from volatility_mcp.cli import decode_result
import test_backend


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.root / 'config.json'
        self.config.write_text(json.dumps(self.fixture.config.to_dict()))
        self.transport = StdioServerParameters(command=sys.executable,
            args=['-m','volatility_mcp','serve','--config',str(self.config)])

    async def test_stdio_tools_both_protocol_modes_without_reporting(self):
        original_run = None
        for mode in ('auto','legacy'):
            async with Client(self.transport,mode=mode,read_timeout_seconds=15) as client:
                tools = await client.list_tools()
                self.assertEqual({t.name for t in tools.tools}, {'list_memory_images','get_image_info',
                    'list_plugins','run_plugin','read_output','case_history','inspect_artifact','query_output','get_evidence','get_coverage'})
                images = decode_result(await client.call_tool('list_memory_images',{}))
                self.assertEqual(images['count'],1)
                plugins = decode_result(await client.call_tool('list_plugins',{'query':'windows.pslist.PsList'}))
                self.assertTrue(plugins['plugins'][0]['options'])
                run = decode_result(await client.call_tool('run_plugin',dict(image='example.raw',
                    plugin='windows.pslist.PsList',arguments=['--pid','42'])))
                self.assertEqual(run['status'],'success')
                self.assertEqual(run['reused'], original_run is not None)
                if original_run:
                    self.assertEqual(run['run_id'], original_run)
                original_run = run['run_id']
                self.assertEqual(run['hashing']['groups']['image_after']['files'], 1)
                self.assertEqual(len(run['commands']),1)
                output = decode_result(await client.call_tool('read_output',dict(path=run['json_artifact'],limit=32)))
                self.assertTrue(output['truncated'])
                history = decode_result(await client.call_tool('case_history',dict(image='example.raw')))
                self.assertGreaterEqual(history['count'],1)
                invalid = await client.call_tool('run_plugin',dict(image='../escape.raw',plugin='windows.pslist.PsList'))
                self.assertTrue(invalid.is_error)
                self.assertFalse(list(self.fixture.root.rglob('report.md')))
                self.assertFalse(list(self.fixture.root.rglob('case-manifest.json')))
        self.assertEqual(len((self.fixture.root / 'analysis-count.jsonl').read_text().splitlines()), 1)

    async def test_protocol_cancellation_finalizes_execution_record(self):
        self.fixture.image.write_text('timeout')
        async with Client(self.transport,mode='legacy',read_timeout_seconds=15) as client:
            task = asyncio.create_task(client.call_tool('run_plugin',dict(image='example.raw',plugin='windows.pslist.PsList')))
            counter = self.fixture.root / 'analysis-count.jsonl'
            for _ in range(250):
                if counter.exists(): break
                await asyncio.sleep(0.02)
            self.assertTrue(counter.exists(), 'Fixture analysis must start before testing in-flight cancellation')
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            manifest = {}
            for _ in range(30):
                await asyncio.sleep(0.1)
                paths = list(self.fixture.backend.outputs.glob('*/runs/*/manifest.json'))
                if paths:
                    manifest = json.loads(paths[0].read_text())
                    if manifest['status'] != 'running':
                        break
            self.assertEqual(manifest['status'],'cancelled')
            self.assertTrue(manifest['integrity_verified'])
            self.assertTrue(manifest['completed_at'])

if __name__ == '__main__': unittest.main()
