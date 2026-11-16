"""Real stdio MCP exchanges against a harmless fake analyzer, independent of reporting."""
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


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = test_backend.BackendTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.root / 'config.json'
        self.config.write_text(json.dumps(self.fixture.config.to_dict()))
        self.transport = StdioServerParameters(command=sys.executable,
            env={'PYTHONPATH': os.environ['PYTHONPATH']} if 'PYTHONPATH' in os.environ else None,
            args=['-m','volatility_mcp','serve','--config',str(self.config)])

    async def test_catalog_refresh_over_mcp_without_analysis(self):
        async with Client(self.transport, mode='auto', read_timeout_seconds=15) as client:
            result = decode_result(await client.call_tool('list_plugins', {'refresh': True}))
            self.assertEqual(result['count'], len(result['plugins']))
            self.assertTrue(result['discovered_at'])
            self.assertIn('source', result['plugins'][0])
        self.assertFalse((self.fixture.root / 'analysis-count.jsonl').exists())

    async def test_stdio_tools_both_protocol_modes_without_reporting(self):
        original_run = None
        for mode in ('auto','legacy'):
            async with Client(self.transport,mode=mode,read_timeout_seconds=15) as client:
                tools = await client.list_tools()
                self.assertEqual({t.name for t in tools.tools}, {'list_memory_images','get_image_info',
                    'list_plugins','run_plugin','read_output','case_history','inspect_artifact','query_output','get_evidence','get_coverage','submit_jobs','get_job','list_jobs','cancel_job'})
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

    async def wait_job(self, client, job_id):
        for _ in range(250):
            job = decode_result(await client.call_tool('get_job', {'job_id': job_id}))
            if job['state'] not in ('queued', 'running'):
                return job
            await asyncio.sleep(0.02)
        self.fail('Synthetic background job did not finish')

    async def test_explicit_jobs_results_and_incremental_followup_both_modes(self):
        for mode in ('auto', 'legacy'):
            async with Client(self.transport, mode=mode, read_timeout_seconds=15) as client:
                empty = decode_result(await client.call_tool('list_jobs', {}))
                old_ids = {job['job_id'] for job in empty['jobs']}
                submitted = decode_result(await client.call_tool('submit_jobs', {'jobs': [
                    {'image': 'example.raw', 'plugin': 'windows.pslist.PsList', 'arguments': ['--pid', '42']},
                    {'image': 'example.raw', 'plugin': 'windows.info.Info'}], 'order': 'slowest-first'}))
                self.assertEqual(len(submitted['jobs']), 2)
                for queued in submitted['jobs']:
                    self.assertNotIn(queued['job_id'], old_ids)
                    final = await self.wait_job(client, queued['job_id'])
                    self.assertEqual(final['state'], 'success')
                    self.assertEqual(final['result']['status'], 'success')
                    self.assertTrue(Path(final['result']['manifest_path']).is_file())
                    self.assertTrue(final['completed_at'])
                # A client chooses a later follow-up only after observing earlier results.
                followup = decode_result(await client.call_tool('submit_jobs', {'jobs': [
                    {'image': 'example.raw', 'plugin': 'windows.pslist.PsList', 'arguments': ['--pid', '42']}]}))
                final = await self.wait_job(client, followup['jobs'][0]['job_id'])
                self.assertTrue(final['result']['reused'])
                listed = decode_result(await client.call_tool('list_jobs', {}))
                page = decode_result(await client.call_tool('list_jobs', {'limit': 1}))
                self.assertEqual(page['returned_count'], 1)
                self.assertEqual(page['next_offset'], 1)
                self.assertEqual(page['count'], len(listed['jobs']))
                self.assertTrue({j['job_id'] for j in submitted['jobs']}.issubset(
                    {j['job_id'] for j in listed['jobs']}))
                invalid = await client.call_tool('submit_jobs', {'jobs': [
                    {'image': 'example.raw', 'plugin': 'windows.pslist.PsList'},
                    {'image': '../escape.raw', 'plugin': 'windows.pslist.PsList'}]})
                self.assertTrue(invalid.is_error)
                after = decode_result(await client.call_tool('list_jobs', {}))
                self.assertEqual(len(after['jobs']), len(listed['jobs']))
        self.assertEqual(len((self.fixture.root / 'analysis-count.jsonl').read_text().splitlines()), 2)
        self.assertFalse(list(self.fixture.root.rglob('report.md')))

    async def test_background_queued_and_running_job_cancellation(self):
        self.fixture.image.write_text('timeout')
        self.config.write_text(json.dumps(replace(self.fixture.config,
            command_timeout=10, max_concurrent_runs=1).to_dict()))
        async with Client(self.transport, mode='legacy', read_timeout_seconds=15) as client:
            submitted = decode_result(await client.call_tool('submit_jobs', {'jobs': [
                {'image': 'example.raw', 'plugin': 'windows.pslist.PsList', 'arguments': ['--pid', '1']},
                {'image': 'example.raw', 'plugin': 'windows.pslist.PsList', 'arguments': ['--pid', '2']}]}))
            first, second = [j['job_id'] for j in submitted['jobs']]
            counter = self.fixture.root / 'analysis-count.jsonl'
            for _ in range(250):
                if counter.exists(): break
                await asyncio.sleep(0.02)
            self.assertTrue(counter.exists())
            await client.call_tool('cancel_job', {'job_id': second})
            await client.call_tool('cancel_job', {'job_id': first})
            self.assertEqual((await self.wait_job(client, second))['state'], 'cancelled')
            final = await self.wait_job(client, first)
            self.assertEqual(final['state'], 'cancelled')
            self.assertTrue(final['result']['integrity_verified'])
            manifest = json.loads(Path(final['result']['manifest_path']).read_text())
            self.assertEqual(manifest['status'], 'cancelled')
            self.assertTrue(manifest['completed_at'])
            self.assertIn('partial stdout', Path(manifest['commands'][0]['stdout_path']).read_text())
            # Cancellation of a completed job does not replace its terminal result.
            again = decode_result(await client.call_tool('cancel_job', {'job_id': first}))
            self.assertEqual(again['state'], 'cancelled')
        self.assertEqual(len(counter.read_text().splitlines()), 1)

    async def test_scoped_background_jobs_reject_other_images_before_admission(self):
        other = self.fixture.evidence / 'other.raw'
        other.write_text('normal')
        scope = self.fixture.root / 'scope.json'
        scope.write_text(json.dumps({'config': self.fixture.config.to_dict(),
            'images': [str(self.fixture.image)]}))
        transport = StdioServerParameters(command=sys.executable,
            env={'PYTHONPATH': os.environ['PYTHONPATH']} if 'PYTHONPATH' in os.environ else None,
            args=['-m', 'volatility_mcp.scoped', str(scope)])
        outside = self.fixture.backend.submit_jobs([
            {'image': 'other.raw', 'plugin': 'windows.pslist.PsList'}])['jobs'][0]['job_id']
        self.addCleanup(self.fixture.backend.shutdown_jobs)
        async with Client(transport, mode='legacy', read_timeout_seconds=15) as client:
            before = decode_result(await client.call_tool('list_jobs', {}))
            self.assertEqual(before['jobs'], [])
            for method in ('get_job', 'cancel_job'):
                self.assertTrue((await client.call_tool(method, {'job_id': outside})).is_error)
            invalid = await client.call_tool('submit_jobs', {'jobs': [
                {'image': 'example.raw', 'plugin': 'windows.pslist.PsList'},
                {'image': 'other.raw', 'plugin': 'windows.pslist.PsList'}]})
            self.assertTrue(invalid.is_error)
            self.assertEqual(decode_result(await client.call_tool('list_jobs', {}))['jobs'], [])
            selected = decode_result(await client.call_tool('submit_jobs', {'jobs': [
                {'image': 'example.raw', 'plugin': 'windows.pslist.PsList'}]}))
            final = await self.wait_job(client, selected['jobs'][0]['job_id'])
            self.assertEqual(final['state'], 'success')
            self.assertEqual(len(decode_result(await client.call_tool('list_jobs', {}))['jobs']), 1)
            self.fixture.image.unlink()
            saved = decode_result(await client.call_tool('get_job', {'job_id': final['job_id']}))
            self.assertEqual(saved['state'], 'success')
            self.assertEqual(len(decode_result(await client.call_tool('list_jobs', {}))['jobs']), 1)
            self.assertEqual(decode_result(await client.call_tool('cancel_job',
                {'job_id': final['job_id']}))['state'], 'success')
            self.assertTrue((await client.call_tool('run_plugin',
                {'image': 'example.raw', 'plugin': 'windows.pslist.PsList'})).is_error)
        # A new case-scoped process must recover saved jobs even after source removal.
        async with Client(transport, mode='legacy', read_timeout_seconds=15) as client:
            self.assertEqual(decode_result(await client.call_tool('get_job',
                {'job_id': final['job_id']}))['state'], 'success')
            self.assertEqual(decode_result(await client.call_tool('cancel_job',
                {'job_id': final['job_id']}))['state'], 'success')
            self.assertEqual(len(decode_result(await client.call_tool('list_jobs', {}))['jobs']), 1)
            self.assertTrue((await client.call_tool('get_job', {'job_id': outside})).is_error)
            self.assertTrue((await client.call_tool('run_plugin',
                {'image': 'example.raw', 'plugin': 'windows.pslist.PsList'})).is_error)

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
