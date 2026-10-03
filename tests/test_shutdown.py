"""An actual stdio shutdown must reap a harmless analyzer and seal its metadata."""
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import sys
import unittest

from mcp import Client
from mcp.client.stdio import StdioServerParameters
import test_backend


class ShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_sigterm_reaps_analysis_and_finalizes_manifest(self):
        fixture = test_backend.BackendTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.image.write_text('timeout')
        marker = "mode = image.read_text().strip()"
        source = fixture.fake.read_text().replace(marker,
            "import os\n(files / 'pids.json').write_text(json.dumps("
            "{'child': os.getpid(), 'server': os.getppid()}))\n" + marker)
        fixture.fake.write_text(source)
        fixture.fake.chmod(0o700)
        config = fixture.root / 'config.json'
        config.write_text(json.dumps(replace(fixture.config, command_timeout=10).to_dict()))
        transport = StdioServerParameters(command=sys.executable,
            args=['-m', 'volatility_mcp', 'serve', '--config', str(config)])
        child = None
        try:
            async with Client(transport, mode='legacy', read_timeout_seconds=15) as client:
                request = asyncio.create_task(client.call_tool('run_plugin',
                    {'image': 'example.raw', 'plugin': 'windows.pslist.PsList'}))
                for _ in range(100):
                    paths = list(fixture.backend.outputs.glob('*/runs/*/json/files/pids.json'))
                    if paths:
                        pids = json.loads(paths[0].read_text())
                        child = pids['child']
                        break
                    await asyncio.sleep(0.05)
                self.assertIsNotNone(child, 'The harmless analysis process never started')
                os.kill(pids['server'], signal.SIGTERM)
                try:
                    await asyncio.wait_for(request, timeout=5)
                except Exception:
                    # The connection may close before the cancelled tool reply;
                    # the persisted record is the authoritative shutdown result.
                    pass
                for _ in range(40):
                    try:
                        os.kill(pids['server'], 0)
                    except ProcessLookupError:
                        break
                    await asyncio.sleep(0.05)
                else:
                    self.fail('SIGTERM did not stop the server before client cleanup')
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
            path = next(fixture.backend.outputs.glob('*/runs/*/manifest.json'))
            record = json.loads(path.read_text())
            self.assertEqual(record['status'], 'cancelled')
            self.assertTrue(record['integrity_verified'])
            self.assertTrue(record['completed_at'])
            self.assertEqual(record['commands'][0]['status'], 'cancelled')
            self.assertIn('partial stdout', Path(record['commands'][0]['stdout_path']).read_text())
        finally:
            if child:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == '__main__':
    unittest.main()
