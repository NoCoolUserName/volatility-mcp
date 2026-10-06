"""Timestamp formatting, portable identifiers, and legacy UI compatibility."""
from pathlib import Path
import shutil
import subprocess
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from volatility_mcp.timestamps import utc_now, timestamped_id
from volatility_mcp.reporting import _timestamp


class TimestampTests(unittest.TestCase):
    def test_new_metadata_and_collision_safe_portable_names(self):
        with patch('volatility_mcp.timestamps.datetime') as clock:
            clock.now.return_value=datetime(2026,10,6,2,52,39,891767,tzinfo=timezone.utc)
            self.assertEqual(utc_now(),'2026-10-06 02:52:39Z')
            first,second=timestamped_id(),timestamped_id()
        self.assertRegex(first,r'^2026-10-06_02-52-39Z-[a-f0-9]{12}$')
        self.assertNotEqual(first,second)
        _timestamp('2026-10-06 02:52:39Z','new')
        _timestamp('2026-10-06T02:52:39.891767+00:00','legacy')

    @unittest.skipUnless(shutil.which('node'),'Node required for browser formatter check')
    def test_browser_legacy_labels_and_elapsed_time(self):
        source=(Path(__file__).resolve().parents[1]/'src/volatility_mcp/ui/static/app.js').read_text()
        source=source.split('let state,',1)[0]
        checks=r'''
const assert = require('node:assert/strict');
for (const value of [
  '20261006T025239.891767Z',
  '2026-10-06T025239-891767+0000',
  '2026-10-06T02:52:39.891767+00:00',
  '2026-10-06T02:52:39.891Z',
  '2026-10-06_02-52-39Z',
  '2026-10-06 02:52:39Z',
]) {
  assert.equal(readableTime(value), '2026-10-06 02:52:39Z');
  assert.equal(readableTime('runs/'+value+'-abc/output.json'),
    'runs/2026-10-06 02:52:39Z-abc/output.json');
}
assert.equal(timestampMillis('2026-10-06 02:52:39Z'), Date.parse('2026-10-06T02:52:39Z'));
assert.equal(timestampMillis('2026-10-06T02:52:39.891767+00:00'), Date.parse('2026-10-06T02:52:39.891Z'));
assert.equal(readableTime('unchanged evidence'), 'unchanged evidence');
assert.equal(readableTime('2026-10-06T02:52:39+02:00'), '2026-10-06T02:52:39+02:00');
'''
        subprocess.run(['node','-e',source+checks],check=True,capture_output=True,text=True)
