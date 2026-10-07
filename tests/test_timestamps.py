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
