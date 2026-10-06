"""Decorative assets use saved identity only; originals and sealed reports stay intact."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from volatility_mcp.ui.coins import ensure_coin, populate, install


class CoinTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()
        self.image={'id':'E001','path':'/nonexistent/evidence.raw','sha256':'a'*64}

    def test_stable_distinct_coins_without_evidence_access(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No subprocess permitted')):
            a=ensure_coin(self.root/'case',self.image)
            b=ensure_coin(self.root/'case',{**self.image,'id':'E002','sha256':'b'*64})
            original=(self.root/'case'/a['path']).read_bytes()
            reopened=ensure_coin(self.root/'other-case',{**self.image,'display_name':'Changed label'})
        self.assertNotEqual(a['asset_sha256'],b['asset_sha256'])
        self.assertEqual(a['asset_sha256'],reopened['asset_sha256'])
        self.assertEqual(original,(self.root/'other-case'/reopened['path']).read_bytes())
        self.assertEqual(reopened['label'],'evidence.raw')

    def test_original_png_reused_exactly_and_not_overwritten(self):
        data=b'\x89PNG\r\n\x1a\nSYNTHETIC-TEST-BYTES'
        install(self.root/'coin-library','a'*64,data,'png','Synthetic','Test provenance')
        coin=ensure_coin(self.root/'case',self.image)
        self.assertEqual((self.root/'case'/coin['path']).read_bytes(),data)
        self.assertEqual(coin['asset_sha256'],hashlib.sha256(data).hexdigest())
        with self.assertRaises(ValueError):
            install(self.root/'coin-library','a'*64,b'changed','png','Other','Test')

    def test_missing_hash_and_artwork_failure_are_optional(self):
        self.assertEqual(populate(self.root/'case',[{'id':'E001'}]),[])
        with patch('volatility_mcp.ui.coins.render_coin',side_effect=OSError('Disk unavailable')):
            coins=populate(self.root/'case',[self.image])
        self.assertEqual(coins[0]['error'],'Disk unavailable')

    def test_label_escaped_and_symlink_escape_rejected(self):
        coin=ensure_coin(self.root/'case',{**self.image,'display_name':'<script> & unknown'})
        data=(self.root/'case'/coin['path']).read_text()
        self.assertNotIn('<script>',data);self.assertIn('&lt;SCRIPT&gt;',data)
        outside=self.root/'outside';outside.mkdir()
        (self.root/'coin-library'/('b'*64)).symlink_to(outside,target_is_directory=True)
        coins=populate(self.root/'case',[{**self.image,'sha256':'b'*64}])
        self.assertIn('error',coins[0])
