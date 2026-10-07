"""Administrative relocation preserves saved identities, never general symlinks."""
import dataclasses
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from volatility_mcp.backend import VolatilityBackend
from volatility_mcp.config import Config
from volatility_mcp.relocation import ENV, logical_path, mapping
from volatility_mcp.ui.storage import safe_file, private_dir
import test_saved_evidence


class RelocationTests(unittest.TestCase):
    def setUp(self):
        self.saved=test_saved_evidence.SavedTests();self.saved.setUp()
        self.addCleanup(self.saved.doCleanups)
        self.old=self.saved.fixture.root
        self.new=self.old.with_name(self.old.name+'-moved')
        self.config=self.saved.backend.config.to_dict()
        self.reference=self.saved.ref('/0/PID')
        self.original={p.relative_to(self.old):p.read_bytes() for p in self.old.rglob('manifest.json')}
        self.old.rename(self.new)
        self.old.symlink_to(self.new,target_is_directory=True)
        def restore():
            self.old.unlink()
            self.new.rename(self.old)
        self.addCleanup(restore)
        self.mapfile=self.new/'relocation.local.json'
        self.mapfile.write_text(json.dumps({'logical_root':str(self.old),'physical_root':str(self.new)}))
        self.env=patch.dict(os.environ,{ENV:str(self.mapfile)})
        self.env.start();self.addCleanup(self.env.stop)

    def test_saved_queries_history_references_and_physical_inputs(self):
        with patch('subprocess.Popen',side_effect=AssertionError('No analysis')) as process:
            backend=VolatilityBackend(Config.from_dict(self.config))
            result=backend.query_output(str(self.new/'evidence/example.raw'),'saved','json/stdout.json')
            self.assertEqual(result['matching_count'],4)
            self.assertEqual(result['rows'][0]['reference']['source'],self.reference['source'])
            self.assertEqual(backend.get_evidence(self.reference,{'type':'integer','value':4})['observable_validation'],'matched')
            self.assertEqual(backend.case_history('example.raw')['total'],1)
            path=backend.case_directory(backend.resolve_input('example.raw'))/'runs/saved/json/stdout.json'
            self.assertTrue(backend.read_output(str(path))['content'])
            self.assertEqual(safe_file(self.old,'evidence/example.raw'),self.old/'evidence/example.raw')
            self.assertEqual(private_dir(self.new/'new-output'),self.old/'new-output')
            self.assertEqual(self.original,{p.relative_to(self.old):p.read_bytes() for p in self.old.rglob('manifest.json')})
        process.assert_not_called()

    def test_inner_aliases_traversal_and_tampered_mapping_rejected(self):
        backend=VolatilityBackend(Config.from_dict(self.config))
        (self.old/'evidence/escape.raw').symlink_to(self.old/'evidence/example.raw')
        for path in ['escape.raw','../evidence/example.raw']:
            with self.subTest(path=path),self.assertRaises(ValueError):backend.resolve_input(path)
        with self.assertRaises(ValueError):safe_file(self.old,'evidence/escape.raw')
        self.old.unlink();self.old.symlink_to(self.new/'evidence',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'exact registered'):backend.resolve_input('example.raw')
        self.old.unlink();self.old.symlink_to(self.new,target_is_directory=True)
        for record in [dict(logical_root=str(self.old),physical_root=str(self.old)),
                       dict(logical_root='relative',physical_root=str(self.new))]:
            self.mapfile.write_text(json.dumps(record))
            with self.assertRaises(ValueError):mapping()

    def test_opt_in_required_and_physical_config_preserves_namespace(self):
        physical={k:v.replace(str(self.old),str(self.new)) if isinstance(v,str) else v for k,v in self.config.items()}
        self.assertEqual(Config.from_dict(physical).output_root,Path(self.config['output_root']))
        with patch.dict(os.environ,{ENV:''}):
            with self.assertRaises(ValueError):safe_file(self.old,'evidence/example.raw')
