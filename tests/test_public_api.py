import sys
import unittest
from importlib.resources import files
from volatility_mcp import api

class PublicAPITests(unittest.TestCase):
    def test_core_contract_and_no_application_dependency(self):
        self.assertEqual(api.API_VERSION, 1)
        self.assertIn('Executive summary', api.report_spec())
        self.assertFalse(any(n.startswith('volatility_workbench') for n in sys.modules))
        self.assertFalse(files('volatility_mcp').joinpath('ui/static').is_dir())
