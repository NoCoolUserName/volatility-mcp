import sys
import unittest
from importlib.resources import files
from volatility_mcp import api

class PublicAPITests(unittest.TestCase):
    def test_core_contract_and_no_application_dependency(self):
        self.assertEqual(api.API_VERSION, 1)
        for backend in (api.VolatilityBackend, api.CaseBackend):
            for method in ('submit_jobs', 'get_job', 'list_jobs', 'cancel_job', 'shutdown_jobs'):
                self.assertTrue(callable(getattr(backend, method)))
        self.assertIn('Executive summary', api.report_spec())
        self.assertFalse(any(n.startswith('volatility_workbench') for n in sys.modules))
        self.assertFalse(files('volatility_mcp').joinpath('ui/static').is_dir())
