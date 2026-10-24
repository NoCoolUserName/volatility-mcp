"""Release gate failure paths; no publication, credentials or live API needed."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

SPEC = importlib.util.spec_from_file_location(
    'release_gate', Path(__file__).resolve().parents[1] / 'scripts/check_release.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
SHA = 'a' * 40


class ReleaseGateTests(unittest.TestCase):
    def test_versions_and_manifest_must_match(self):
        manifest = {'core_version': '0.1.1', 'source_revision': SHA}
        self.assertEqual(gate.validate_version('0.1.1', '0.1.1', SHA, manifest), 'v0.1.1')
        for version, runtime, revision, bundle in [
            ('0.1.1rc1', '0.1.1rc1', SHA, None),
            ('0.1.1', '0.1.0', SHA, None),
            ('0.1.1', '0.1.1', SHA[:8], None),
            ('0.1.1', '0.1.1', SHA, {**manifest, 'core_version': '0.1.0'}),
            ('0.1.1', '0.1.1', SHA, {**manifest, 'source_revision': 'b' * 40}),
        ]:
            with self.subTest(version=version, runtime=runtime, bundle=bundle):
                with self.assertRaises(ValueError):
                    gate.validate_version(version, runtime, revision, bundle)

    def test_missing_tag_allowed_only_before_creation(self):
        with patch.object(gate, 'api_get', return_value=None):
            gate.check_tag('v0.1.1', SHA)
            with self.assertRaisesRegex(ValueError, 'missing'):
                gate.check_tag('v0.1.1', SHA, require_tag=True)

    def test_lightweight_and_annotated_tags(self):
        commit = {'object': {'type': 'commit', 'sha': SHA}}
        with patch.object(gate, 'api_get', return_value=commit):
            gate.check_tag('v0.1.1', SHA, require_tag=True)
            with self.assertRaisesRegex(ValueError, 'different'):
                gate.check_tag('v0.1.1', 'b' * 40)
        annotated = {'object': {'type': 'tag', 'sha': 'c' * 40}}
        with patch.object(gate, 'api_get', side_effect=[annotated, commit]) as api:
            gate.check_tag('v0.1.1', SHA, require_tag=True)
            self.assertEqual(api.call_args.args, (f'git/tags/{"c" * 40}',))
        with patch.object(gate, 'api_get', side_effect=[annotated, commit]):
            with self.assertRaisesRegex(ValueError, 'different'):
                gate.check_tag('v0.1.1', 'b' * 40)

    def test_noncommit_and_cyclic_tags_fail(self):
        for kind in ('tree', 'blob', 'tag'):
            with self.subTest(kind=kind):
                with patch.object(gate, 'api_get', return_value={
                    'object': {'type': kind, 'sha': SHA}}):
                    with self.assertRaises(ValueError):
                        gate.check_tag('v0.1.1', SHA)

    def test_ci_requires_latest_success_for_every_workflow(self):
        success = {'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
                   'status': 'completed', 'conclusion': 'success'}
        with patch.object(gate, 'api_get', return_value={'workflow_runs': [success]}) as api:
            gate.check_ci(SHA)
            self.assertEqual(api.call_count, len(gate.WORKFLOWS))

    def test_ci_rejects_missing_pending_failed_and_unrelated_runs(self):
        success = {'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
                   'status': 'completed', 'conclusion': 'success'}
        failures = [[]]
        for key, values in {
            'head_sha': ['b' * 40], 'head_branch': ['other'], 'event': ['pull_request'],
            'status': ['queued', 'in_progress'],
            'conclusion': ['failure', 'cancelled', 'skipped', 'neutral', None],
        }.items():
            failures.extend([[{**success, key: value}] for value in values])
        # A successful older run must never hide a failed latest run.
        failures.append([{**success, 'conclusion': 'failure'}, success])
        for runs in failures:
            for failed_workflow in range(len(gate.WORKFLOWS)):
                results = [{'workflow_runs': [deepcopy(success)]}
                           for _ in gate.WORKFLOWS]
                results[failed_workflow] = {'workflow_runs': runs}
                with self.subTest(runs=runs, workflow=failed_workflow):
                    with patch.object(gate, 'api_get', side_effect=results):
                        with self.assertRaises(ValueError):
                            gate.check_ci(SHA)

    def test_api_only_treats_tag_404_as_absent(self):
        with patch.dict(gate.os.environ, {'GITHUB_REPOSITORY': 'example/repo',
                                         'GH_TOKEN': 'test-placeholder'}):
            for path, code in [('git/ref/tags/v0.1.1', 404),
                               ('git/ref/tags/v0.1.1', 403),
                               ('actions/workflows/ci.yml/runs', 404)]:
                error = HTTPError('https://api.github.com/', code, 'test', {}, None)
                with self.subTest(path=path, code=code):
                    with patch.object(gate, 'urlopen', side_effect=error):
                        if path.startswith('git/ref/tags/') and code == 404:
                            self.assertIsNone(gate.api_get(path))
                        else:
                            with self.assertRaises(HTTPError):
                                gate.api_get(path)
