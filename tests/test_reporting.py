"""Checks of the optional reporting contract, including deliberately invalid bundles."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from volatility_mcp.reporting import check_bundle


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-report-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(__file__).resolve().parents[1]
        source = root / 'examples/synthetic-case'
        self.bundle = Path(self.tmp.name).resolve() / 'case'
        shutil.copytree(source,self.bundle)

    def modify_manifest(self, change):
        path = self.bundle / 'case-manifest.json'
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def test_synthetic_contract_valid(self):
        result = check_bundle(self.bundle)
        self.assertEqual(result['status'],'valid')
        self.assertTrue(result['synthetic'])
        self.assertIn('analyst review', result['scope'])

    def test_changed_artifact_invalid(self):
        artifact = next((self.bundle/'artifacts').iterdir())
        artifact.write_text('SYNTHETIC modified output')
        with self.assertRaisesRegex(ValueError,'hash/size mismatch'): check_bundle(self.bundle)

    def test_unsafe_artifact_path_and_symlink(self):
        self.modify_manifest(lambda m:m['artifacts'][0].update(path='../outside.txt'))
        with self.assertRaisesRegex(ValueError,'Unsafe bundle path'): check_bundle(self.bundle)

    def test_unknown_finding_reference(self):
        self.modify_manifest(lambda m:m['findings'][0]['evidence_refs'][0].update(artifact_id='absent'))
        with self.assertRaisesRegex(ValueError,'Invalid finding locator'): check_bundle(self.bundle)

    def test_failed_source_integrity_cannot_complete(self):
        self.modify_manifest(lambda m:m['evidence'][0].update(sha256_after='0'*64))
        with self.assertRaisesRegex(ValueError,'integrity failure'): check_bundle(self.bundle)

    def test_run_failure_not_rewritten_as_success(self):
        self.modify_manifest(lambda m:m['runs'][-1].update(status='success'))
        with self.assertRaisesRegex(ValueError,'status mismatch'): check_bundle(self.bundle)

    def test_incomplete_checksum_coverage(self):
        (self.bundle/'unlisted.txt').write_text('SYNTHETIC unlisted material')
        with self.assertRaisesRegex(ValueError,'coverage'): check_bundle(self.bundle)

    def test_timezone_is_required(self):
        self.modify_manifest(lambda m:m.update(created_at='2020-01-02T12:00:00'))
        with self.assertRaisesRegex(ValueError,'timezone'): check_bundle(self.bundle)

    def test_investigation_cycle_rejected(self):
        path=self.bundle/'investigation.jsonl'
        calls=[json.loads(line) for line in path.read_text().splitlines()]
        calls[0]['prerequisite_call_ids']=[calls[-1]['call_id']]
        path.write_text('\n'.join(json.dumps(c) for c in calls)+'\n')
        with self.assertRaisesRegex(ValueError,'cycle'): check_bundle(self.bundle)

    def test_call_output_linkage_must_match_actual_run(self):
        path = self.bundle / 'investigation.jsonl'
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        calls[1]['artifact_ids'] = ['SYN-A004']
        path.write_text('\n'.join(json.dumps(c) for c in calls) + '\n')
        with self.assertRaisesRegex(ValueError,'output artifact mismatch'): check_bundle(self.bundle)

    def test_ioc_reference_requires_exact_id(self):
        path = self.bundle / 'iocs.csv'
        path.write_text(path.read_text().replace('SYN-A002:', 'SYN-A002-UNKNOWN:'))
        with self.assertRaisesRegex(ValueError,'exact artifact ID'): check_bundle(self.bundle)

    def test_source_identity_matches_bundled_fixture(self):
        self.modify_manifest(lambda m:m['evidence'][0].update(sha256='0'*64,sha256_before='0'*64,sha256_after='0'*64))
        with self.assertRaisesRegex(ValueError,'contradicts'): check_bundle(self.bundle)

    def test_missing_fields_are_actionable(self):
        self.modify_manifest(lambda m:m['runs'][0].pop('call_id'))
        with self.assertRaisesRegex(ValueError,'Invalid report structure'): check_bundle(self.bundle)

    def test_run_cannot_claim_another_runs_output(self):
        self.modify_manifest(lambda m:m['runs'][0]['artifact_ids'].append('SYN-A002'))
        path = self.bundle / 'investigation.jsonl'
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        calls[0]['artifact_ids'].append('SYN-A002')
        path.write_text('\n'.join(json.dumps(c) for c in calls) + '\n')
        with self.assertRaisesRegex(ValueError,'owned by another run'): check_bundle(self.bundle)

    def test_explicit_call_run_id_must_match(self):
        path = self.bundle / 'investigation.jsonl'
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        calls[1]['run_id'] = 'SYN-R001'
        path.write_text('\n'.join(json.dumps(c) for c in calls) + '\n')
        with self.assertRaisesRegex(ValueError,'contradicts run ownership'): check_bundle(self.bundle)

if __name__ == '__main__': unittest.main()
