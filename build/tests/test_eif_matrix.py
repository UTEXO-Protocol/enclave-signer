"""Protect production artifacts from the opt-in signet staging profile."""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class EifProfileTests(unittest.TestCase):
    def select(self, profile):
        result = subprocess.run(['python3', str(ROOT / 'build/eif-matrix.py'), profile],
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)['include']

    def test_production_keeps_existing_artifact_locations(self):
        entries = self.select('production')
        self.assertEqual([(x['variant'], x['eif_name'], x['s3_subpath']) for x in entries], [
            ('combined', 'utexo-bridge-enclave.eif', ''),
            ('rgb', 'utexo-bridge-enclave-rgb.eif', 'rgb/'),
            ('rgb-mint', 'utexo-bridge-enclave-mint.eif', 'rgb-mint/'),
            ('rgb-burn', 'utexo-bridge-enclave-burn.eif', 'rgb-burn/'),
            ('ccd', 'utexo-bridge-enclave-ccd.eif', 'ccd/'),
        ])
        self.assertFalse(any('stage' in x['dockerfile'] for x in entries))

    def test_stage_has_two_roles_with_disjoint_artifact_names_and_paths(self):
        production = self.select('production')
        stage = self.select('public-signet-stage')
        self.assertEqual([x['signer_role'] for x in stage], ['mint-signer', 'burn-signer'])
        for field in ('variant', 'eif_name', 's3_subpath', 'artifact_suffix'):
            with self.subTest(field=field):
                stage_values = {x[field] for x in stage}
                self.assertEqual(len(stage_values), 2)
                self.assertTrue(stage_values.isdisjoint({x[field] for x in production}))
        for entry in stage:
            self.assertEqual(entry['dockerfile'], 'Dockerfile.enclave.stage')
            self.assertTrue(entry['s3_subpath'].startswith('stage-signet/'))

    def test_unknown_profile_cannot_silently_build_production(self):
        result = subprocess.run(['python3', str(ROOT / 'build/eif-matrix.py'), 'stage-typo'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('unknown EIF profile', result.stderr)


if __name__ == '__main__':
    unittest.main()
