"""Production build and publication account selection, without AWS access."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'build' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


settings = load('settings', 'eif-aws-settings.py')
ACCOUNT = '123456789012'


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(BUILD_PROFILE='prod-mainnet', GITHUB_REF='refs/heads/dev',
                        PROD_AWS_ACCOUNT_ID=ACCOUNT, PROD_AWS_REGION='us-east-1',
                        PROD_EIF_S3_BUCKET='fixture-prod-eif',
                        PROD_AWS_OIDC_ROLE_ARN=f'arn:aws:iam::{ACCOUNT}:role/build',
                        PROD_EIF_RELEASE_READ_ROLE_ARN=f'arn:aws:iam::{ACCOUNT}:role/read',
                        AWS_REGION='eu-central-1', EIF_S3_BUCKET='fixture-stage-eif',
                        AWS_OIDC_ROLE_ARN=f'arn:aws:iam::{ACCOUNT}:role/stage')

    def test_production_selects_only_its_own_settings(self):
        for operation, role in [('build', 'build'), ('publish', 'read')]:
            result = settings.select(self.env, operation)
            self.assertEqual(result['AWS_REGION'], 'us-east-1')
            self.assertEqual(result['EIF_S3_BUCKET'], 'fixture-prod-eif')
            self.assertEqual(result['AWS_ROLE'], f'arn:aws:iam::{ACCOUNT}:role/{role}')

    def test_missing_production_setting_never_falls_back(self):
        for key in ('PROD_AWS_ACCOUNT_ID', 'PROD_AWS_REGION', 'PROD_EIF_S3_BUCKET', 'PROD_AWS_OIDC_ROLE_ARN'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                settings.select(dict(self.env, **{key: ''}), 'build')

    def test_role_from_another_account_and_untrusted_ref_rejected(self):
        for edit in (dict(PROD_AWS_OIDC_ROLE_ARN='arn:aws:iam::999999999999:role/build'),
                     dict(GITHUB_REF='refs/heads/unreviewed')):
            with self.assertRaises(ValueError):
                settings.select(dict(self.env, **edit), 'build')

    def test_stage_retains_optional_upload_and_existing_settings(self):
        self.assertEqual(settings.select({'BUILD_PROFILE': 'default'}, 'build')['AWS_ROLE'], '')
        result = settings.select(dict(self.env, BUILD_PROFILE='stage-mainnet'), 'build')
        self.assertEqual(result['EIF_S3_BUCKET'], 'fixture-stage-eif')
        self.assertTrue(result['AWS_ROLE'].endswith('/stage'))
