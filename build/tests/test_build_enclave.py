"""Build argument regression tests; stop before any Docker/Nitro build."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RGB_RECIPES = (
    'Dockerfile.enclave',
    'Dockerfile.enclave.rgb',
    'Dockerfile.enclave.mint',
    'Dockerfile.enclave.burn',
)


class BuildArgumentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='enclave-build-args-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.argv = self.base / 'docker-argv.json'
        docker = self.bin / 'docker'
        docker.write_text(
            '#!/usr/bin/env python3\n'
            'import json, os, pathlib, sys\n'
            'pathlib.Path(os.environ["TEST_DOCKER_ARGV"]).write_text(json.dumps(sys.argv[1:]))\n'
            'sys.exit(42)\n'
        )
        docker.chmod(0o700)
        for command in ('nitro-cli', 'jq'):
            stub = self.bin / command
            stub.write_text('#!/bin/sh\nexit 99\n')
            stub.chmod(0o700)
        self.env = dict(os.environ)
        for key in ('RGB_ASSET_ID', 'ENCLAVE_DEBUG_FEATURES', 'PRIVATE_DEPS_DIR',
                    'KMS_KEY_ARN', 'KMS_REGION', 'KMS_SEED_ID', 'KMS_EXPECTED_EVM_ADDRESS'):
            self.env.pop(key, None)
        self.env.update(
            PATH=f'{self.bin}:{os.environ["PATH"]}',
            GITHUB_TOKEN='fixture-not-a-real-token',
            OUT_DIR=str(self.base / 'out'),
            SOURCE_DATE_EPOCH='1700000000',
            TEST_DOCKER_ARGV=str(self.argv),
        )

    def invoke(self, recipe, **extra):
        return subprocess.run(
            ['bash', str(ROOT / 'build/build-enclave.sh')],
            env=dict(self.env, DOCKERFILE=recipe, **extra),
            capture_output=True, text=True,
        )

    def captured_build_args(self):
        argv = json.loads(self.argv.read_text())
        self.assertEqual(argv[:2], ['buildx', 'build'])
        self.assertNotIn(self.env['GITHUB_TOKEN'], ' '.join(argv))
        return [argv[i + 1] for i, value in enumerate(argv) if value == '--build-arg']

    def test_rgb_recipes_reject_missing_asset_before_docker(self):
        for recipe in RGB_RECIPES:
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('requires RGB_ASSET_ID', result.stderr)
                self.assertFalse(self.argv.exists())

    def test_rgb_asset_forwarded_once_without_implicit_debug(self):
        for recipe in RGB_RECIPES:
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset')
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(self.captured_build_args(), [
                    'SOURCE_DATE_EPOCH=1700000000', 'RGB_ASSET_ID=rgb:test-bfa-asset',
                ])

    def test_combined_forwards_asset_and_explicit_debug_together(self):
        result = self.invoke('Dockerfile.enclave', RGB_ASSET_ID='rgb:test-bfa-asset',
                             ENCLAVE_DEBUG_FEATURES='allow-debug-pcrs')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), [
            'SOURCE_DATE_EPOCH=1700000000', 'RGB_ASSET_ID=rgb:test-bfa-asset',
            'ENCLAVE_DEBUG_FEATURES=allow-debug-pcrs',
        ])

    def test_kms_pins_forwarded_only_to_swap_recipes(self):
        pins = dict(KMS_KEY_ARN='arn:aws:kms:eu-west-1:123456789012:key/k',
                    KMS_REGION='eu-west-1', KMS_SEED_ID='signer-1')
        for recipe in ('Dockerfile.enclave', 'Dockerfile.enclave.rgb'):
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset', **pins)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(self.captured_build_args(), [
                    'SOURCE_DATE_EPOCH=1700000000', 'RGB_ASSET_ID=rgb:test-bfa-asset',
                    'KMS_KEY_ARN=arn:aws:kms:eu-west-1:123456789012:key/k',
                    'KMS_REGION=eu-west-1', 'KMS_SEED_ID=signer-1',
                ])
        result = self.invoke('Dockerfile.enclave.mint', RGB_ASSET_ID='rgb:test-bfa-asset', **pins)
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(),
                         ['SOURCE_DATE_EPOCH=1700000000', 'RGB_ASSET_ID=rgb:test-bfa-asset'])

    def test_ccd_does_not_require_asset(self):
        result = self.invoke('Dockerfile.enclave.ccd')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), ['SOURCE_DATE_EPOCH=1700000000'])

    def test_ccd_ignores_workflow_asset(self):
        result = self.invoke('Dockerfile.enclave.ccd', RGB_ASSET_ID='rgb:test-bfa-asset')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), ['SOURCE_DATE_EPOCH=1700000000'])


if __name__ == '__main__':
    unittest.main()
