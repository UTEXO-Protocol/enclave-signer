"""Build argument regression tests; stop before any Docker/Nitro build."""
import json
import os
from pathlib import Path
import re
import shlex
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

KMS_PINS = dict(
    KMS_KEY_ARN='arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    KMS_REGION='eu-west-1',
    KMS_SEED_ID='mint-signer-1',
)


class BuildArgumentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='enclave-build-args-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.argv = self.base / 'docker-argv.json'
        self.docker_env = self.base / 'docker-env.json'
        docker = self.bin / 'docker'
        docker.write_text(
            '#!/usr/bin/env python3\n'
            'import json, os, pathlib, sys\n'
            'pathlib.Path(os.environ["TEST_DOCKER_ARGV"]).write_text(json.dumps(sys.argv[1:]))\n'
            'pins = {k: v for k, v in os.environ.items() '
            'if k.startswith("KMS_") or k == "RGB_ASSET_ID"}\n'
            'pathlib.Path(os.environ["TEST_DOCKER_ENV"]).write_text(json.dumps(pins))\n'
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
            TEST_DOCKER_ENV=str(self.docker_env),
        )

    def invoke(self, recipe, **extra):
        self.argv.unlink(missing_ok=True)
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
        # Endpoint and KMS values in the caller's env never reach the build.
        for recipe in RGB_RECIPES:
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset',
                                     ELECTRUM_URL='ssl://electrum.test:50002',
                                     EVM_RPC_HOST='rpc.test', EVM_RPC_TLS_CA_DER_HEX='ab',
                                     **KMS_PINS)
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

    def test_no_recipe_forwards_kms_pins(self):
        pins = dict(KMS_PINS, KMS_EXPECTED_EVM_ADDRESS='0x' + '12' * 20)
        for recipe in (*RGB_RECIPES, 'Dockerfile.enclave.ccd',
                       'Dockerfile.enclave-dev', 'Dockerfile.enclave-dev.bfa'):
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset', **pins)
                self.assertEqual(result.returncode, 42, result.stderr)
                expected = ['SOURCE_DATE_EPOCH=1700000000']
                if recipe in RGB_RECIPES:
                    expected.append('RGB_ASSET_ID=rgb:test-bfa-asset')
                self.assertEqual(self.captured_build_args(), expected)

    def invoke_make(self, target, **extra):
        self.argv.unlink(missing_ok=True)
        return subprocess.run(
            ['make', '--no-print-directory', target], cwd=ROOT,
            env=dict(self.env, **extra), capture_output=True, text=True,
        )

    def test_make_mint_passes_only_the_asset_as_environment_argument(self):
        pins = dict(KMS_PINS, KMS_EXPECTED_EVM_ADDRESS='0x' + '34' * 20,
                    RGB_ASSET_ID='rgb:test-bfa-asset')
        result = self.invoke_make('build_enclave_mint', **pins)
        self.assertEqual(result.returncode, 2, result.stderr)  # Docker stub exits 42.
        argv = json.loads(self.argv.read_text())
        self.assertEqual(argv[0], 'build')
        self.assertIn('./build/Dockerfile.enclave.mint', argv)
        self.assertEqual([argv[i + 1] for i, arg in enumerate(argv) if arg == '--build-arg'],
                         ['RGB_ASSET_ID'])
        self.assertEqual(json.loads(self.docker_env.read_text())['RGB_ASSET_ID'],
                         'rgb:test-bfa-asset')
        self.assertNotIn(self.env['GITHUB_TOKEN'], ' '.join(argv))

    def test_make_mint_rejects_missing_asset_before_docker(self):
        result = self.invoke_make('build_enclave_mint')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('RGB_ASSET_ID required', result.stderr)
        self.assertFalse(self.argv.exists())

    def test_make_old_targets_have_no_kms_dependency_or_arguments(self):
        for target in ('build_enclave', 'build_enclave_rgb',
                       'build_enclave_ccd', 'build_enclave_dev'):
            with self.subTest(target=target):
                result = self.invoke_make(target)
                self.assertEqual(result.returncode, 2, result.stderr)  # Reaches Docker.
                argv = json.loads(self.argv.read_text())
                self.assertEqual(argv[0], 'build')
                self.assertFalse(any('KMS_' in value for value in argv))

    def test_ccd_does_not_require_asset(self):
        result = self.invoke('Dockerfile.enclave.ccd')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), ['SOURCE_DATE_EPOCH=1700000000'])

    def test_ccd_ignores_workflow_asset(self):
        result = self.invoke('Dockerfile.enclave.ccd', RGB_ASSET_ID='rgb:test-bfa-asset')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), ['SOURCE_DATE_EPOCH=1700000000'])


class ImageInputsTests(unittest.TestCase):
    RECIPES = RGB_RECIPES + ('Dockerfile.enclave.ccd',)

    def test_eif_apt_uses_only_https_snapshots(self):
        for recipe in self.RECIPES:
            text = (ROOT / 'build' / recipe).read_text().replace('\\\n', ' ')
            stages = re.split(r'(?m)^FROM ', text)[1:]
            for stage in stages:
                with self.subTest(recipe=recipe, stage=stage.splitlines()[0]):
                    updates = [line for line in stage.splitlines()
                               if line.startswith('RUN ') and 'apt-get update' in line]
                    self.assertTrue(updates, 'Stage must configure snapshot sources')
                    for update in updates:
                        tokens = shlex.split(update)
                        sources = [token.split() for token in tokens
                                   if token.startswith(('deb ', 'deb-src '))]
                        self.assertTrue(sources, 'APT must not use inherited live sources')
                        for source in sources:
                            self.assertRegex(
                                source[1],
                                r'^https://snapshot\.debian\.org/archive/'
                                r'debian(?:-security)?/[0-9]{8}T[0-9]{6}Z/?$',
                            )
                        self.assertIn('> /etc/apt/sources.list', update)
                        self.assertLess(update.index('> /etc/apt/sources.list'),
                                        update.index('apt-get update'))
                        self.assertIn('rm -f /etc/apt/sources.list.d/*', update)
                        self.assertLess(update.index('rm -f /etc/apt/sources.list.d/*'),
                                        update.index('apt-get update'))

    def test_no_build_input_names_an_endpoint(self):
        files = [ROOT / 'build' / r for r in self.RECIPES]
        files += [ROOT / 'build/build-enclave.sh', ROOT / '.github/workflows/build-eif.yml',
                  ROOT / 'Makefile']
        for path in files:
            text = path.read_text()
            for name in ('ELECTRUM_URL', 'EVM_RPC_HOST', 'EVM_RPC_TLS_CA', 'EVM_RPC_URL',
                         'KMS_KEY_ARN', 'KMS_REGION', 'KMS_SEED_ID', 'KMS_EXPECTED_EVM_ADDRESS'):
                with self.subTest(file=path.name, name=name):
                    self.assertNotIn(name, text)


if __name__ == '__main__':
    unittest.main()
