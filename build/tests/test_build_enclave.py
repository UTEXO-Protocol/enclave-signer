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
    'Dockerfile.enclave.mint',
    'Dockerfile.enclave.burn',
)

KMS_PINS = dict(
    KMS_KEY_ARN='arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    KMS_REGION='eu-west-1',
    KMS_SEED_ID='mint-signer-1',
)
ACCOUNTS = '123456789012'
MEASURED_PINS = dict(
    BITCOIN_NETWORK='signet', BTC_RELAY_MODE='none', EVM_CHAIN_ID='42161',
    EVM_PROXY_CONTRACT_ADDRESS='0x' + '11' * 20,
    FUNDS_IN_CONTRACT='0x' + '22' * 20, TOKEN_CONTRACT='0x' + '33' * 20,
)
MEMBER_INPUT_NAMES = (
    'ENDPOINTS_SHA256', 'ELECTRUM_URL', 'EVM_RPC_HOST', 'EVM_RPC_TLS_PORT',
    'EVM_RPC_TLS_CA_DER_FILE', 'EVM_RPC_TLS_CA_DER_HEX', 'EVM_RPC_URL',
    'EVM_RPC_PATH', 'EVM_RPC_PATH_FILE', 'EVM_RPC_API_KEY',
    'KMS_KEY_ARN', 'KMS_REGION', 'KMS_SEED_ID', 'KMS_EXPECTED_EVM_ADDRESS',
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
                    'BUILD_PROFILE', 'STAGE_RGB_ASSET_ID', 'STAGE_TOKEN_CONTRACT',
                    'STAGE_GAS_TX_ALLOWED_SELECTORS', 'RUST_LOG',
                    'GAS_TX_ALLOWED_TO', 'GAS_TX_MAX_GAS_LIMIT', 'GAS_TX_MAX_FEE_PER_GAS',
                    'GAS_TX_MAX_VALUE_WEI', 'GAS_TX_ALLOWED_SELECTORS',
                    'KMS_ALLOWED_ACCOUNT_IDS', 'ENCLAVE_FEATURES', *MEASURED_PINS, *MEMBER_INPUT_NAMES):
            self.env.pop(key, None)
        self.env.update(
            PATH=f'{self.bin}:{os.environ["PATH"]}',
            KMS_ALLOWED_ACCOUNT_IDS=ACCOUNTS,
            RGB_LIB_BFA_DEPLOY_KEY='fixture-deploy-key-not-a-real-credential',
            RGB_PRIVATE_DEPS_TOKEN='fixture-mirror-token-not-a-real-credential',
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

    def base_args(self, recipe):
        """Build args every RGB recipe gets. The mint recipe also pins the KMS accounts."""
        args = ['SOURCE_DATE_EPOCH=1700000000', 'RGB_ASSET_ID=rgb:test-bfa-asset']
        if recipe.endswith('.mint'):
            args.append(f'KMS_ALLOWED_ACCOUNT_IDS={ACCOUNTS}')
        return args

    def captured_build_args(self):
        argv = json.loads(self.argv.read_text())
        self.assertEqual(argv[:2], ['buildx', 'build'])
        self.assertNotIn(self.env['RGB_LIB_BFA_DEPLOY_KEY'], ' '.join(argv))
        self.assertNotIn(self.env['RGB_PRIVATE_DEPS_TOKEN'], ' '.join(argv))
        return [argv[i + 1] for i, value in enumerate(argv) if value == '--build-arg']

    def test_rgb_recipes_reject_missing_asset_before_docker(self):
        for recipe in RGB_RECIPES:
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('requires RGB_ASSET_ID', result.stderr)
                self.assertFalse(self.argv.exists())

    def test_mint_recipe_rejects_a_missing_or_malformed_account_list_before_docker(self):
        for value, message in (
            ('', 'requires KMS_ALLOWED_ACCOUNT_IDS'),
            (' ', 'comma-separated 12-digit'),
            (',', 'comma-separated 12-digit'),
            ('12345', 'comma-separated 12-digit'),
            ('12345678901a', 'comma-separated 12-digit'),
            (f'{ACCOUNTS},', 'comma-separated 12-digit'),
            (f'{ACCOUNTS}, {ACCOUNTS}', 'comma-separated 12-digit'),
        ):
            with self.subTest(value=value):
                result = self.invoke('Dockerfile.enclave.mint', RGB_ASSET_ID='rgb:test-bfa-asset',
                                     KMS_ALLOWED_ACCOUNT_IDS=value)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.argv.exists())

    def test_mint_recipe_forwards_a_list_of_accounts(self):
        accounts = f'{ACCOUNTS},111111111111'
        result = self.invoke('Dockerfile.enclave.mint', RGB_ASSET_ID='rgb:test-bfa-asset',
                             KMS_ALLOWED_ACCOUNT_IDS=accounts)
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertIn(f'KMS_ALLOWED_ACCOUNT_IDS={accounts}', self.captured_build_args())

    def test_rgb_asset_forwarded_once_without_implicit_debug(self):
        # Endpoint and KMS values in the caller's env never reach the build.
        for recipe in RGB_RECIPES:
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset',
                                     ELECTRUM_URL='ssl://electrum.test:50002',
                                     EVM_RPC_HOST='rpc.test', EVM_RPC_TLS_CA_DER_HEX='ab',
                                     **KMS_PINS)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(self.captured_build_args(), self.base_args(recipe))
                self.assertNotIn('build override:', result.stdout)

    def test_role_overrides_are_forwarded_and_logged_only_when_declared(self):
        for role in ('mint', 'burn'):
            with self.subTest(role=role):
                overrides = dict(MEASURED_PINS, ENCLAVE_FEATURES=f'vsock,{role}-signer')
                result = self.invoke(f'Dockerfile.enclave.{role}',
                                     RGB_ASSET_ID='rgb:test-bfa-asset', **overrides)
                self.assertEqual(result.returncode, 42, result.stderr)
                applied = dict(overrides)
                self.assertCountEqual(self.captured_build_args(), [
                    *self.base_args(f'Dockerfile.enclave.{role}'),
                    *(f'{key}={value}' for key, value in applied.items()),
                ])
                self.assertCountEqual(
                    [line.strip() for line in result.stdout.splitlines()
                     if 'build override:' in line],
                    [f'build override: {key}={value}' for key, value in applied.items()],
                )

    def test_kms_account_pin_reaches_only_the_recipe_that_declares_it(self):
        for role, forwarded in (('mint', True), ('burn', False)):
            with self.subTest(role=role):
                result = self.invoke(f'Dockerfile.enclave.{role}',
                                     RGB_ASSET_ID='rgb:test-bfa-asset',
                                     ENCLAVE_FEATURES=f'vsock,{role}-signer',
                                     BITCOIN_NETWORK='signet',
                                     KMS_ALLOWED_ACCOUNT_IDS='123456789012')
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(
                    'KMS_ALLOWED_ACCOUNT_IDS=123456789012' in self.captured_build_args(),
                    forwarded)

    def test_member_settings_do_not_change_role_build_arguments(self):
        # Capture the real wrapper's full Docker command for both feature profiles.
        # No Docker/Nitro build runs here; ImageInputsTests separately checks that
        # the recipes cannot bake these member settings into ARG or ENV.
        for role in ('mint', 'burn'):
            for spv in (True, False):
                with self.subTest(role=role, spv=spv):
                    recipe = f'Dockerfile.enclave.{role}'
                    pins = dict(
                        RGB_ASSET_ID='rgb:test-bfa-asset',
                        ENCLAVE_FEATURES=f'vsock,{"rgb," if spv else ""}{role}-signer',
                        BITCOIN_NETWORK='bitcoin' if spv else 'signet',
                        BTC_RELAY_MODE='required' if spv else 'none',
                    )
                    baseline = self.invoke(recipe, **pins)
                    self.assertEqual(baseline.returncode, 42, baseline.stderr)
                    baseline_argv = json.loads(self.argv.read_text())
                    for member in ('a', 'b'):
                        # These include ignored legacy/unsupported inputs. Neither
                        # credentials nor an old digest may enter a measured build.
                        settings = dict(
                            ENDPOINTS_SHA256=('12' if member == 'a' else '34') * 32,
                            ELECTRUM_URL=f'ssl://electrum-{member}.test:50002',
                            EVM_RPC_HOST=f'rpc-{member}.test',
                            EVM_RPC_TLS_PORT='443' if member == 'a' else '8443',
                            EVM_RPC_TLS_CA_DER_FILE=f'/member-{member}/ca.der',
                            EVM_RPC_TLS_CA_DER_HEX='aa' if member == 'a' else 'bb',
                            EVM_RPC_URL=f'https://rpc-{member}.test/v2/secret-{member}',
                            EVM_RPC_PATH=f'/v2/secret-{member}',
                            EVM_RPC_PATH_FILE=f'/member-{member}/rpc-path',
                            EVM_RPC_API_KEY=f'secret-{member}',
                            **dict(KMS_PINS, KMS_SEED_ID=f'member-{member}',
                                   KMS_EXPECTED_EVM_ADDRESS='0x' + ('11' if member == 'a' else '22') * 20),
                        )
                        self.assertCountEqual(settings, MEMBER_INPUT_NAMES)
                        result = self.invoke(recipe, **pins, **settings)
                        self.assertEqual(result.returncode, 42, result.stderr)
                        self.assertEqual(json.loads(self.argv.read_text()), baseline_argv)
                        self.assertEqual(result.stdout, baseline.stdout)
                        self.assertEqual(result.stderr, baseline.stderr)
                        build_arg_names = {arg.split('=', 1)[0]
                                           for arg in self.captured_build_args()}
                        self.assertTrue(build_arg_names.isdisjoint(MEMBER_INPUT_NAMES))

    def test_optional_overrides_do_not_leak_into_legacy_or_ccd_recipes(self):
        for recipe in ('Dockerfile.enclave', 'Dockerfile.enclave.rgb', 'Dockerfile.enclave.ccd',
                       'Dockerfile.enclave-dev', 'Dockerfile.enclave-dev.bfa'):
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset',
                                     ENCLAVE_FEATURES='vsock,mint-signer', **MEASURED_PINS)
                self.assertEqual(result.returncode, 42, result.stderr)
                expected = ['SOURCE_DATE_EPOCH=1700000000']
                if recipe in RGB_RECIPES:
                    expected = self.base_args(recipe)
                self.assertEqual(self.captured_build_args(), expected)
                self.assertNotIn('build override:', result.stdout)

    def test_empty_role_overrides_keep_recipe_defaults(self):
        for role in ('mint', 'burn'):
            with self.subTest(role=role):
                empty = {key: '' for key in ('ENCLAVE_FEATURES', *MEASURED_PINS)}
                result = self.invoke(f'Dockerfile.enclave.{role}',
                                     RGB_ASSET_ID='rgb:test-bfa-asset', **empty)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(self.captured_build_args(),
                                 self.base_args(f'Dockerfile.enclave.{role}'))
                self.assertNotIn('build override:', result.stdout)

    def test_non_signet_roles_require_rgb_before_docker(self):
        for role in ('mint', 'burn'):
            for network in (None, '', 'bitcoin', 'testnet', 'testnet4', 'regtest'):
                with self.subTest(role=role, network=network):
                    overrides = {} if network is None else {'BITCOIN_NETWORK': network}
                    result = self.invoke(f'Dockerfile.enclave.{role}',
                                         RGB_ASSET_ID='rgb:test-bfa-asset',
                                         ENCLAVE_FEATURES=f'vsock,{role}-signer', **overrides)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn('requires the rgb feature', result.stderr)
                    self.assertFalse(self.argv.exists())

    def test_related_feature_names_do_not_satisfy_rgb_guard(self):
        for feature in ('rgb-validation', 'bfa-mint'):
            with self.subTest(feature=feature):
                result = self.invoke('Dockerfile.enclave.burn',
                                     RGB_ASSET_ID='rgb:test-bfa-asset',
                                     ENCLAVE_FEATURES=f'vsock,{feature},burn-signer')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('requires the rgb feature', result.stderr)
                self.assertFalse(self.argv.exists())

    def test_non_signet_roles_accept_explicit_rgb(self):
        for role in ('mint', 'burn'):
            for features in (f'rgb,vsock,{role}-signer', f'vsock,rgb,{role}-signer',
                             f'vsock,{role}-signer,rgb', f'vsock rgb {role}-signer'):
                with self.subTest(role=role, features=features):
                    result = self.invoke(f'Dockerfile.enclave.{role}',
                                         RGB_ASSET_ID='rgb:test-bfa-asset',
                                         BITCOIN_NETWORK='bitcoin', ENCLAVE_FEATURES=features)
                    self.assertEqual(result.returncode, 42, result.stderr)
                    self.assertIn(f'ENCLAVE_FEATURES={features}', self.captured_build_args())

    def test_no_recipe_forwards_kms_pins(self):
        pins = dict(KMS_PINS, KMS_EXPECTED_EVM_ADDRESS='0x' + '12' * 20)
        for recipe in (*RGB_RECIPES, 'Dockerfile.enclave.ccd',
                       'Dockerfile.enclave-dev.bfa'):
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset', **pins)
                self.assertEqual(result.returncode, 42, result.stderr)
                expected = ['SOURCE_DATE_EPOCH=1700000000']
                if recipe in RGB_RECIPES:
                    expected = self.base_args(recipe)
                self.assertEqual(self.captured_build_args(), expected)

    def invoke_make(self, target, **extra):
        self.argv.unlink(missing_ok=True)
        return subprocess.run(
            ['make', '--no-print-directory', target], cwd=ROOT,
            env=dict(self.env, **extra), capture_output=True, text=True,
        )

    def test_make_mint_passes_the_asset_and_the_account_list_as_environment_arguments(self):
        pins = dict(KMS_PINS, KMS_EXPECTED_EVM_ADDRESS='0x' + '34' * 20,
                    RGB_ASSET_ID='rgb:test-bfa-asset')
        result = self.invoke_make('build_enclave_mint', **pins)
        self.assertEqual(result.returncode, 2, result.stderr)  # Docker stub exits 42.
        argv = json.loads(self.argv.read_text())
        self.assertEqual(argv[0], 'build')
        self.assertIn('./build/Dockerfile.enclave.mint', argv)
        self.assertEqual([argv[i + 1] for i, arg in enumerate(argv) if arg == '--build-arg'],
                         ['RGB_ASSET_ID', 'KMS_ALLOWED_ACCOUNT_IDS'])
        docker_env = json.loads(self.docker_env.read_text())
        self.assertEqual(docker_env['RGB_ASSET_ID'], 'rgb:test-bfa-asset')
        self.assertEqual(docker_env['KMS_ALLOWED_ACCOUNT_IDS'], ACCOUNTS)
        self.assertNotIn(self.env['RGB_LIB_BFA_DEPLOY_KEY'], ' '.join(argv))
        self.assertIn('id=rgb_deps_token,env=RGB_PRIVATE_DEPS_TOKEN', argv)

    def test_make_mint_rejects_missing_asset_before_docker(self):
        result = self.invoke_make('build_enclave_mint')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('RGB_ASSET_ID required', result.stderr)
        self.assertFalse(self.argv.exists())

    def test_make_mint_rejects_a_missing_account_list_before_docker(self):
        result = self.invoke_make('build_enclave_mint', RGB_ASSET_ID='rgb:test-bfa-asset',
                                  KMS_ALLOWED_ACCOUNT_IDS='')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('KMS_ALLOWED_ACCOUNT_IDS required', result.stderr)
        self.assertFalse(self.argv.exists())

    def test_make_old_targets_have_no_kms_dependency_or_arguments(self):
        for target in ('build_enclave_ccd',):
            with self.subTest(target=target):
                result = self.invoke_make(target)
                self.assertEqual(result.returncode, 2, result.stderr)  # Reaches Docker.
                argv = json.loads(self.argv.read_text())
                self.assertEqual(argv[0], 'build')
                self.assertFalse(any('KMS_' in value for value in argv))

    def test_the_measured_image_env_is_published(self):
        stubs = {
            'docker': ('#!/bin/sh\n[ "$1 $2" = "image inspect" ] && '
                       'echo \'["EVM_CHAIN_ID=42161"]\'\nexit 0\n'),
            'nitro-cli': ('#!/bin/sh\n[ "$1" = build-enclave ] && touch "$5"\n'
                          '[ "$1" = describe-eif ] && echo \'{"Measurements": {}}\'\nexit 0\n'),
            'jq': '#!/bin/sh\ncat\n',
        }
        for name, body in stubs.items():
            (self.bin / name).write_text(body)
        result = self.invoke('Dockerfile.enclave.mint', RGB_ASSET_ID='rgb:test-bfa-asset')
        self.assertEqual(result.returncode, 0, result.stderr)
        env = json.loads((self.base / 'out/IMAGE-ENV.json').read_text())
        self.assertEqual(env, ['EVM_CHAIN_ID=42161'])

    def captured_secrets(self):
        argv = json.loads(self.argv.read_text())
        return [argv[i + 1] for i, value in enumerate(argv) if value == '--secret']

    def test_every_recipe_takes_the_deploy_key_and_the_mirror_token_as_secrets(self):
        for recipe in (*RGB_RECIPES, 'Dockerfile.enclave.ccd',
                       'Dockerfile.enclave-dev.bfa'):
            with self.subTest(recipe=recipe):
                result = self.invoke(recipe, RGB_ASSET_ID='rgb:test-bfa-asset')
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(self.captured_secrets(), [
                    'id=lib_key,env=RGB_LIB_BFA_DEPLOY_KEY',
                    'id=rgb_deps_token,env=RGB_PRIVATE_DEPS_TOKEN',
                ])

    def test_the_secret_files_of_private_deps_dir_win(self):
        deps = self.base / 'deps'
        deps.mkdir()
        (deps / 'lib_key').write_text('fixture-deploy-key-file')
        (deps / 'rgb_deps_token').write_text('fixture-mirror-token-file')
        result = self.invoke('Dockerfile.enclave.ccd', PRIVATE_DEPS_DIR=str(deps))
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_secrets(), [
            f'id=lib_key,src={deps}/lib_key',
            f'id=rgb_deps_token,src={deps}/rgb_deps_token',
        ])
        self.assertNotIn('fixture-deploy-key-file', self.argv.read_text())
        self.assertNotIn('fixture-mirror-token-file', self.argv.read_text())

    def test_a_missing_key_or_token_refuses_before_docker(self):
        deps = self.base / 'deps'
        deps.mkdir()
        cases = (
            ('RGB_LIB_BFA_DEPLOY_KEY', None, 'rgb-lib-bfa'),
            ('RGB_PRIVATE_DEPS_TOKEN', None, 'RGB_PRIVATE_DEPS_TOKEN'),
            (None, 'lib_key', 'lib_key'),
            (None, 'rgb_deps_token', 'rgb_deps_token'),
        )
        for unset, missing_file, named in cases:
            with self.subTest(unset=unset, missing_file=missing_file):
                env = dict(self.env, DOCKERFILE='Dockerfile.enclave.ccd')
                if unset:
                    env.pop(unset)
                else:
                    for name in ('lib_key', 'rgb_deps_token'):
                        (deps / name).write_text('' if name == missing_file else 'fixture')
                    env['PRIVATE_DEPS_DIR'] = str(deps)
                self.argv.unlink(missing_ok=True)
                result = subprocess.run(['bash', str(ROOT / 'build/build-enclave.sh')],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(named, result.stderr)
                self.assertFalse(self.argv.exists())

    def test_ccd_does_not_require_asset(self):
        result = self.invoke('Dockerfile.enclave.ccd')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), ['SOURCE_DATE_EPOCH=1700000000'])

    def test_ccd_ignores_workflow_asset(self):
        result = self.invoke('Dockerfile.enclave.ccd', RGB_ASSET_ID='rgb:test-bfa-asset')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.captured_build_args(), ['SOURCE_DATE_EPOCH=1700000000'])

    def stage_inputs(self):
        return dict(BUILD_PROFILE='stage-signet', STAGE_RGB_ASSET_ID='rgb:new-signet-asset',
                    STAGE_TOKEN_CONTRACT='0x' + '33' * 20,
                    STAGE_GAS_TX_ALLOWED_SELECTORS='0x12345678,0xabcdef01')

    def test_stage_profile_requires_dedicated_pins_before_docker(self):
        for key in ('STAGE_RGB_ASSET_ID', 'STAGE_TOKEN_CONTRACT',
                    'STAGE_GAS_TX_ALLOWED_SELECTORS'):
            with self.subTest(key=key):
                inputs = self.stage_inputs()
                inputs[key] = ''
                result = self.invoke('Dockerfile.enclave.burn',
                                     RGB_ASSET_ID='rgb:old-asset', **inputs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)
                self.assertFalse(self.argv.exists())

    def test_stage_profile_rejects_bad_pins_and_debug_features(self):
        for key, value in (('STAGE_TOKEN_CONTRACT', '0x' + '00' * 20),
                           ('STAGE_TOKEN_CONTRACT', 'not-an-address'),
                           ('STAGE_GAS_TX_ALLOWED_SELECTORS', '0x1234'),
                           ('ENCLAVE_DEBUG_FEATURES', 'allow-debug-pcrs')):
            with self.subTest(key=key, value=value):
                inputs = self.stage_inputs()
                inputs[key] = value
                result = self.invoke('Dockerfile.enclave.burn', **inputs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.argv.exists())

    def test_stage_profile_pins_both_roles_without_spv_and_uses_multisig_for_gas(self):
        for role in ('mint', 'burn'):
            with self.subTest(role=role):
                inputs = self.stage_inputs()
                if role == 'mint':
                    inputs.pop('STAGE_GAS_TX_ALLOWED_SELECTORS')
                result = self.invoke(f'Dockerfile.enclave.{role}',
                                     BITCOIN_NETWORK='bitcoin', ENCLAVE_FEATURES='vsock,rgb',
                                     RGB_ASSET_ID='rgb:old-asset', RUST_LOG='trace', **inputs)
                self.assertEqual(result.returncode, 42, result.stderr)
                args = dict(arg.split('=', 1) for arg in self.captured_build_args())
                self.assertEqual(args['ENCLAVE_FEATURES'], f'vsock,{role}-signer')
                self.assertEqual(args['RGB_ASSET_ID'], inputs['STAGE_RGB_ASSET_ID'])
                self.assertEqual(args['TOKEN_CONTRACT'], inputs['STAGE_TOKEN_CONTRACT'])
                self.assertNotIn('ENDPOINTS_SHA256', args)
                self.assertEqual(args['BITCOIN_NETWORK'], 'signet')
                self.assertEqual(args['BTC_RELAY_MODE'], 'none')
                self.assertEqual(args['RUST_LOG'], 'debug,alloy_transport_http=off')
                self.assertEqual(args['FUNDS_IN_CONTRACT'],
                                 '0xe67c9eb5006512525f597c3fa6119891bd4efaa6')
                if role == 'burn':
                    self.assertEqual(args['GAS_TX_ALLOWED_TO'],
                                     '0x4ab64dd591778ab9b65fd81062703595dfe64552')
                    self.assertEqual(args['GAS_TX_ALLOWED_TO'], args['EVM_PROXY_CONTRACT_ADDRESS'])
                    self.assertEqual(args['GAS_TX_MAX_GAS_LIMIT'], '3000000')
                    self.assertEqual(args['GAS_TX_ALLOWED_SELECTORS'], inputs['STAGE_GAS_TX_ALLOWED_SELECTORS'])
                else:
                    self.assertNotIn('GAS_TX_ALLOWED_TO', args)

    def test_stage_profile_refuses_legacy_recipe_and_unknown_profile(self):
        for recipe, profile in (('Dockerfile.enclave', 'stage-signet'),
                                ('Dockerfile.enclave.burn', 'typo')):
            with self.subTest(recipe=recipe, profile=profile):
                result = self.invoke(recipe, BUILD_PROFILE=profile)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.argv.exists())


class ImageInputsTests(unittest.TestCase):
    RECIPES = RGB_RECIPES + ('Dockerfile.enclave.ccd',)

    def test_every_rgb_recipe_fixes_the_finality_tag_and_the_depth(self):
        # Every image uses `finalized` and 3. With no ARG, no build can change them.
        for recipe in RGB_RECIPES:
            text = (ROOT / 'build' / recipe).read_text()
            with self.subTest(recipe=recipe):
                self.assertRegex(text, r'(?m)^\s*EVM_FINALITY_TAG=finalized\b')
                self.assertRegex(text, r'(?m)^\s*SPV_MIN_CONFIRMATIONS=3\b')
                self.assertNotRegex(text, r'(?m)^ARG (EVM_FINALITY_TAG|SPV_MIN_CONFIRMATIONS)\b')

    def test_eif_apt_uses_only_https_snapshots(self):
        for recipe in self.RECIPES:
            text = (ROOT / 'build' / recipe).read_text().replace('\\\n', ' ')
            stages = re.split(r'(?m)^FROM ', text)[1:]
            for stage in stages:
                with self.subTest(recipe=recipe, stage=stage.splitlines()[0]):
                    updates = [line for line in stage.splitlines()
                               if line.startswith('RUN ') and (
                                   'apt-get update' in line or
                                   'sh /usr/local/bin/apt-snapshot-install.sh' in line)]
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
                        install = ('sh /usr/local/bin/apt-snapshot-install.sh'
                                   if 'apt-snapshot-install.sh' in update
                                   else 'apt-get update')
                        self.assertLess(update.index('> /etc/apt/sources.list'),
                                        update.index(install))
                        self.assertIn('rm -f /etc/apt/sources.list.d/*', update)
                        self.assertLess(update.index('rm -f /etc/apt/sources.list.d/*'),
                                        update.index(install))

    def test_no_build_input_names_an_endpoint(self):
        files = [ROOT / 'build' / r for r in self.RECIPES]
        files += [ROOT / 'build/build-enclave.sh', ROOT / '.github/workflows/build-eif.yml',
                  ROOT / 'Makefile']
        for path in files:
            text = path.read_text()
            for name in (*MEMBER_INPUT_NAMES, 'EVM_RPC_TLS_CA', 'EVM_RPC_CA'):
                with self.subTest(file=path.name, name=name):
                    self.assertNotIn(name, text)

    def test_no_member_setting_in_measured_image_environment(self):
        # Inspect real ENV declarations, including multiline ones, in all EIF
        # recipes. A wrapper-only test misses values baked directly in a recipe.
        for recipe in self.RECIPES:
            text = (ROOT / 'build' / recipe).read_text().replace('\\\n', ' ')
            for line in text.splitlines():
                if not line.startswith('ENV '):
                    continue
                for assignment in shlex.split(line[4:]):
                    name = assignment.split('=', 1)[0]
                    # A release pin, not a member setting: a host that chose
                    # this list could name a key in its own account.
                    if name == 'KMS_ALLOWED_ACCOUNT_IDS':
                        continue
                    with self.subTest(recipe=recipe, name=name):
                        self.assertNotEqual(name, 'ENDPOINTS_SHA256')
                        self.assertFalse(name.startswith(('ELECTRUM_', 'ESPLORA_',
                                                          'EVM_RPC_', 'KMS_')))


if __name__ == '__main__':
    unittest.main()
