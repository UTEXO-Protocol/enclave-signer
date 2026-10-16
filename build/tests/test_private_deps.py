"""Credential routing and cleanup tests; no private credentials or network needed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Each private dep uses a per-repo SSH Host alias. IdentitiesOnly yes ensures
# GitHub accepts exactly the right key per connection.
ALIASES = {
    'github-rgb-lib': 'lib_key',
    'github-federated-signer': 'federated_key',
}
DEPLOY_KEY = 'fixture-private-key-not-a-real-credential'


class PrivateDepsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='private-deps-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.secrets = self.base / 'secrets'
        self.secrets.mkdir()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        scanner = self.bin / 'ssh-keyscan'
        scanner.write_text('#!/bin/sh\nprintf "github.com ssh-ed25519 test-host-key\\n"\n')
        scanner.chmod(0o700)
        self.env = dict(os.environ, PRIVATE_DEPS_DIR=str(self.secrets),
                        PATH=f'{self.bin}:{os.environ["PATH"]}')

    def run_auth(self, scope, code):
        probe = self.base / 'probe.py'
        probe.write_text('import os, pathlib, subprocess, json, shlex\n' + code)
        return subprocess.run(['sh', str(ROOT / 'build/with-private-deps.sh'),
                               scope, 'python3', str(probe)], env=self.env,
                              capture_output=True, text=True)

    def keys(self):
        for key in ALIASES.values():
            path = self.secrets / key
            path.write_text(f'{DEPLOY_KEY}\n')
            path.chmod(0o600)

    def lib_key(self):
        path = self.secrets / 'lib_key'
        path.write_text(f'{DEPLOY_KEY}\n')
        path.chmod(0o600)

    def test_each_ssh_alias_selects_only_its_repo_key(self):
        self.keys()
        result = self.run_auth('parent', f'''
assert os.environ['CARGO_NET_GIT_FETCH_WITH_CLI'] == 'true'
for alias, key in {ALIASES!r}.items():
    args = shlex.split(os.environ['GIT_SSH_COMMAND']) + ['-G', alias]
    config = subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)
    assert 'hostname github.com\\n' in config, config
    assert 'identitiesonly yes\\n' in config, config
    assert 'identityagent none\\n' in config, config
    identities = [s for s in config.splitlines() if s.startswith('identityfile ')]
    assert identities == ['identityfile ' + os.environ['PRIVATE_DEPS_DIR'] + '/' + key], identities
print(os.environ['GIT_CONFIG_GLOBAL'])
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_only_the_parent_and_enclave_scopes_exist(self):
        self.lib_key()
        result = self.run_auth('tools', 'print("must not start")')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid dependency scope', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_missing_or_empty_lib_key_refuses_before_build(self):
        for scope in ('parent', 'enclave'):
            for content in (None, ''):
                with self.subTest(scope=scope, content=content):
                    path = self.secrets / 'lib_key'
                    path.unlink(missing_ok=True)
                    if content is not None:
                        path.write_text(content)
                    result = self.run_auth(scope, 'print("must not start")')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('lib_key', result.stderr)
                    self.assertIn('rgb-lib-bfa', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_enclave_scope_has_only_rgb_lib_key(self):
        self.keys()
        result = self.run_auth('enclave', f'''
args = shlex.split(os.environ['GIT_SSH_COMMAND']) + ['-G', 'github-rgb-lib']
config = subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)
assert 'identityfile ' + os.environ['PRIVATE_DEPS_DIR'] + '/lib_key' in config, config
args2 = shlex.split(os.environ['GIT_SSH_COMMAND']) + ['-G', 'github-federated-signer']
config2 = subprocess.check_output(args2, text=True, stderr=subprocess.DEVNULL)
assert os.environ['PRIVATE_DEPS_DIR'] + '/federated_key' not in config2, config2
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deploy_key_reads_proto_when_both_keys_present(self):
        self.keys()
        result = self.run_auth('parent', f'''
for alias, key in {ALIASES!r}.items():
    args = shlex.split(os.environ['GIT_SSH_COMMAND']) + ['-G', alias]
    config = subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)
    assert os.environ['PRIVATE_DEPS_DIR'] + '/' + key in config, (alias, config)
assert 'GIT_SSH_COMMAND' in os.environ
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_command_preserves_status_and_cleans_config(self):
        self.keys()
        result = self.run_auth('parent', 'print(os.environ["GIT_CONFIG_GLOBAL"]); raise SystemExit(42)')
        self.assertEqual(result.returncode, 42)
        self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_prepare_keys_preserves_multiline_values_and_restricts_permissions(self):
        value = "fixture first line\nfixture second line"
        env = dict(self.env, FEDERATED_SIGNER_PROTO_DEPLOY_KEY=value,
                   RGB_LIB_BFA_DEPLOY_KEY=DEPLOY_KEY)
        script = ['sh', str(ROOT / 'build/prepare-private-deps.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o700)
        for key, content in (('federated_key', value + '\n'), ('lib_key', DEPLOY_KEY + '\n')):
            path = self.secrets / key
            self.assertEqual(path.read_text(), content)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for name in ('FEDERATED_SIGNER_PROTO_DEPLOY_KEY', 'RGB_LIB_BFA_DEPLOY_KEY'):
            with self.subTest(missing=name):
                result = subprocess.run(script, env=dict(env, **{name: ''}),
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Missing {name}', result.stderr)
                self.assertNotIn(value, result.stdout + result.stderr)
                self.assertNotIn(DEPLOY_KEY, result.stdout + result.stderr)

    def test_ci_access_adds_deploy_key_to_ssh(self):
        home = self.base / 'home'
        home.mkdir()
        env = dict(self.env, HOME=str(home),
                   GIT_CONFIG_GLOBAL=str(home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1',
                   RGB_LIB_BFA_DEPLOY_KEY=DEPLOY_KEY)
        script = ['sh', str(ROOT / 'build/ci-rgb-lib-access.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        ssh_dir = home / '.ssh'
        key_file = ssh_dir / 'key_lib'
        self.assertTrue(key_file.exists())
        self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key_file.read_text(), DEPLOY_KEY + '\n')
        ssh_config = (ssh_dir / 'config').read_text()
        self.assertIn('Host github-rgb-lib', ssh_config)
        self.assertIn('IdentityFile', ssh_config)
        self.assertIn('key_lib', ssh_config)
        result = subprocess.run(script, env=dict(env, RGB_LIB_BFA_DEPLOY_KEY=''),
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing RGB_LIB_BFA_DEPLOY_KEY', result.stderr)

    def test_every_dockerfile_builds_through_its_secret_scope(self):
        for path in (ROOT / 'build').glob('Dockerfile*'):
            with self.subTest(dockerfile=path.name):
                data = path.read_text()
                self.assertIn('--mount=type=secret,id=lib_key', data)
                self.assertNotIn('RUN cargo build', data)
                self.assertIn('git ca-certificates', data.split('COPY . /build/')[0])
                if path.name == 'Dockerfile.parent':
                    self.assertIn('sh /build/build/with-private-deps.sh parent cargo build', data)
                    self.assertIn('--mount=type=secret,id=federated_key', data)
                    self.assertIn('openssh-client', data.split('COPY . /build/')[0])
                else:
                    self.assertIn('sh /build/build/with-private-deps.sh enclave cargo build', data)
                    self.assertNotIn('federated_key', data)


if __name__ == '__main__':
    unittest.main()
