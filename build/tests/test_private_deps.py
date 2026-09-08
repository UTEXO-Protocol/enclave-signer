"""Credential routing and cleanup tests; no private credentials or network needed."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ALIASES = {
    'github-rgb-consignment': 'consignment_key',
    'github-rgb-consensus': 'consensus_key',
    'github-rgb-ops': 'ops_key',
    'github-rgb-schemas': 'schemas_key',
    'github-federated-signer': 'federated_key',
}


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

    def keys(self, parent=True):
        for key in ALIASES.values():
            if key == 'federated_key' and not parent:
                continue
            path = self.secrets / key
            path.write_text('fixture-private-key-not-a-real-credential\n')
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

    def test_enclave_does_not_need_proto_key(self):
        self.keys(parent=False)
        result = self.run_auth('enclave', 'print("started")')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_auth('parent', 'print("must not start")')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('federated_key', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_missing_or_empty_key_refuses_before_build(self):
        self.keys()
        (self.secrets / 'ops_key').write_text('')
        result = self.run_auth('enclave', 'print("must not start")')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ops_key', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_token_rewrites_actual_manifest_urls_without_embedding_token(self):
        token = 'fixture-token-not-a-real-credential'
        (self.secrets / 'github_token').write_text(token)
        sources = '\n'.join((ROOT / p).read_text() for p in
                            ['Cargo.toml', 'enclave/Cargo.toml', 'parent/Cargo.toml'])
        urls = sorted(set(re.findall(r'"(ssh://git@github-[^"]+)"', sources)))
        self.assertGreaterEqual(len(urls), 5)
        result = self.run_auth('parent', f'''
for url in {urls!r}:
    actual = subprocess.check_output(['git', 'ls-remote', '--get-url', url], text=True).strip()
    expected = 'https://x-access-token@github.com/UTEXO-Protocol/' + url.split('/UTEXO-Protocol/')[1]
    assert actual == expected, (actual, expected)
config = pathlib.Path(os.environ['GIT_CONFIG_GLOBAL'])
assert {token!r} not in config.read_text()
password = subprocess.check_output([os.environ['GIT_ASKPASS'], 'Password:'], text=True)
assert password == {token!r}
print(str(config))
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_failed_command_preserves_status_and_cleans_config(self):
        self.keys()
        result = self.run_auth('parent', 'print(os.environ["GIT_CONFIG_GLOBAL"]); raise SystemExit(42)')
        self.assertEqual(result.returncode, 42)
        self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_prepare_keys_preserves_multiline_values_and_restricts_permissions(self):
        mapping = {
            'RGB_CONSIGNMENT_PARSER_DEPLOY_KEY': 'consignment_key',
            'RGB_CONSENSUS_BFA_DEPLOY_KEY': 'consensus_key',
            'RGB_OPS_BFA_DEPLOY_KEY': 'ops_key',
            'RGB_SCHEMAS_BFA_DEPLOY_KEY': 'schemas_key',
            'FEDERATED_SIGNER_PROTO_DEPLOY_KEY': 'federated_key',
        }
        value = "fixture first line\nfixture second line"
        env = dict(self.env, **{name: value for name in mapping})
        script = ['sh', str(ROOT / 'build/prepare-private-deps.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o700)
        for key in mapping.values():
            path = self.secrets / key
            self.assertEqual(path.read_text(), value + '\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        env['RGB_OPS_BFA_DEPLOY_KEY'] = ''
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing RGB_OPS_BFA_DEPLOY_KEY', result.stderr)
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_all_dockerfiles_mount_the_required_keys(self):
        for path in (ROOT / 'build').glob('Dockerfile*'):
            with self.subTest(dockerfile=path.name):
                data = path.read_text()
                scope = 'parent' if path.name == 'Dockerfile.parent' else 'enclave'
                self.assertIn(f'sh /build/build/with-private-deps.sh {scope} cargo build', data)
                self.assertIn('--mount=type=secret,id=github_token', data)
                for key in ALIASES.values():
                    if key == 'federated_key' and scope == 'enclave':
                        continue
                    self.assertIn('--mount=type=secret,id=' + key, data)
                self.assertIn('openssh-client', data.split('COPY . /build/')[0])


if __name__ == '__main__':
    unittest.main()
