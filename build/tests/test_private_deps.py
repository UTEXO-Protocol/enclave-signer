"""Credential routing and cleanup tests; no private credentials or network needed."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# The parent's proto deploy key. The rgb-lib mirror of both workspaces is
# read with github_token.
ALIASES = {
    'github-federated-signer': 'federated_key',
}
TOKEN = 'fixture-token-not-a-real-credential'


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
            path.write_text('fixture-private-key-not-a-real-credential\n')
            path.chmod(0o600)

    def token(self):
        (self.secrets / 'github_token').write_text(TOKEN)

    def manifest_urls(self, pattern):
        sources = '\n'.join((ROOT / p).read_text() for p in
                            ['Cargo.toml', 'enclave/Cargo.toml', 'parent/Cargo.toml'])
        return sorted(set(re.findall(pattern, sources)))

    def test_each_ssh_alias_selects_only_its_repo_key(self):
        self.keys()
        self.token()
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
        self.keys()
        self.token()
        result = self.run_auth('tools', 'print("must not start")')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid dependency scope', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_missing_or_empty_token_refuses_before_build(self):
        self.keys()
        for scope in ('parent', 'enclave'):
            for token in (None, ''):
                with self.subTest(scope=scope, token=token):
                    path = self.secrets / 'github_token'
                    path.unlink(missing_ok=True)
                    if token is not None:
                        path.write_text(token)
                    result = self.run_auth(scope, 'print("must not start")')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('github_token', result.stderr)
                    self.assertIn('rgb-lib-bfa', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_token_reads_the_rgb_lib_mirror_without_embedding_token(self):
        self.token()
        urls = self.manifest_urls(r'"(https://github\.com/UTEXO-Protocol/[^"]+)"')
        self.assertIn('https://github.com/UTEXO-Protocol/rgb-lib-bfa.git', urls)
        for scope in ('parent', 'enclave'):
            with self.subTest(scope=scope):
                result = self.run_auth(scope, f'''
for url in {urls!r}:
    actual = subprocess.check_output(['git', 'ls-remote', '--get-url', url], text=True).strip()
    assert actual == url.replace('https://', 'https://x-access-token@'), actual
config = pathlib.Path(os.environ['GIT_CONFIG_GLOBAL'])
assert {TOKEN!r} not in config.read_text()
password = subprocess.check_output([os.environ['GIT_ASKPASS'], 'Password:'], text=True)
assert password == {TOKEN!r}
print(str(config))
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(TOKEN, result.stdout + result.stderr)
                self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_token_reads_the_proto_without_a_deploy_key(self):
        self.token()
        urls = self.manifest_urls(r'"(ssh://git@github-[^"]+)"')
        self.assertEqual(len(urls), 1)
        result = self.run_auth('parent', f'''
for url in {urls!r}:
    actual = subprocess.check_output(['git', 'ls-remote', '--get-url', url], text=True).strip()
    expected = 'https://x-access-token@github.com/UTEXO-Protocol/' + url.split('/UTEXO-Protocol/')[1]
    assert actual == expected, (actual, expected)
assert 'GIT_SSH_COMMAND' not in os.environ
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_deploy_key_keeps_reading_the_proto_beside_the_token(self):
        self.keys()
        self.token()
        urls = self.manifest_urls(r'"(ssh://git@github-[^"]+)"')
        for scope, has_key in (('parent', True), ('enclave', False)):
            with self.subTest(scope=scope):
                result = self.run_auth(scope, f'''
for url in {urls!r}:
    actual = subprocess.check_output(['git', 'ls-remote', '--get-url', url], text=True).strip()
    assert actual == url, actual
assert ('GIT_SSH_COMMAND' in os.environ) == {has_key!r}
''')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_command_preserves_status_and_cleans_config(self):
        self.keys()
        self.token()
        result = self.run_auth('parent', 'print(os.environ["GIT_CONFIG_GLOBAL"]); raise SystemExit(42)')
        self.assertEqual(result.returncode, 42)
        self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_prepare_keys_preserves_multiline_values_and_restricts_permissions(self):
        value = "fixture first line\nfixture second line"
        env = dict(self.env, FEDERATED_SIGNER_PROTO_DEPLOY_KEY=value, RGB_LIB_BFA_TOKEN=TOKEN)
        script = ['sh', str(ROOT / 'build/prepare-private-deps.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o700)
        for key, content in (('federated_key', value + '\n'), ('github_token', TOKEN)):
            path = self.secrets / key
            self.assertEqual(path.read_text(), content)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for name in ('FEDERATED_SIGNER_PROTO_DEPLOY_KEY', 'RGB_LIB_BFA_TOKEN'):
            with self.subTest(missing=name):
                result = subprocess.run(script, env=dict(env, **{name: ''}),
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Missing {name}', result.stderr)
                self.assertNotIn(value, result.stdout + result.stderr)
                self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_ci_access_answers_git_with_the_token_file(self):
        home = self.base / 'home'
        home.mkdir()
        env = dict(self.env, HOME=str(home), RUNNER_TEMP=str(self.base),
                   GIT_CONFIG_GLOBAL=str(home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1',
                   RGB_LIB_BFA_TOKEN=TOKEN)
        script = ['sh', str(ROOT / 'build/ci-rgb-lib-access.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertNotIn(TOKEN, (home / '.gitconfig').read_text())
        self.assertEqual((self.base / 'rgb-lib-bfa-credential.token').stat().st_mode & 0o777, 0o600)
        fill = subprocess.run(
            ['git', 'credential', 'fill'], env=dict(env, GIT_TERMINAL_PROMPT='0'),
            input='protocol=https\nhost=github.com\npath=UTEXO-Protocol/rgb-lib-bfa.git\n\n',
            capture_output=True, text=True)
        self.assertEqual(fill.returncode, 0, fill.stderr)
        self.assertIn(f'password={TOKEN}\n', fill.stdout)
        self.assertIn('username=x-access-token\n', fill.stdout)
        result = subprocess.run(script, env=dict(env, RGB_LIB_BFA_TOKEN=''),
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing RGB_LIB_BFA_TOKEN', result.stderr)

    def test_every_dockerfile_builds_through_its_secret_scope(self):
        for path in (ROOT / 'build').glob('Dockerfile*'):
            with self.subTest(dockerfile=path.name):
                data = path.read_text()
                self.assertIn('--mount=type=secret,id=github_token', data)
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
