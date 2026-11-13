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

    def secret(self, name, content):
        path = self.secrets / name
        path.write_text(content)
        path.chmod(0o600)

    def keys(self):
        for key in ALIASES.values():
            self.secret(key, f'{DEPLOY_KEY}\n')

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

    def test_missing_or_empty_federated_key_refuses_before_build(self):
        for content in (None, ''):
            with self.subTest(content=content):
                path = self.secrets / 'federated_key'
                path.unlink(missing_ok=True)
                if content is not None:
                    path.write_text(content)
                result = self.run_auth('parent', 'print("must not start")')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('federated_key', result.stderr)
                self.assertIn('federated-signer-proto', result.stderr)
                self.assertEqual(result.stdout, '')

    def test_the_enclave_scope_is_refused(self):
        # The enclave workspace has no private dependency, so it gets no key.
        self.keys()
        result = self.run_auth('enclave', 'print("must not start")')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Invalid dependency scope: enclave', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_failed_command_preserves_status_and_cleans_config(self):
        self.keys()
        result = self.run_auth('parent', 'print(os.environ["GIT_CONFIG_GLOBAL"]); raise SystemExit(42)')
        self.assertEqual(result.returncode, 42)
        self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_prepare_keys_preserves_multiline_values_and_restricts_permissions(self):
        value = "fixture first line\nfixture second line"
        env = dict(self.env, FEDERATED_SIGNER_PROTO_DEPLOY_KEY=value)
        script = ['sh', str(ROOT / 'build/prepare-private-deps.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o700)
        path = self.secrets / 'federated_key'
        self.assertEqual(path.read_text(), value + '\n')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        result = subprocess.run(script, env=dict(env, FEDERATED_SIGNER_PROTO_DEPLOY_KEY=''),
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing FEDERATED_SIGNER_PROTO_DEPLOY_KEY', result.stderr)

    def test_only_the_parent_dockerfile_builds_with_a_secret(self):
        for path in (ROOT / 'build').glob('Dockerfile*'):
            with self.subTest(dockerfile=path.name):
                data = path.read_text()
                self.assertIn('git ca-certificates', data.split('COPY . /build/')[0])
                if path.name == 'Dockerfile.parent':
                    self.assertNotIn('RUN cargo build', data)
                    self.assertIn('sh /build/build/with-private-deps.sh parent cargo build', data)
                    self.assertIn('--mount=type=secret,id=federated_key', data)
                    self.assertIn('openssh-client', data.split('COPY . /build/')[0])
                else:
                    self.assertIn('RUN cargo build', data)
                    self.assertNotIn('--mount=type=secret', data)
                    self.assertNotIn('with-private-deps.sh', data)


class CacheTests(unittest.TestCase):
    """This repo is public, and fork PRs can restore its CI caches."""

    def test_no_cargo_cache_holds_the_private_sources(self):
        # Workflows and the composite actions they call.
        files = sorted(f for f in (ROOT / '.github').rglob('*') if f.suffix in ('.yml', '.yaml'))
        blocks = [
            (f, block)
            for f in files
            for block in f.read_text().split('uses: actions/cache@')[1:]
        ]
        self.assertTrue(blocks)
        for no, (f, block) in enumerate(blocks):
            paths = [line.strip() for line in block.split('key:')[0].splitlines()]
            with self.subTest(file=str(f.relative_to(ROOT)), cache=no):
                # tar packs a listed directory whole, excludes below it included.
                self.assertNotIn('~/.cargo/git', paths)

    def test_no_image_cache_exports_the_builder_stage(self):
        cd = (ROOT / '.github/workflows/cd-reusable.yml').read_text()
        self.assertIn('cache-to:', cd)
        self.assertNotIn('mode=max', cd)


if __name__ == '__main__':
    unittest.main()
