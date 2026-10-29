"""Credential routing and cleanup tests; no private credentials or network needed."""
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Each private dep uses a per-repo SSH Host alias. IdentitiesOnly yes ensures
# GitHub accepts exactly the right key per connection.
ALIASES = {
    'github-rgb-lib': 'lib_key',
    'github-federated-signer': 'federated_key',
}
DEPLOY_KEY = 'fixture-private-key-not-a-real-credential'
MIRROR_TOKEN = 'fixture-mirror-token-not-a-real-credential'
# rgb-lib's [patch.crates-io] repos, each mapped to UTEXO-Protocol/<repo>-s-bfa.
PROTOCOL_REPOS = ('rgb-consensus', 'rgb-ops', 'rgb-api', 'rgb-schemas')


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
        # No system git helper may answer for the mirrors on a dev machine.
        self.env = dict(os.environ, PRIVATE_DEPS_DIR=str(self.secrets),
                        PATH=f'{self.bin}:{os.environ["PATH"]}', GIT_CONFIG_NOSYSTEM='1')

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
        self.secret('rgb_deps_token', f'{MIRROR_TOKEN}\n')

    def lib_key(self):
        self.secret('lib_key', f'{DEPLOY_KEY}\n')
        self.secret('rgb_deps_token', f'{MIRROR_TOKEN}\n')

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

    def test_missing_or_empty_mirror_token_refuses_before_build(self):
        for scope in ('parent', 'enclave'):
            for content in (None, ''):
                with self.subTest(scope=scope, content=content):
                    self.lib_key()
                    path = self.secrets / 'rgb_deps_token'
                    path.unlink()
                    if content is not None:
                        path.write_text(content)
                    result = self.run_auth(scope, 'print("must not start")')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('rgb_deps_token', result.stderr)
                    self.assertIn('RGB_PRIVATE_DEPS_TOKEN', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_both_scopes_fetch_the_protocol_crates_from_our_mirrors(self):
        self.keys()
        for scope in ('parent', 'enclave'):
            with self.subTest(scope=scope):
                result = self.run_auth(scope, f'''
for repo in {PROTOCOL_REPOS!r}:
    mirror = f'https://github.com/UTEXO-Protocol/{{repo}}-s-bfa.git'
    url = subprocess.check_output(['git', 'ls-remote', '--get-url',
                                   f'ssh://git@github.com/rgb-tools-devs/{{repo}}.git'], text=True)
    assert url.strip() == mirror, url
    filled = subprocess.run(['git', 'credential', 'fill'], input=f'url={{mirror}}\\n\\n',
                            capture_output=True, text=True)
    assert 'password={MIRROR_TOKEN}\\n' in filled.stdout, 'no token for ' + mirror
    assert {MIRROR_TOKEN!r} not in open(os.environ['GIT_CONFIG_GLOBAL']).read()
print(os.environ['GIT_CONFIG_GLOBAL'])
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(MIRROR_TOKEN, result.stdout + result.stderr)
                self.assertFalse(Path(result.stdout.strip()).parent.exists())

    def test_the_mirror_token_goes_to_the_mirrors_only(self):
        self.keys()
        result = self.run_auth('enclave', '''
for url in ('https://github.com/UTEXO-Protocol/rgb-lib-bfa.git',
            'https://github.com/rgb-protocol/rgb-strict-types',
            'https://example.com/UTEXO-Protocol/rgb-ops-s-bfa.git'):
    filled = subprocess.run(['git', 'credential', 'fill'], input=f'url={url}\\n\\n',
                            capture_output=True, text=True)
    assert 'password=' not in filled.stdout, url
''')
        self.assertEqual(result.returncode, 0, result.stderr)

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
                   RGB_LIB_BFA_DEPLOY_KEY=DEPLOY_KEY, RGB_PRIVATE_DEPS_TOKEN=MIRROR_TOKEN)
        script = ['sh', str(ROOT / 'build/prepare-private-deps.sh')]
        result = subprocess.run(script, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, '')
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o700)
        for key, content in (('federated_key', value + '\n'), ('lib_key', DEPLOY_KEY + '\n'),
                             ('rgb_deps_token', MIRROR_TOKEN + '\n')):
            path = self.secrets / key
            self.assertEqual(path.read_text(), content)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for name in ('FEDERATED_SIGNER_PROTO_DEPLOY_KEY', 'RGB_LIB_BFA_DEPLOY_KEY',
                     'RGB_PRIVATE_DEPS_TOKEN'):
            with self.subTest(missing=name):
                result = subprocess.run(script, env=dict(env, **{name: ''}),
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Missing {name}', result.stderr)
                self.assertNotIn(value, result.stdout + result.stderr)
                self.assertNotIn(DEPLOY_KEY, result.stdout + result.stderr)
                self.assertNotIn(MIRROR_TOKEN, result.stdout + result.stderr)

    def test_ci_access_adds_deploy_key_to_ssh(self):
        home = self.base / 'home'
        home.mkdir()
        env = dict(self.env, HOME=str(home),
                   GIT_CONFIG_GLOBAL=str(home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1',
                   RGB_LIB_BFA_DEPLOY_KEY=DEPLOY_KEY, RGB_PRIVATE_DEPS_TOKEN=MIRROR_TOKEN)
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
        for name in ('RGB_LIB_BFA_DEPLOY_KEY', 'RGB_PRIVATE_DEPS_TOKEN'):
            result = subprocess.run(script, env=dict(env, **{name: ''}),
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f'Missing {name}', result.stderr)

    def test_ci_access_maps_the_protocol_crates_to_our_mirrors(self):
        home = self.base / 'home'
        home.mkdir()
        env = dict(self.env, HOME=str(home), GIT_TERMINAL_PROMPT='0',
                   GIT_CONFIG_GLOBAL=str(home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1',
                   RGB_LIB_BFA_DEPLOY_KEY=DEPLOY_KEY, RGB_PRIVATE_DEPS_TOKEN=MIRROR_TOKEN)
        result = subprocess.run(['sh', str(ROOT / 'build/ci-rgb-lib-access.sh')], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(MIRROR_TOKEN, (home / '.gitconfig').read_text())
        token = home / '.rgb-private-deps/token'
        self.assertEqual(token.stat().st_mode & 0o777, 0o600)
        for repo in PROTOCOL_REPOS:
            mirror = f'https://github.com/UTEXO-Protocol/{repo}-s-bfa.git'
            url = subprocess.check_output(
                ['git', 'ls-remote', '--get-url', f'ssh://git@github.com/rgb-tools-devs/{repo}.git'],
                env=env, text=True)
            self.assertEqual(url.strip(), mirror)
            filled = subprocess.run(['git', 'credential', 'fill'], input=f'url={mirror}\n\n',
                                    env=env, capture_output=True, text=True)
            self.assertIn(f'password={MIRROR_TOKEN}\n', filled.stdout)

    def test_every_dockerfile_builds_through_its_secret_scope(self):
        for path in (ROOT / 'build').glob('Dockerfile*'):
            with self.subTest(dockerfile=path.name):
                data = path.read_text()
                self.assertIn('--mount=type=secret,id=lib_key', data)
                self.assertIn('--mount=type=secret,id=rgb_deps_token', data)
                self.assertNotIn('RUN cargo build', data)
                self.assertIn('git ca-certificates', data.split('COPY . /build/')[0])
                if path.name == 'Dockerfile.parent':
                    self.assertIn('sh /build/build/with-private-deps.sh parent cargo build', data)
                    self.assertIn('--mount=type=secret,id=federated_key', data)
                    self.assertIn('openssh-client', data.split('COPY . /build/')[0])
                else:
                    self.assertIn('sh /build/build/with-private-deps.sh enclave cargo build', data)
                    self.assertNotIn('federated_key', data)


class PatchTests(unittest.TestCase):
    """The parent compiles the enclave too, so it needs the root's RGB crate revs."""

    def patch(self, manifest):
        with open(ROOT / manifest, 'rb') as f:
            return tomllib.load(f)['patch']['crates-io']

    def test_the_parent_patches_the_rgb_crates_as_the_root_does(self):
        root = self.patch('Cargo.toml')
        # Only bfa-mint uses rgb-psbt-utils; the parent's enclave build has no bfa-mint.
        expected = {name: source for name, source in root.items() if name != 'rgb-psbt-utils'}
        self.assertEqual(self.patch('parent/Cargo.toml'), expected)

    def test_no_lock_takes_a_patched_crate_from_the_registry(self):
        # A crate the parent's patch leaves out would silently come from crates.io.
        names = self.patch('Cargo.toml').keys()
        for lock in ('Cargo.lock', 'parent/Cargo.lock'):
            with open(ROOT / lock, 'rb') as f:
                packages = tomllib.load(f)['package']
            for package in packages:
                if package['name'] in names:
                    with self.subTest(lock=lock, crate=package['name']):
                        self.assertTrue(package.get('source', '').startswith('git+'), package)

    def test_the_private_crates_come_from_the_repos_the_mirrors_map(self):
        for name, source in self.patch('Cargo.toml').items():
            with self.subTest(crate=name):
                self.assertRegex(source['rev'], r'^[0-9a-f]{40}$')
                if source['git'].startswith('ssh://'):
                    repo = source['git'].removeprefix('ssh://git@github.com/rgb-tools-devs/')
                    self.assertIn(repo.removesuffix('.git'), PROTOCOL_REPOS)


class CacheTests(unittest.TestCase):
    """This repo is public, and fork PRs can restore its CI caches."""

    def test_no_cargo_cache_holds_the_private_sources(self):
        blocks = (ROOT / '.github/workflows/ci.yml').read_text().split('uses: actions/cache@')[1:]
        self.assertTrue(blocks)
        for no, block in enumerate(blocks):
            paths = [line.strip() for line in block.split('key:')[0].splitlines()]
            with self.subTest(cache=no):
                # tar packs a listed directory whole, excludes below it included.
                self.assertNotIn('~/.cargo/git', paths)
                for repo in ('rgb-lib-bfa',) + PROTOCOL_REPOS:
                    self.assertIn(f'!~/.cargo/git/*/{repo}-*', paths)

    def test_no_image_cache_exports_the_builder_stage(self):
        cd = (ROOT / '.github/workflows/cd-reusable.yml').read_text()
        self.assertIn('cache-to:', cd)
        self.assertNotIn('mode=max', cd)


if __name__ == '__main__':
    unittest.main()
