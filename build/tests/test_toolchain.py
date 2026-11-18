"""Profile and observed-builder validation without installing tools on the test host."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'build'))
import toolchain

spec = importlib.util.spec_from_file_location('installer', ROOT / 'build/prepare-ci-builder.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
PROFILE = toolchain.load(ROOT / 'build/toolchain.json')


class ToolchainTests(unittest.TestCase):
    def test_committed_profile_matches_rust_pin(self):
        toolchain.check_rust(PROFILE, ROOT)

    def test_profiles_refuse_floating_missing_unknown_and_zero_inputs(self):
        for key, value in [('buildkit_image', 'moby/buildkit:latest'), ('rust_version', 'stable'),
                           ('nitro_commit', 'v1.4.5'), ('docker_sha256', '0' * 64),
                           ('buildkit_image', 'moby/buildkit@sha256:' + '0' * 64),
                           ('awscli_version', '2.31'), ('buildx_version', 1)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                toolchain.validate(dict(PROFILE, **{key: value}))
        for profile in ({}, dict(PROFILE, token='secret'), None):
            with self.assertRaises(ValueError):
                toolchain.validate(profile)

    def test_rust_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Rust version differs'):
            toolchain.check_rust(dict(PROFILE, rust_version='1.0.0'), ROOT)

    def test_installer_refuses_non_disposable_hosts_before_any_commands(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(sys, 'argv', ['installer', str(ROOT / 'build/toolchain.json')]), \
                patch.object(installer, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'disposable GitHub-hosted'):
                installer.main()
            run.assert_not_called()

    def test_download_mismatch_discards_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'tool'
            with patch.object(installer.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong')):
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    installer.download('https://example.invalid/tool', 'a' * 64, destination)
            self.assertFalse(destination.exists())

    def test_record_checks_actual_versions_and_running_buildkit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            src = root / 'source'
            (src / 'tools').mkdir(parents=True)
            (src / 'tools/Dockerfile').write_text('FROM unpinned:latest\nRUN true\n')
            installer.pin_nitro_base(src / 'tools/Dockerfile', PROFILE['nitro_build_image'])
            blobs = src / 'blobs'
            blobs.mkdir()
            for name in ('bzImage', 'init', 'linuxkit'):
                (blobs / name).write_bytes(b'fixture-blob')
            binary = root / 'nitro-cli'
            binary.write_bytes(b'fixture-binary')
            versions = {
                ('docker', 'version', '--format', '{{.Client.Version}}'): PROFILE['docker_version'],
                ('docker', 'version', '--format', '{{.Server.Version}}'): PROFILE['docker_version'],
                ('docker', 'buildx', 'version'): 'github.com/docker/buildx v' + PROFILE['buildx_version'],
                ('rustc', '--version'): 'rustc ' + PROFILE['rust_version'],
                ('rustup', '--version'): 'rustup ' + PROFILE['rustup_version'],
                ('aws', '--version'): 'aws-cli/' + PROFILE['awscli_version'],
                ('nitro-cli', '--version'): 'Nitro CLI ' + PROFILE['nitro_version'],
                ('git', '-C', str(src), 'rev-parse', 'HEAD'): PROFILE['nitro_commit'],
                ('docker', 'buildx', 'inspect', 'eif-builder', '--bootstrap'): 'running',
                ('docker', 'inspect', 'buildx_buildkit_eif-builder0'): json.dumps([
                    {'Config': {'Image': PROFILE['buildkit_image']}, 'Image': 'sha256:fixture'}]),
                ('docker', 'image', 'inspect', PROFILE['buildkit_image']): json.dumps([{'Id': 'sha256:fixture'}]),
                ('dpkg-query', '-W'): 'fixture-package\t1.0',
            }
            env = {'NITRO_SOURCE_DIR': str(src), 'NITRO_CLI_BLOBS': str(blobs), 'BUILDX_BUILDER': 'eif-builder'}
            destination = root / 'artifacts'
            with patch.dict(os.environ, env), patch.object(toolchain.shutil, 'which', return_value=str(binary)), \
                    patch.object(toolchain, 'output', side_effect=lambda *args: versions[args]):
                toolchain.record(ROOT / 'build/toolchain.json', destination)
                self.assertEqual((destination / 'toolchain.json').read_bytes(), (ROOT / 'build/toolchain.json').read_bytes())
                info = json.loads((destination / 'builder-info.json').read_text())
                self.assertEqual(info['hashes']['blobs/init'], toolchain.digest(blobs / 'init'))
                self.assertIn('builder-info.json', (destination / 'TOOLCHAIN-SHA256SUMS').read_text())
                bad = copy.deepcopy(info)
                bad['versions']['docker_server'] = '999.0.0'
                with self.assertRaisesRegex(ValueError, 'docker_server version'):
                    toolchain.validate_observations(PROFILE, bad)
                versions[('docker', 'image', 'inspect', PROFILE['buildkit_image'])] = json.dumps([{'Id': 'sha256:different'}])
                with self.assertRaisesRegex(ValueError, 'container image differs'):
                    toolchain.record(ROOT / 'build/toolchain.json', root / 'rejected')
                self.assertFalse((root / 'rejected').exists())


if __name__ == '__main__':
    unittest.main()
