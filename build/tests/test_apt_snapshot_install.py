"""Exercise acquisition retries and fail-closed installation without root/network."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'apt-snapshot-install.sh'


class SnapshotInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.log = self.base / 'calls.jsonl'
        apt = self.base / 'apt-get'
        apt.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_DIR'])
args = sys.argv[1:]
phase = ('plan' if '--print-uris' in args else
         'update' if 'update' in args else
         'download' if '--download-only' in args else 'install')
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps([phase, args]) + '\\n')
counter = root / phase
n = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(n))
if phase == 'plan':
    print(os.environ.get('URI_PLAN', ''))
if phase == 'download':
    # A successful partial download must survive the next attempt.
    cached = root / 'downloaded.deb'
    if n > 1 and cached.read_text() != 'verified fixture':
        sys.exit(99)
    cached.write_text('verified fixture')
if phase == 'install':
    if '--no-download' not in args or not (root / 'downloaded.deb').exists():
        sys.exit(99)
if n <= int(os.environ.get(phase.upper() + '_FAILURES', '0')):
    sys.exit(int(os.environ.get('FAILURE_CODE', '100')))
''')
        apt.chmod(0o700)
        sleep = self.base / 'sleep'
        sleep.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ['FIXTURE_DIR']) / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(['sleep', sys.argv[1:]]) + '\\n')
''')
        sleep.chmod(0o700)
        helper = self.base / 'apt-helper'
        helper.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ['FIXTURE_DIR']) / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(['cdn', sys.argv[1:]]) + '\\n')
sys.exit(int(os.environ.get('CDN_STATUS', '0')))
''')
        helper.chmod(0o700)
        move = self.base / 'mv'
        move.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
with (pathlib.Path(os.environ['FIXTURE_DIR']) / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(['publish', sys.argv[1:]]) + '\\n')
''')
        move.chmod(0o700)

    def invoke(self, packages=('openssl', 'ca-certificates'), **extra):
        env = dict(os.environ, PATH=f'{self.base}:{os.environ["PATH"]}',
                   FIXTURE_DIR=str(self.base), UPDATE_FAILURES='0',
                   DOWNLOAD_FAILURES='0', INSTALL_FAILURES='0', FAILURE_CODE='100')
        env.update(extra)
        result = subprocess.run(['sh', str(HELPER), *packages], env=env,
                                capture_output=True, text=True, timeout=10)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] \
            if self.log.exists() else []
        return result, calls

    def test_transient_errors_retry_fetches_then_install_once(self):
        result, calls = self.invoke(UPDATE_FAILURES='1', DOWNLOAD_FAILURES='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([phase for phase, _ in calls], [
            'update', 'sleep', 'update', 'download', 'sleep', 'download',
            'sleep', 'download', 'install',
        ])
        self.assertEqual([args for phase, args in calls if phase == 'sleep'],
                         [['30'], ['30'], ['60']])
        for phase, args in calls:
            if phase in ('update', 'download'):
                self.assertIn('Acquire::Retries=0', args)
            if phase == 'update':
                self.assertIn('APT::Update::Error-Mode=any', args)
            if phase in ('download', 'install'):
                self.assertEqual(args[-2:], ['openssl', 'ca-certificates'])
                self.assertIn('--no-install-recommends', args)
            self.assertNotIn('--fix-missing', args)
            self.assertNotIn('--allow-unauthenticated', args)

    def test_persistent_fetch_failure_never_installs(self):
        for phase in ('update', 'download'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                # Each subcase uses fresh counters/logs; stubs remain on PATH.
                result, _ = self.invoke(FIXTURE_DIR=directory,
                                       **{phase.upper() + '_FAILURES': '99'})
                calls = [json.loads(line) for line in
                         (Path(directory) / 'calls.jsonl').read_text().splitlines()]
                self.assertEqual(result.returncode, 100, result.stderr)
                self.assertEqual(sum(p == phase for p, _ in calls), 4)
                self.assertEqual([args for p, args in calls if p == 'sleep'],
                                 [['30'], ['60'], ['120']])
                self.assertNotIn('install', [p for p, _ in calls])
                if phase == 'update':
                    self.assertNotIn('download', [p for p, _ in calls])

    def test_killed_fetch_is_not_retried(self):
        result, calls = self.invoke(DOWNLOAD_FAILURES='1', FAILURE_CODE='137')
        self.assertEqual(result.returncode, 137)
        self.assertEqual([phase for phase, _ in calls], ['update', 'download'])

    def test_installation_failure_is_not_retried(self):
        result, calls = self.invoke(INSTALL_FAILURES='1')
        self.assertEqual(result.returncode, 100)
        self.assertEqual([phase for phase, _ in calls], ['update', 'download', 'install'])

    def plan(self, archive='debian', digest=None, filename='fixture_1_amd64.deb'):
        digest = digest or 'SHA256:' + 'a' * 64
        return (f"'https://snapshot.debian.org/archive/{archive}/20261007T000000Z/"
                f"pool/main/f/fixture/{filename}' {filename} 123 {digest}")

    def test_cdn_fallback_keeps_snapshot_versions_and_sha256(self):
        plan = '\n'.join([self.plan(), self.plan('debian-security')])
        result, calls = self.invoke(DOWNLOAD_FAILURES='99', URI_PLAN=plan)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(p == 'update' for p, _ in calls), 1)
        self.assertEqual(sum(p == 'download' for p, _ in calls), 4)
        self.assertEqual(sum(p == 'install' for p, _ in calls), 1)
        self.assertIn('Acquire::ForceHash=SHA256',
                      next(args for p, args in calls if p == 'plan'))
        cdn = [args for p, args in calls if p == 'cdn']
        self.assertEqual(len(cdn), 2)
        for archive, args in zip(('debian', 'debian-security'), cdn):
            self.assertEqual(args[-3:], [
                f'https://deb.debian.org/{archive}/pool/main/f/fixture/fixture_1_amd64.deb',
                '/var/cache/apt/archives/partial/fixture_1_amd64.deb', 'SHA256:' + 'a' * 64])
            self.assertIn('Acquire::Retries=0', args)
        self.assertIn('--no-download', calls[-1][1])

    def test_cdn_failure_or_hash_mismatch_never_installs(self):
        result, calls = self.invoke(DOWNLOAD_FAILURES='99', URI_PLAN=self.plan(),
                                    CDN_STATUS='100')
        self.assertEqual(result.returncode, 100)
        self.assertNotIn('install', [p for p, _ in calls])
        self.assertNotIn('publish', [p for p, _ in calls])

    def test_invalid_plan_is_rejected_before_cdn_download(self):
        plans = [self.plan(digest='MD5Sum:' + 'a' * 32),
                 self.plan(digest='SHA256:abc'),
                 self.plan(filename='../escape.deb'),
                 self.plan().replace('snapshot.debian.org', 'untrusted.example'),
                 self.plan() + ' extra']
        for plan in plans:
            with self.subTest(plan=plan), tempfile.TemporaryDirectory() as directory:
                result, _ = self.invoke(FIXTURE_DIR=directory,
                                       DOWNLOAD_FAILURES='99', URI_PLAN=plan)
                calls = [json.loads(line) for line in
                         (Path(directory) / 'calls.jsonl').read_text().splitlines()]
                self.assertEqual(result.returncode, 100, result.stderr)
                self.assertNotIn('cdn', [p for p, _ in calls])
                self.assertNotIn('install', [p for p, _ in calls])


if __name__ == '__main__':
    unittest.main()
