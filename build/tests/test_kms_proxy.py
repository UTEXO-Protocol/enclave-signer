"""Provision only a temporary fake host; never invoke real systemd or Nitro."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class KmsProxyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kms-proxy-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.etc = self.base / 'etc'
        (self.etc / 'systemd/system').mkdir(parents=True)
        self.calls = self.base / 'calls'
        proxy = self.base / 'vsock-proxy'
        proxy.write_text('#!/bin/sh\nexit 90\n')
        proxy.chmod(0o755)
        systemctl = self.base / 'systemctl'
        systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                            '[ "$1" != is-active ] || [ "${PROXY_FAILED:-0}" != 1 ]\n')
        systemctl.chmod(0o755)
        self.script = self.base / 'prepare.sh'
        self.script.write_text((ROOT / 'deploy/host-prep-kms.sh').read_text()
                               .replace('/etc/', str(self.etc) + '/')
                               .replace('/usr/bin/vsock-proxy', str(proxy)))
        self.env = dict(PATH=f'{self.base}:{os.environ["PATH"]}', CALLS=str(self.calls),
                        KMS_REGION='eu-central-1')

    def invoke(self, **extra):
        return subprocess.run(['bash', str(self.script)], env=dict(self.env, **extra),
                              capture_output=True, text=True, timeout=10)

    def test_initial_setup_and_repeat_do_not_restart_or_redirect_proxy(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        before = {p: p.read_bytes() for p in self.etc.rglob('*') if p.is_file()}
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('restart', self.calls.read_text())
        self.assertNotIn('stop', self.calls.read_text())
        calls = self.calls.read_bytes()
        result = self.invoke(KMS_REGION='eu-west-1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls.read_bytes(), calls)
        for path, data in before.items(): self.assertEqual(path.read_bytes(), data)

    def test_proxy_failure_is_not_reported_as_success(self):
        self.assertNotEqual(self.invoke(PROXY_FAILED='1').returncode, 0)

    def test_noncommercial_or_injected_region_is_rejected_before_writes(self):
        for value in ('cn-north-1', 'us-gov-west-1', 'us-iso-east-1', 'eu-central-1;id'):
            self.assertNotEqual(self.invoke(KMS_REGION=value).returncode, 0)
            self.assertFalse(self.calls.exists())
            self.assertFalse((self.etc / 'nitro_enclaves').exists())


if __name__ == '__main__':
    unittest.main()
