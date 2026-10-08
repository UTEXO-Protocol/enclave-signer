"""Deploy wiring tests; stop before any host change."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'deploy/deploy-host.sh'
WORKFLOW = ROOT / '.github/workflows/release-eif.yml'


class DeployHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='deploy-host-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.calls = self.base / 'calls.log'
        for command in ('curl', 'su', 'aws', 'nitro-cli', 'systemctl', 'getent',
                        'groupadd', 'usermod'):
            stub = self.bin / command
            stub.write_text(f'#!/bin/sh\necho {command} >> "{self.calls}"\nexit 99\n')
            stub.chmod(0o700)
        self.cluster = self.base / 'cluster'
        self.env = {k: v for k, v in os.environ.items()
                    if k != 'EVM_NETWORK_IDS' and not k.startswith('KMS_')}
        self.env.update(
            PATH=f'{self.bin}:{os.environ["PATH"]}',
            GIT_SHA='0' * 40,
            BUCKET='test-bucket',
            AWS_REGION='eu-west-1',
            CLUSTER_DIR=str(self.cluster),
            GRPC_HOST='127.0.0.1',
            PARENT_TLS_DIR=str(self.base / 'tls'),
        )

    def invoke(self, ids):
        env = dict(self.env)
        if ids is not None:
            env['EVM_NETWORK_IDS'] = ids
        return subprocess.run(['bash', str(SCRIPT)], env=env,
                              capture_output=True, text=True)

    def test_refuses_bad_evm_network_ids_before_any_change(self):
        for ids in (None, '', 'abc', '1,', '1,,2', '42161, 8453', '4294967296',
                    '99999999999', '1\nGRPC_HOST=0.0.0.0'):
            with self.subTest(ids=ids):
                result = self.invoke(ids)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('EVM_NETWORK_IDS', result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.cluster.exists())

    def test_accepts_u32_network_ids(self):
        for ids in ('42161,8453', '4294967295'):
            with self.subTest(ids=ids):
                result = self.invoke(ids)
                self.assertNotIn('EVM_NETWORK_IDS', result.stderr)
                self.assertIn('provision readable mTLS file', result.stdout)

    def test_every_parent_env_file_carries_evm_network_ids(self):
        text = SCRIPT.read_text()
        match = re.search(r'^for CID in "\$\{CIDS\[@\]\}"; do\n'
                          r'  cat > "/etc/utexo/parent-\$CID\.env" <<EOF\n(.*?)^EOF\ndone$',
                          text, re.M | re.S)
        self.assertIsNotNone(match)
        lines = match.group(1).splitlines()
        self.assertEqual(lines.count('EVM_NETWORK_IDS=$EVM_NETWORK_IDS'), 1)
        self.assertEqual(text.count('/etc/utexo/parent-$CID.env'), 1)

    def test_release_workflow_passes_evm_network_ids_quoted(self):
        text = WORKFLOW.read_text()
        self.assertIn('EVM_NETWORK_IDS: ${{ vars.EVM_NETWORK_IDS }}', text)
        self.assertIn(': "${EVM_NETWORK_IDS:?set repo var EVM_NETWORK_IDS}"', text)
        export = text.find('''printf 'export EVM_NETWORK_IDS=%q\\n' "$EVM_NETWORK_IDS"''')
        self.assertNotEqual(export, -1)
        self.assertLess(export, text.find('cat deploy/deploy-host.sh'))
        self.assertNotIn('echo "export EVM_NETWORK_IDS=', text)


if __name__ == '__main__':
    unittest.main()
