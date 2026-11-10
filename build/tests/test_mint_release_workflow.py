"""Exercise the release SSM payload with fake AWS; never contact a host."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import textwrap

ROOT = Path(__file__).resolve().parents[2]


class MintReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mint-workflow-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.workflow = (ROOT / '.github/workflows/release-eif.yml').read_text()
        self.step = self.workflow.split('      - name: Deploy to hosts via SSM\n', 1)[1].split('      - name: Summary', 1)[0]
        run = textwrap.dedent(self.step.split('        run: |\n', 1)[1])
        self.script = self.base / 'step.sh'
        self.script.write_text(run.replace('/tmp/deploy-run.sh', str(self.base / 'payload.sh')))
        aws = self.base / 'aws'
        aws.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['TEST_ROOT'])
with (root / 'calls').open('a') as f: f.write(json.dumps(args) + '\\n')
if args[1] == 'send-command':
    (root / 'parameters').write_text(args[args.index('--parameters') + 1])
    print('test-command-id')
elif args[args.index('--query') + 1] == 'Status': print('Success')
''')
        aws.chmod(0o755)
        self.env = dict(PATH=f'{self.base}:{os.environ["PATH"]}', TEST_ROOT=str(self.base),
                        GIT_SHA='a' * 40, SIGNER_ROLE='mint', ENCLAVE_CID='24',
                        BUCKET='test-artifacts', REGION='eu-north-1', CLUSTER_DIR='/opt/test-release',
                        DEPLOY_CONFIG_FILE='/etc/utexo/release-config/mint-24.json',
                        MINT_MODE='recovery', DEPLOY_ENVIRONMENT='release-test',
                        TEST_REGION='eu-north-1', TEST_BUCKET='isolated-artifacts',
                        TEST_CLUSTER_DIR='/opt/isolated-release',
                        INSTANCES_INPUT='i-test-only', INSTANCES_SECRET='i-stage-do-not-use')

    def run_step(self, **extra):
        return subprocess.run(['bash', str(self.script)], cwd=ROOT, env=dict(self.env, **extra),
                              capture_output=True, text=True, timeout=20)

    def test_payload_forwards_mint_config_mode_cid_without_stage_fallback(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        parameters = (self.base / 'parameters').read_text()
        encoded = parameters.split('echo ', 1)[1].split(' |', 1)[0]
        payload = base64.b64decode(encoded).decode()
        for line in ('export ENCLAVE_CID=24', 'export MINT_MODE=recovery',
                     'export DEPLOY_CONFIG_FILE=/etc/utexo/release-config/mint-24.json',
                     'export AWS_REGION=eu-north-1', 'export BUCKET=isolated-artifacts',
                     'export CLUSTER_DIR=/opt/isolated-release'):
            self.assertIn(line + '\n', payload)
        calls = (self.base / 'calls').read_text()
        self.assertIn('i-test-only', calls)
        self.assertNotIn('i-stage-do-not-use', calls)
        self.assertIn('DEPLOY_CONFIG_FILE: ${{ inputs.deployment_config }}', self.step)
        self.assertIn('environment: ${{ inputs.deployment_environment }}', self.workflow)

    def test_missing_config_or_test_target_fails_before_ssm(self):
        for extra in ({'DEPLOY_CONFIG_FILE': ''}, {'INSTANCES_INPUT': ''}, {'TEST_BUCKET': ''}, {'TEST_REGION': ''}):
            with self.subTest(extra=extra):
                result = self.run_step(**extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.base / 'calls').exists())


if __name__ == '__main__':
    unittest.main()
