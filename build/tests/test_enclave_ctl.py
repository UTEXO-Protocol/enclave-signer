"""Launcher failures must not silently bypass inventory or endpoint checks."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.state = self.path / 'inventory.json'
        self.state.write_text('[]')
        self.calls = self.path / 'calls'
        self.stub('nitro-cli', '''
import json, os, pathlib, sys
args = sys.argv[1:]
state = pathlib.Path(os.environ['STATE'])
with open(os.environ['CALLS'], 'a') as f: f.write(' '.join(args) + '\\n')
if args[0] == 'describe-enclaves':
    print(state.read_text()); sys.exit(int(os.environ.get('INVENTORY_RC', '0')))
if args[0] == 'run-enclave':
    state.write_text(json.dumps([{'EnclaveName':'enclave-16', 'EnclaveID':'enc-fixture', 'EnclaveCID':16}]))
if args[0] == 'terminate-enclave': state.write_text('[]')
''')
        self.stub('cli', '''
import os, sys
with open(os.environ['CALLS'], 'a') as f: f.write(' '.join(sys.argv[1:]) + '\\n')
if sys.argv[-1] == 'health':
    print('Endpoints set: false'); sys.exit(1)
if sys.argv[-1] == 'set-endpoints': sys.exit(int(os.environ.get('ENDPOINT_RC', '0')))
if 'verify-launch' in sys.argv: sys.exit(int(os.environ.get('VERIFY_RC', '0')))
''')
        self.env = dict(os.environ, PATH=f'{self.path}:{os.environ["PATH"]}', STATE=str(self.state), CALLS=str(self.calls),
                        CLI=str(self.path / 'cli'), EIF='/fixture.eif', PCR_FILE='/PCR.json', IMAGE_ENV='/IMAGE-ENV.json',
                        SIGNER_ROLE='burn', ENCLAVE_DEBUG_MODE='0', UTEXO_ENCLAVE_LOCK=str(self.path / 'lock'))

    def stub(self, name, text):
        path = self.path / name
        path.write_text('#!/usr/bin/env python3\n' + text)
        path.chmod(0o755)

    def invoke(self, action='start', **values):
        return subprocess.run(['bash', str(ROOT / 'deploy/systemd/utexo-enclave-ctl.sh'), action, '16'],
                              env=dict(self.env, **values), capture_output=True, text=True, timeout=10)

    def test_inventory_failure_does_not_start_or_terminate(self):
        for action in ('start', 'stop'):
            result = self.invoke(action, INVENTORY_RC='1')
            self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('run-enclave', self.calls.read_text())
        self.assertNotIn('terminate-enclave', self.calls.read_text())

    def test_repeated_start_preserves_existing_enclave(self):
        self.state.write_text('[{"EnclaveName":"enclave-16","EnclaveID":"enc-existing"}]')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('enc-existing', self.state.read_text())
        self.assertNotIn('terminate-enclave', self.calls.read_text())

    def test_failed_endpoints_or_launch_attestation_terminate_new_enclave(self):
        for values in ({'ENDPOINT_RC': '1'}, {'VERIFY_RC': '1'}):
            result = self.invoke(**values)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(self.state.read_text()), [])

    def test_success_configures_then_verifies(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text()
        self.assertLess(calls.index('set-endpoints'), calls.index('verify-launch'))
        self.assertEqual(len(json.loads(self.state.read_text())), 1)
