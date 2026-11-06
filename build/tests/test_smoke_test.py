"""Lifecycle smoke checks against a scripted parent CLI; no live enclave."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

FAKE_PARENT = '''#!/usr/bin/env python3
import json, os, pathlib, sys
base = pathlib.Path(os.environ["SMOKE_TEST_DIR"])
args = sys.argv[1:]
calls = base / "calls.jsonl"
n = len(calls.read_text().splitlines()) if calls.exists() else 0
with calls.open("a") as log:
    log.write(json.dumps(args) + "\\n")
replies = json.loads((base / "replies.json").read_text())
if len(args) != 3 or args[:2] != ["--addr", "127.0.0.1:5050"] or n >= len(replies) or args[2] != replies[n][0]:
    (base / "unexpected").write_text(f"call {n}: {args}")
    sys.exit(99)
print(replies[n][2])
sys.exit(replies[n][1])
'''


def keys(tag='ab'):
    return '\n'.join([
        '  EVM address:         0x' + tag * 20,
        '  BTC pubkey:          02' + 'cd' * 32,
        '  BTC xpub:            tpub' + 'A' * 107,
        '  Master fingerprint:  12345678',
        '  Account xpub vanilla: tpub' + 'B' * 107,
        '  Account xpub colored: tpub' + 'C' * 107,
        '  EVM gas TX address:  0x' + 'de' * 20,
        '  EVM gas TX pubkey:   04' + 'ef' * 64,
        '  CCD Ed25519 pubkey:  ' + '12' * 32,
    ])


def health(ready=True, endpoints=True, keyed=True, spv=True):
    boolean = lambda value: str(value).lower()
    return ['health', 0 if ready else 1, '\n'.join([
        f'Ready:            {boolean(ready)}',
        f'Endpoints set:    {boolean(endpoints)}',
        f'Key loaded:       {boolean(keyed)}',
        f'SPV synced:       {boolean(spv)}',
        f'Phase:            {"Ready" if keyed else "Initial"}',
        f'SPV tip height:   {100 if spv else 0}',
        f'SPV tip age:      0s (max {600 if spv else 0}s)',
    ])]


def rejected_init():
    return ['init', 1, 'Error: enclave returned error (code 1): already initialized']


def running(spv=True):
    return [health(spv=spv), ['get-keys', 0, keys()], rejected_init(),
            ['get-keys', 0, keys()], health(spv=spv)]


class SmokeTestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='lifecycle-smoke-test-')
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.parent = self.dir / 'parent-cli'
        self.parent.write_text(FAKE_PARENT)
        self.parent.chmod(0o700)

    def run_script(self, replies):
        for name in ('calls.jsonl', 'unexpected'):
            (self.dir / name).unlink(missing_ok=True)
        (self.dir / 'replies.json').write_text(json.dumps(replies))
        env = dict(os.environ, PARENT_BIN=str(self.parent), SMOKE_TEST_DIR=str(self.dir))
        result = subprocess.run(
            ['bash', str(ROOT / 'build/smoke-test.sh'), '--addr=127.0.0.1:5050'],
            env=env, text=True, capture_output=True,
        )
        self.assertFalse((self.dir / 'unexpected').exists(), result.stdout + result.stderr)
        calls = [json.loads(line) for line in (self.dir / 'calls.jsonl').read_text().splitlines()]
        self.assertEqual([call[2] for call in calls], [reply[0] for reply in replies])
        return result

    def assert_failed(self, result, check):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        failures = [line for line in result.stdout.splitlines() if '[FAIL]' in line]
        self.assertEqual(len(failures), 1, result.stdout)
        self.assertIn(check, failures[0])

    def test_fresh_enclave_sets_endpoints_then_initializes_and_retains_identity(self):
        replies = [
            health(ready=False, endpoints=False, keyed=False),
            ['set-endpoints', 0, 'Endpoints set'],
            health(ready=False, keyed=False),
            ['init', 0, 'Keys initialized:\n' + keys()],
            ['get-keys', 0, keys()], rejected_init(), ['get-keys', 0, keys()], health(),
        ]
        result = self.run_script(replies)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('[PASS]', result.stdout)
        self.assertIn('Identity unchanged', result.stdout)

    def test_running_enclave_preserves_endpoints_with_or_without_spv(self):
        for spv in (False, True):
            with self.subTest(spv=spv):
                result = self.run_script(running(spv=spv))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('preserving the launch configuration', result.stdout)
                # The ordered fake rejects any signing or SPV-only RPC.
                self.assertIn('this smoke test checks lifecycle and readiness', result.stdout)

    def test_double_init_requires_the_expected_error_and_exit_status(self):
        wrong_replies = [
            ['init', 1, 'Error: connection failed: Connection refused'],
            ['init', 1, 'Error: enclave returned error (code 1): key not initialized'],
            ['init', 2, rejected_init()[2]],
            ['init', 0, rejected_init()[2]],
            ['init', 0, 'Keys initialized:\n' + keys()],
        ]
        for reply in wrong_replies:
            with self.subTest(reply=reply):
                replies = running()
                replies[2] = reply
                self.assert_failed(self.run_script(replies), 'Double init')

    def test_refusal_does_not_hide_changed_keys(self):
        for changed in (keys('bc'), keys().replace('CCD Ed25519 pubkey:  12', 'CCD Ed25519 pubkey:  34')):
            with self.subTest(changed=changed):
                replies = running()
                replies[3] = ['get-keys', 0, changed]
                self.assert_failed(self.run_script(replies), 'Identity after refused initialization')

    def test_key_read_error_cannot_pass_on_key_shaped_output(self):
        replies = running()
        replies[3] = ['get-keys', 1, keys() + '\nError: connection failed']
        self.assert_failed(self.run_script(replies), 'Identity after refused initialization')

    def test_initialization_response_must_match_public_keys(self):
        replies = [health(ready=False, keyed=False), ['init', 0, keys()],
                   ['get-keys', 0, keys('bc')]]
        self.assert_failed(self.run_script(replies), 'GetPublicKey')

    def test_endpoint_failure_is_not_masked_by_a_later_health_call(self):
        replies = [health(ready=False, endpoints=False, keyed=False),
                   ['set-endpoints', 1, 'Error: connection failed']]
        self.assert_failed(self.run_script(replies), 'SetEndpoints')

    def test_init_failure_stops_before_negative_checks(self):
        replies = [health(ready=False, keyed=False), ['init', 1, 'Error: connection failed']]
        self.assert_failed(self.run_script(replies), 'InitializeKey')

    def test_unrelated_preflight_failure_stops_before_mutation(self):
        self.assert_failed(self.run_script([
            ['health', 1, 'Error: connection failed: Connection refused'],
        ]), 'Health handshake')

    def test_final_not_ready_is_a_failure(self):
        replies = running()
        replies[-1] = health(ready=False, spv=False)
        self.assert_failed(self.run_script(replies), 'Final health/readiness')


if __name__ == '__main__':
    unittest.main()
