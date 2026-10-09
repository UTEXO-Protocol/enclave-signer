"""grpc-smoke-test.sh with a fake grpcurl that answers from an ordered script."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

FAKE_GRPCURL = '''#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_DIR"]
args = sys.argv[1:]
method = args[-1].rsplit("/", 1)[-1]
payload = args[args.index("-d") + 1]
with open(os.path.join(d, "log"), "a") as f:
    f.write(json.dumps([args[-1], payload, args[args.index("-proto") + 1]]) + "\\n")
replies = json.load(open(os.path.join(d, "replies.json")))
n = sum(1 for _ in open(os.path.join(d, "log"))) - 1
if n >= len(replies) or replies[n][0] != method:
    open(os.path.join(d, "unexpected"), "a").write(f"call {n}: {method}\\n")
    sys.exit(99)
print(replies[n][2])
sys.exit(replies[n][1])
'''


def ok(method, field):
    return [method, 0, '{\n  "%s": "AA=="\n}' % field]


def err(method, code, message):
    return [method, 1, f'ERROR:\n  Code: {code}\n  Message: {message}']


POSITIVE = [ok('PublicKey', 'publicKey'), ok('AttestedPublicKey', 'evmAddress')]
NEGATIVE = [
    err('Sign', 'InvalidArgument', 'SignRequest.common is missing'),
    err('AttestedPublicKey', 'InvalidArgument', 'nonce must be 32 bytes, got 31'),
    err('SubmitHeaders', 'PermissionDenied', 'SubmitHeaders is closed; the parent syncs headers itself'),
    err('Sign', 'Internal', 'enclave error (code 1): this enclave is the burn signer (RGB -> EVM): '
        'it does not sign EVM -> RGB bridge PSBTs'),
]


class GrpcSmokeTestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='grpc-smoke-test-')
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / 'bin').mkdir()
        fake = self.dir / 'bin' / 'grpcurl'
        fake.write_text(FAKE_GRPCURL)
        fake.chmod(0o700)
        (self.dir / 'proto' / 'enclave').mkdir(parents=True)
        (self.dir / 'proto' / 'enclave' / 'parent.proto').write_text('')

    def run_script(self, replies):
        (self.dir / 'replies.json').write_text(json.dumps(replies))
        env = dict(os.environ, PATH=f'{self.dir / "bin"}:{os.environ["PATH"]}',
                   FAKE_DIR=str(self.dir), PROTO_DIR=str(self.dir / 'proto'))
        result = subprocess.run(['bash', str(ROOT / 'build/grpc-smoke-test.sh')],
                                env=env, capture_output=True, text=True)
        self.assertFalse((self.dir / 'unexpected').exists(),
                         (self.dir / 'unexpected').read_text() if (self.dir / 'unexpected').exists() else '')
        return result

    def fails(self, result):
        return [line for line in result.stdout.splitlines() if '[FAIL]' in line]

    def test_correct_replies_pass_with_distinct_negative_payloads(self):
        result = self.run_script(POSITIVE + NEGATIVE)
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = [json.loads(line) for line in (self.dir / 'log').read_text().splitlines()]
        self.assertEqual(len(calls), len(POSITIVE + NEGATIVE))
        self.assertEqual({(c[0].split('/')[0], c[2]) for c in calls},
                         {('parent.ParentService', 'enclave/parent.proto')})
        payloads = [c[1] for c in calls]
        self.assertEqual(len(set(payloads)), len(payloads))

    def test_a_mismatched_reply_fails_only_that_case(self):
        mutations = [
            (2, ok('Sign', 'signature'), 'Sign without common'),  # success instead of error
            (4, err('SubmitHeaders', 'Unimplemented', 'SubmitHeaders is closed'), 'SubmitHeaders'),  # wrong code
            (3, err('AttestedPublicKey', 'InvalidArgument', 'SignRequest.common is missing'),
             'AttestedPublicKey'),  # right code, wrong message
        ]
        for index, bad_reply, expect_name in mutations:
            with self.subTest(index=index):
                for name in ('log', 'unexpected'):
                    (self.dir / name).unlink(missing_ok=True)
                replies = POSITIVE + NEGATIVE
                replies[index] = bad_reply
                result = self.run_script(replies)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(len(self.fails(result)), 1)
                self.assertIn(expect_name, self.fails(result)[0])

    def test_an_unrelated_error_fails_every_negative_case(self):
        replies = POSITIVE + [err(r[0], 'Unavailable', 'enclave connection failed: refused')
                              for r in NEGATIVE]
        result = self.run_script(replies)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.fails(result)), len(NEGATIVE))


if __name__ == '__main__':
    unittest.main()
