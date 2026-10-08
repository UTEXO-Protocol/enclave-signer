"""verify-signer.sh with stub cast and attest-verify; no network needed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SIGNER = '0x' + 'ab' * 20
PROXY = '0x' + 'cd' * 20


class VerifySignerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='verify-signer-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.argv = self.base / 'argv'
        self.stub('cast', 'if [ "$1" = chain-id ]; then echo "${CHAIN:-42161}"; '
                          'else echo "[${SIGNERS:-}]"; fi')
        self.stub('attest-verify', f'printf "%s\\n" "$@" > {self.argv}\n'
                                   '[ "${VERIFY_OK:-1}" = 1 ] || exit 1\n'
                                   f'echo OK; echo "  EVM address           : {SIGNER}"')
        pcrs = self.base / 'PCR.json'
        pcrs.write_text('{"PCR0": "%s", "PCR1": "%s", "PCR2": "%s"}' % ('11' * 48, '22' * 48, '33' * 48))
        self.bundle = self.base / 'attestation-16.json'
        self.bundle.write_text('{}')
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}', PCR_FILE=str(pcrs),
                        ARB_RPC_URL='http://rpc.test', MULTISIG_PROXY=PROXY,
                        SIGNERS=f'0x{"01" * 20}, {SIGNER.upper().replace("0X", "0x")}')

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f'#!/bin/sh\n{body}\n')
        path.chmod(0o700)

    def run_script(self, *args, **env):
        return subprocess.run(['bash', str(ROOT / 'build/verify-signer.sh'), str(self.bundle), *args],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_a_listed_attested_signer_passes_with_the_proxy_pinned(self):
        result = self.run_script('--expect-signer-role', 'burn')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'OK: {SIGNER}', result.stdout)
        argv = self.argv.read_text().split('\n')
        self.assertEqual(argv[:2], ['--from-file', str(self.bundle)])
        joined = ' '.join(argv)
        self.assertIn(f'--expect-chain-id 42161 --expect-bridge-contract {PROXY}', joined)
        self.assertIn('--pcr0 ' + '11' * 48, joined)
        self.assertIn('--expect-signer-role burn', joined)

    def test_an_unlisted_signer_fails(self):
        result = self.run_script(SIGNERS='0x' + '01' * 20)
        self.assertEqual(result.returncode, 1)
        self.assertIn('is not in getEnclaveSigners(96)', result.stderr)

    def test_an_rpc_on_another_chain_fails(self):
        result = self.run_script(CHAIN='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('RPC chain id 1 is not 42161', result.stderr)
        self.assertFalse(self.argv.exists())

    def test_a_bundle_that_does_not_verify_fails(self):
        result = self.run_script(VERIFY_OK='0')
        self.assertEqual(result.returncode, 1)
        self.assertIn('attest-verify rejected the bundle', result.stderr)

    def test_the_caller_cannot_set_the_chain_or_the_contract(self):
        for flag in ('--expect-chain-id', '--expect-bridge-contract=0x00', '--endpoint'):
            result = self.run_script(flag, '1')
            self.assertEqual(result.returncode, 2, flag)
            self.assertIn('set by this script', result.stderr)
        self.assertFalse(self.argv.exists())


if __name__ == '__main__':
    unittest.main()
