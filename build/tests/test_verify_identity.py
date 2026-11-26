"""Identity gate regressions with stub Nitro/CLI; no AWS or enclave required."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADDRESSES = {str(cid): '0x' + f'{cid + 160:02x}' * 20 for cid in (16, 18, 20)}
VANILLA = 'xpub' + '1' * 107
COLORED = 'xpub' + '2' * 107
FINGERPRINT = '73c5da0a'
CA = b'fixture CA DER'


def pin_map(value):
    return ' '.join(f'{cid}={value}' for cid in ADDRESSES)


APPROVED = ' '.join(f'{cid}={address}' for cid, address in ADDRESSES.items())


class VerifyIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='identity-gate-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.calls = self.base / 'calls.jsonl'
        self.launch = self.base / 'enclave.env'
        self.launch.write_text('')
        self.ca = self.base / 'rpc-ca.der'
        self.ca.write_bytes(CA)
        self.env = dict(
            PATH=f'{self.base}:{os.environ["PATH"]}',
            CLUSTER_DIR=str(self.base), ENCLAVE_ENV=str(self.launch), EVM_RPC_ENV='',
            CIDS='16 18 20', EXPECTED_EVM=APPROVED, SIGNER_ROLE='mint',
            PCR_FILE='PCR.json', IMAGE_ENV='IMAGE-ENV.json', CALLS=str(self.calls),
            ADDRESSES=json.dumps(ADDRESSES),
            EXPECTED_XPUB_VANILLA=pin_map(VANILLA),
            EXPECTED_XPUB_COLORED=pin_map(COLORED),
            EXPECTED_MASTER_FINGERPRINT=pin_map(FINGERPRINT),
            EXPECTED_EVM_RPC_HOST='rpc.example.test',
            EXPECTED_EVM_RPC_CA_SHA256=hashlib.sha256(CA).hexdigest(),
            EVM_RPC_HOST='rpc.example.test', EVM_RPC_TLS_CA_DER_FILE=str(self.ca),
        )
        self.stub('nitro-cli', '''
import json, os, sys
print(os.environ.get('INVENTORY', json.dumps([
    {'EnclaveCID': cid, 'State': 'RUNNING', 'Flags': 'NONE'} for cid in (16, 18, 20)])))
sys.exit(int(os.environ.get('NITRO_RC', '0')))
''')
        self.stub('utexo-bridge-parent-cli', '''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps(args) + '\\n')
cid = args[args.index('--addr') + 1].split('://')[1].split(':')[0]
address = json.loads(os.environ['ADDRESSES'])[cid]
if 'export-attestation' in args and os.environ.get('NO_BUNDLE') != '1':
    pathlib.Path(args[args.index('--out') + 1]).write_text('{}')
print(os.environ.get('CLI_OUTPUT', '  EVM address:         ' + address))
sys.exit(int(os.environ.get('CLI_RC', '0')))
''')
        # These tests exercise the gate, not GNU timeout. subprocess.run has
        # its own deadline and CLI_RC=124 covers a timed-out export.
        self.stub('timeout', '''
import os, sys
os.execvp(sys.argv[2], sys.argv[2:])
''')

    def stub(self, name, body):
        path = self.base / name
        path.write_text('#!/usr/bin/env python3\n' + body)
        path.chmod(0o700)

    def run_gate(self, *args, **env):
        return subprocess.run(
            ['bash', str(ROOT / 'deploy/verify-identity.sh'), *args],
            env=dict(self.env, **env), capture_output=True, text=True, timeout=15,
        )

    def assert_denied(self, result, code):
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertNotIn('PASS:', result.stdout)

    def test_complete_map_passes_with_attestation_for_both_roles(self):
        for mode in ({'SIGNER_ROLE': 'mint'}, {'SIGNER_ROLE': 'burn'}):
            with self.subTest(mode=mode):
                result = self.run_gate(**mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('PASS: all CIDs', result.stdout)

    def test_missing_partial_duplicate_extra_or_malformed_map_fails_before_probe(self):
        bad_maps = ['', ' ', f'16={ADDRESSES["16"]}', APPROVED + ' 16=' + ADDRESSES['16'],
                    APPROVED + ' 22=' + ADDRESSES['16'], APPROVED.replace('18=', '18:'),
                    APPROVED.replace(ADDRESSES['18'], '0x1234'),
                    APPROVED.replace(ADDRESSES['18'], '0x' + '00' * 20),
                    APPROVED.replace('18=', '018='),
                    APPROVED + '\n22=' + ADDRESSES['16'],
                    APPROVED.replace('18=', '$(touch nope)=')]
        for role in ('mint', 'burn'):
            for expected in bad_maps:
                with self.subTest(role=role, expected=expected):
                    self.assert_denied(self.run_gate(SIGNER_ROLE=role, EXPECTED_EVM=expected), 2)
                    self.assertFalse(self.calls.exists())
                    self.assertFalse(list(self.base.glob('attestation-*.json')))

    def test_debug_mode_never_approves_identity(self):
        for role in ('mint', 'burn'):
            self.assert_denied(self.run_gate(SIGNER_ROLE=role, ENCLAVE_DEBUG_MODE='1'), 2)
        self.assertFalse(self.calls.exists())
        debug = json.dumps([{'EnclaveCID': cid, 'State': 'RUNNING', 'Flags': 'DEBUG_MODE'}
                            for cid in (16, 18, 20)])
        self.assert_denied(self.run_gate(INVENTORY=debug), 1)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.run_gate('--liveness', INVENTORY=debug).returncode, 0)

    def test_mint_requires_complete_valid_account_and_fingerprint_maps_before_probe(self):
        for name, value in [('EXPECTED_XPUB_VANILLA', VANILLA),
                            ('EXPECTED_XPUB_COLORED', COLORED),
                            ('EXPECTED_MASTER_FINGERPRINT', FINGERPRINT)]:
            for bad in ('', f'16={value}', pin_map(value) + f' 16={value}',
                        pin_map(value) + f' 22={value}', pin_map('malformed')):
                with self.subTest(name=name, bad=bad):
                    self.assert_denied(self.run_gate(**{name: bad}), 2)
                    self.assertFalse(self.calls.exists())
        result = self.run_gate(EXPECTED_XPUB_VANILLA=pin_map(VANILLA).replace(' ', '\n'),
                               EXPECTED_XPUB_COLORED=pin_map(COLORED).replace(' ', '\n'),
                               EXPECTED_MASTER_FINGERPRINT=pin_map(FINGERPRINT.upper()))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_endpoint_requires_independent_host_and_ca_approval(self):
        for extra in ({'EXPECTED_EVM_RPC_HOST': ''},
                      {'EXPECTED_EVM_RPC_HOST': 'other.example.test'},
                      {'EXPECTED_EVM_RPC_CA_SHA256': ''},
                      {'EXPECTED_EVM_RPC_CA_SHA256': 'ab' * 32},
                      {'EVM_RPC_HOST': ''}, {'EVM_RPC_TLS_CA_DER_FILE': ''},
                      {'EVM_RPC_TLS_CA_DER_FILE': str(self.base / 'missing.der')}):
            with self.subTest(extra=extra):
                self.assert_denied(self.run_gate(**extra), 2)
                self.assertFalse(self.calls.exists())
        self.launch.write_text('EXPECTED_EVM_RPC_HOST=rpc.example.test\n'
                               'EXPECTED_EVM_RPC_CA_SHA256=' + hashlib.sha256(CA).hexdigest() + '\n')
        self.assert_denied(self.run_gate(EXPECTED_EVM_RPC_HOST='other.example.test'), 2)
        self.assert_denied(self.run_gate(EXPECTED_EVM_RPC_CA_SHA256='ab' * 32), 2)
        self.assertEqual(self.run_gate(EXPECTED_EVM_RPC_HOST='RPC.EXAMPLE.TEST',
                                      EXPECTED_EVM_RPC_CA_SHA256=hashlib.sha256(CA).hexdigest().upper()).returncode, 0)

    def test_launch_files_cannot_supply_or_override_caller_approvals(self):
        self.launch.write_text(
            f"EXPECTED_EVM='{APPROVED}'\n"
            f"EXPECTED_XPUB_VANILLA='{pin_map(VANILLA)}'\n"
            f"EXPECTED_XPUB_COLORED='{pin_map(COLORED)}'\n"
            f"EXPECTED_MASTER_FINGERPRINT='{pin_map(FINGERPRINT)}'\n"
            "CIDS='16 18 20'\n")
        for missing in ('EXPECTED_EVM', 'EXPECTED_XPUB_VANILLA',
                        'EXPECTED_XPUB_COLORED', 'EXPECTED_MASTER_FINGERPRINT'):
            self.assert_denied(self.run_gate(**{missing: ''}), 2)
            self.assertFalse(self.calls.exists())
        self.assert_denied(self.run_gate(CIDS=''), 2)
        wrong_evm = APPROVED.replace(ADDRESSES['18'], '0x' + 'ab' * 20)
        self.assert_denied(self.run_gate(EXPECTED_EVM=wrong_evm), 1)
        self.calls.unlink()
        wrong_vanilla = pin_map(COLORED)
        result = self.run_gate(EXPECTED_XPUB_VANILLA=wrong_vanilla)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The stub records the pins; the real CLI mismatch is covered by its
        # binary integration test against an attested enclave response.
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all(args[args.index('--expect-account-xpub-vanilla') + 1] == COLORED
                            for args in calls))

    def test_identity_needs_a_launch_env_and_a_known_role(self):
        del self.env['ENCLAVE_ENV']
        self.assert_denied(self.run_gate(), 2)
        self.assert_denied(self.run_gate(ENCLAVE_ENV=str(self.base / 'missing.env')), 2)
        self.assert_denied(self.run_gate(ENCLAVE_ENV=str(self.launch), SIGNER_ROLE='combined'), 2)
        self.assertFalse(self.calls.exists())

    def test_root_refuses_a_service_user_controlled_env_before_sourcing(self):
        self.stub('id', 'print(0)\n')
        marker = self.base / 'sourced'
        self.launch.write_text(f'touch {marker}\n')
        result = self.run_gate()
        self.assert_denied(result, 2)
        self.assertIn('root-owned', result.stdout)
        self.assertFalse(marker.exists())
        self.assertFalse(self.calls.exists())

    def test_unset_cids_defaults_but_empty_does_not(self):
        del self.env['CIDS']
        self.assertEqual(self.run_gate().returncode, 0)
        self.assert_denied(self.run_gate(CIDS=''), 2)

    def test_multiline_map_and_cids_and_case_insensitive_address(self):
        expected = '\n'.join(f'{cid}=0x{address[2:].upper()}' for cid, address in ADDRESSES.items())
        result = self.run_gate(CIDS='16\n18\n20', EXPECTED_EVM=expected)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mismatch_fails_for_both_roles(self):
        wrong = dict(ADDRESSES, **{'18': '0x' + 'ab' * 20})
        for role in ('mint', 'burn'):
            with self.subTest(role=role):
                self.assert_denied(self.run_gate(SIGNER_ROLE=role, ADDRESSES=json.dumps(wrong)), 1)

    def test_cli_failure_even_with_expected_address_is_not_success(self):
        for role in ('mint', 'burn'):
            for rc in ('1', '124'):
                with self.subTest(role=role, rc=rc):
                    self.assert_denied(self.run_gate(SIGNER_ROLE=role, CLI_RC=rc), 1)

    def test_missing_malformed_ambiguous_or_gas_only_output_fails(self):
        address = ADDRESSES['16']
        for output in ('', 'key not initialized', '  EVM gas TX address: ' + address,
                       'contract: ' + address, 'EVM address: ' + address + 'a',
                       f'EVM address: {address}\nEVM address: {address}'):
            for role in ('mint', 'burn'):
                with self.subTest(role=role, output=output):
                    self.assert_denied(self.run_gate(SIGNER_ROLE=role, CLI_OUTPUT=output), 1)

    def test_every_mint_export_has_approved_address_and_account_keys(self):
        result = self.run_gate(SIGNER_ROLE='mint')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 3)
        for args in calls:
            cid = args[args.index('--addr') + 1].split('://')[1].split(':')[0]
            self.assertIn('export-attestation', args)
            self.assertEqual(args[args.index('--expect-evm-address') + 1], ADDRESSES[cid])
            self.assertEqual(args[args.index('--signer-role') + 1], 'mint')
            self.assertEqual(args[args.index('--expect-account-xpub-vanilla') + 1], VANILLA)
            self.assertEqual(args[args.index('--expect-account-xpub-colored') + 1], COLORED)
            self.assertEqual(args[args.index('--expect-master-fingerprint') + 1], FINGERPRINT)
            self.assertTrue((self.base / f'attestation-{cid}.json').is_file())

    def test_export_success_without_bundle_fails(self):
        self.assert_denied(self.run_gate(SIGNER_ROLE='burn', NO_BUNDLE='1'), 1)

    def test_missing_stopped_or_unreadable_inventory_fails(self):
        for inventory in ('[]', 'not-json', '{}', '[{"EnclaveCID":16,"State":"RUNNING"}]',
                          '[{"EnclaveCID":16,"State":"STOPPED"}]'):
            with self.subTest(inventory=inventory):
                self.assert_denied(self.run_gate(INVENTORY=inventory), 1)
        self.assert_denied(self.run_gate(NITRO_RC='1'), 1)

    def test_liveness_is_explicit_and_never_exports_or_approves(self):
        for expected in ('', APPROVED):
            result = self.run_gate('--liveness', EXPECTED_EVM=expected, SIGNER_ROLE='', PCR_FILE='', IMAGE_ENV='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('identity NOT approved', result.stdout)
            self.assertNotIn('PASS', result.stdout)
        self.assertFalse(list(self.base.glob('attestation-*.json')))
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(all('get-keys' in args for args in calls))
        self.assert_denied(self.run_gate('--liveness', CLI_RC='1'), 1)
        self.assert_denied(self.run_gate('--liveness', INVENTORY='[]'), 1)

    def test_missing_launch_values_unknown_role_and_args_fail(self):
        for values in ({'SIGNER_ROLE': ''}, {'SIGNER_ROLE': 'typo'},
                       {'SIGNER_ROLE': 'burn', 'PCR_FILE': ''},
                       {'SIGNER_ROLE': 'mint', 'PCR_FILE': ''}, {'CLUSTER_DIR': ''}):
            with self.subTest(values=values):
                self.assert_denied(self.run_gate(**values), 2)
        self.assert_denied(self.run_gate('--unknown'), 2)


if __name__ == '__main__':
    unittest.main()
