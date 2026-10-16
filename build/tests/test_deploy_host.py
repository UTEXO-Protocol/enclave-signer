"""Cold deployment regression tests. No real AWS, systemd, Nitro or network calls."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load('deploy_host')
ssm = load('release_ssm')
SHA = 'a' * 40
PCRS = {role: {k: str(i) * 96 for k in host.PCR_KEYS} for i, role in enumerate(('mint', 'burn'), 1)}
PINS = dict(RGB_ASSET_ID='rgb:fixture', BITCOIN_NETWORK='testnet4', EVM_CHAIN_ID='42161',
            EVM_PROXY_CONTRACT_ADDRESS='0x' + '12' * 20, FUNDS_IN_CONTRACT='0x' + '34' * 20,
            TOKEN_CONTRACT='0x' + '56' * 20, RUST_LOG='debug')


def write_env(path, fields):
    path.write_text(''.join(f'{k}={v}\n' for k, v in fields.items()))


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base / 'config'
        self.config.mkdir()
        self.release = self.base / 'releases'
        self.root = self.base / 'root'
        self.staging = self.base / 'staging'
        self.staging.mkdir()
        self.artifacts = self.base / 'artifacts'
        self.calls, self.running = [], []
        self.loaded_units = set()
        self.enabled_extra = ''
        self.seed_exists = False
        self.seed_forbidden = False
        self.ports = ''
        self.rpc_failure = False
        self.runtime_bad = False
        for rel, contents in (('etc/nitro_enclaves/allocator.yaml', 'cpu_count: 6\nmemory_mib: 12288\n'),
                              ('proc/meminfo', 'MemTotal: 33554432 kB\n')):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        self.files = {}
        for name in ('cert', 'key', 'ca', 'acl', 'rpc', 'rpc-ca'):
            path = self.base / name
            path.write_text('a' * 64 + ' listener\n' if name == 'acl' else '/v3/fixture')
            path.chmod(0o600)
            self.files[name] = str(path)
        self.node(22, 'burn')
        self.node(24, 'mint')
        for role in ('mint', 'burn'):
            write_env(self.config / f'image-{role}.env', PINS)
            directory = self.artifacts / f'rgb-{role}'
            directory.mkdir(parents=True)
            eif = f'utexo-bridge-enclave-{role}.eif'
            (directory / eif).write_bytes(b'EIF-' + role.encode())
            (directory / 'PCR.json').write_text(json.dumps(PCRS[role]))
            (directory / 'IMAGE-ENV.json').write_text(json.dumps([f'{k}={v}' for k, v in PINS.items()]))
            (directory / 'metadata.json').write_text(json.dumps(dict(git_sha=SHA, variant='rgb-' + role,
                eif_name=eif, debug_features='', rgb_asset_id=PINS['RGB_ASSET_ID'])))
            for binary in ('utexo-bridge-parent', 'utexo-bridge-parent-cli'):
                (directory / binary).write_bytes(b'fixture-' + role.encode())
            for manifest, names in (('SHA256SUMS', (eif,)), ('HOST-SHA256SUMS', ('utexo-bridge-parent', 'utexo-bridge-parent-cli'))):
                (directory / manifest).write_text(''.join(f'{host.digest(directory / name)}  {name}\n' for name in names))
        for target, value in (('shutil.which', '/bin/fixture'), ('os.access', True)):
            mock = patch.object(host.shutil if target.startswith('shutil') else host.os, target.split('.')[1], return_value=value)
            mock.start()
            self.addCleanup(mock.stop)
        for obj, name in ((host.ssl, 'SSLContext'), (host.ssl, 'create_default_context'), (host.socket, 'create_connection')):
            mock = patch.object(obj, name, return_value=MagicMock())
            mock.start()
            self.addCleanup(mock.stop)
        rpc = patch.object(host.Deployment, 'check_rpc', side_effect=self.rpc)
        rpc.start()
        self.addCleanup(rpc.stop)

    def node(self, cid, role):
        e = dict(SIGNER_ROLE=role, ENCLAVE_CPU_COUNT='2', ENCLAVE_MEMORY='3072', ENCLAVE_DEBUG_MODE='0',
                 ELECTRUM_URL='ssl://electrum.example.com:50002', EVM_RPC_HOST='rpc.example.com',
                 EVM_RPC_TLS_PORT='443', EVM_RPC_TLS_CA_DER_FILE=self.files['rpc-ca'], EVM_RPC_PATH_FILE=self.files['rpc'])
        p = dict(USE_VSOCK='true', ENCLAVE_VSOCK_CID=str(cid), ENCLAVE_VSOCK_PORT='5000',
                 GRPC_HOST='10.0.0.5', GRPC_PORT=str(50000 + cid), HEALTH_HOST='127.0.0.1', HEALTH_PORT=str(51000 + cid),
                 HEADER_ELECTRUM_URL=e['ELECTRUM_URL'], GRPC_TLS_CERT_FILE=self.files['cert'], GRPC_TLS_KEY_FILE=self.files['key'],
                 GRPC_TLS_CLIENT_CA_FILE=self.files['ca'], GRPC_TLS_ACL_FILE=self.files['acl'])
        if role == 'mint':
            e.update(KMS_KEY_ARN='arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                     KMS_REGION='eu-central-1', KMS_SEED_ID='fixture', KMS_EXPECTED_EVM_ADDRESS='')
            p.update(KMS_SEED_ID='fixture', AWS_REGION='eu-central-1', KMS_ALLOWED_CIDS=str(cid), KMS_BROKER_PORT='8004',
                     KMS_S3_BUCKET='fixture-seeds', KMS_S3_KEY='mint/seed')
        write_env(self.config / f'enclave-{cid}.env', e)
        write_env(self.config / f'parent-{cid}.env', p)

    def rpc(self, e):
        if self.rpc_failure:
            raise ValueError('RPC authorization failed')

    def fake_run(self, args, check=True):
        args = list(map(str, args))
        if 'ld-linux' in args[0]:
            raise AssertionError('static musl host binaries must not use the GNU dynamic loader')
        self.calls.append(args)
        result = SimpleNamespace(returncode=0, stdout='', stderr='')
        if args[:2] == ['nitro-cli', 'describe-enclaves']:
            result.stdout = json.dumps(self.running)
        elif args[:2] == ['nitro-cli', 'describe-eif']:
            role = 'mint' if args[-1].endswith('-mint.eif') else 'burn'
            result.stdout = json.dumps({'Measurements': PCRS[role]})
        elif args[0] == 'nproc':
            result.stdout = '8'
        elif args[:3] == ['ip', '-j', 'address']:
            result.stdout = '[{"addr_info":[{"family":"inet","local":"10.0.0.5"}]}]'
        elif args[:2] == ['systemctl', 'list-unit-files']:
            result.stdout = self.enabled_extra
        elif args[:3] == ['systemctl', 'show', '-p']:
            result.stdout = ('loaded' if args[-1] in self.loaded_units else 'not-found') if args[3] == 'LoadState' else '123'
        elif args[:2] == ['ss', '-ltnpH']:
            result.stdout = self.ports
        elif args[:3] == ['aws', 's3', 'cp']:
            url = args[3].split('/')
            shutil.copyfile(self.artifacts / url[-2] / url[-1], args[4])
        elif 'head-object' in args:
            result.returncode = 1 if self.seed_forbidden or not self.seed_exists else 0
            result.stderr = '(403)' if self.seed_forbidden else '(404)'
        elif args[:2] == ['systemctl', 'stop']:
            for unit in args[2:]:
                if unit.startswith('utexo-enclave@'):
                    cid = int(unit.split('@')[1].split('.')[0])
                    self.running = [x for x in self.running if x['EnclaveCID'] != cid]
        elif args[:2] == ['systemctl', 'start']:
            unit = args[2]
            self.loaded_units.add(unit)
            cid = int(unit.split('@')[1].split('.')[0])
            if unit.startswith('utexo-enclave@'):
                role = 'mint' if cid == 24 else 'burn'
                self.running.append(dict(EnclaveCID=cid, State='RUNNING', Measurements=PCRS['mint' if self.runtime_bad else role]))
            else:
                for port in (50000 + cid, 51000 + cid):
                    self.ports += f'LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:* users:(("parent",pid=123,fd=3))\n'
        return result

    def deployment(self):
        return host.Deployment(self.config, self.release, 'fixture-artifacts', 'eu-central-1', SHA, self.fake_run, self.root)

    def no_mutation(self):
        self.assertFalse(any(c[:2] in (['systemctl', 'stop'], ['systemctl', 'start'], ['systemctl', 'restart']) for c in self.calls))

    def test_preflight_fetch_two_roles_without_service_changes(self):
        d = self.deployment()
        d.preflight()
        d.fetch(self.staging)
        self.no_mutation()
        self.assertEqual(d.measurements, PCRS)
        self.assertNotEqual(d.nodes[22][0]['EIF'], d.nodes[24][0]['EIF'])

    def test_rpc_failure_aborts_before_stop(self):
        self.rpc_failure = True
        with self.assertRaisesRegex(ValueError, 'RPC authorization'):
            self.deployment().preflight()
        self.no_mutation()

    def test_wrong_bundle_hash_and_role_abort_before_stop(self):
        for filename, content in (('utexo-bridge-enclave-burn.eif', 'tampered'), ('metadata.json', '{}'), ('PCR.json', json.dumps(PCRS['mint']))):
            path = self.artifacts / 'rgb-burn' / filename
            old = path.read_bytes()
            path.write_text(content)
            with self.assertRaises(ValueError):
                self.deployment().fetch(self.staging)
            path.write_bytes(old)
            shutil.rmtree(self.staging)
            self.staging.mkdir()
            self.no_mutation()

    def test_seed_access_and_bootstrap_recovery_match(self):
        d = self.deployment()
        self.seed_forbidden = True
        with self.assertRaisesRegex(ValueError, 'storage check failed'):
            d.preflight()
        self.seed_forbidden = False
        self.seed_exists = True
        with self.assertRaisesRegex(ValueError, 'pin does not match'):
            d.preflight()
        d.nodes[24][0]['KMS_EXPECTED_EVM_ADDRESS'] = '0x' + 'ab' * 20
        d.preflight()
        self.seed_exists = False
        with self.assertRaisesRegex(ValueError, 'pin does not match'):
            d.preflight()
        self.no_mutation()

    def test_unmanaged_enabled_cid_and_port_abort(self):
        self.enabled_extra = 'utexo-parent@16.service enabled enabled\n'
        with self.assertRaisesRegex(ValueError, 'retire-cids'):
            self.deployment().preflight()
        self.enabled_extra = ''
        self.ports = 'LISTEN 0 128 10.0.0.5:50022 0.0.0.0:* users:(("other",pid=999,fd=3))\n'
        with self.assertRaisesRegex(ValueError, 'unmanaged process'):
            self.deployment().preflight()
        self.no_mutation()

    def test_oversubscribed_allocator_debug_kms_leak_and_port_collision(self):
        d = self.deployment()
        d.nodes[22][0]['ENCLAVE_CPU_COUNT'] = '8'
        with self.assertRaisesRegex(ValueError, 'CPU'):
            d.preflight()
        for filename, line in (('enclave-22.env', 'KMS_SEED_ID=leaked'), ('parent-22.env', 'GRPC_PORT=50024'),
                               ('enclave-22.env', 'ENCLAVE_DEBUG_MODE=1')):
            path = self.config / filename
            old = path.read_text()
            key, value = line.split('=')
            data = host.env_file(path)
            data[key] = value
            write_env(path, data)
            with self.assertRaises(ValueError):
                self.deployment()
            path.write_text(old)
        self.no_mutation()

    def test_apply_installs_per_role_files_and_stops_only_declared_units(self):
        (self.config / 'retire-cids').write_text('16 18 20')
        for cid in (16, 18, 20):
            self.loaded_units.update((f'utexo-enclave@{cid}.service', f'utexo-parent@{cid}.service'))
        d = self.deployment()
        d.preflight()
        d.fetch(self.staging)
        d.apply(self.staging)
        burn = host.env_file(self.root / 'etc/utexo/enclave-22.env')
        mint = host.env_file(self.root / 'etc/utexo/enclave-24.env')
        self.assertTrue(burn['EIF'].endswith('/burn/utexo-bridge-enclave-burn.eif'))
        self.assertIn('KMS_KEY_ARN', mint)
        self.assertFalse(any(k.startswith('KMS_') for k in burn))
        self.assertTrue((self.root / 'etc/systemd/system/utexo-enclave@24.service.d/20-kms.conf').exists())
        self.assertFalse((self.root / 'etc/systemd/system/utexo-enclave@22.service.d/20-kms.conf').exists())
        self.assertFalse(any('pkill' in c for c in self.calls))
        self.assertEqual({x['EnclaveCID'] for x in self.running}, {22, 24})
        stops = [c[2] for c in self.calls if c[:2] == ['systemctl', 'stop']]
        self.assertEqual(set(stops), {f'utexo-{kind}@{cid}.service' for kind in ('enclave', 'parent') for cid in (16, 18, 20)})
        self.assertEqual((self.root / 'etc/utexo/enclave-24.env').stat().st_mode & 0o777, 0o600)

    def test_runtime_wrong_pcr_stops_new_enclaves_before_parents(self):
        d = self.deployment()
        d.fetch(self.staging)
        self.runtime_bad = True
        with self.assertRaisesRegex(ValueError, 'PCR mismatch'):
            d.apply(self.staging)
        self.assertFalse(self.running)
        self.assertFalse(any(c[:2] == ['systemctl', 'start'] and 'parent@' in c[-1] for c in self.calls))


class ReleaseTests(unittest.TestCase):
    def test_failed_second_preflight_prevents_all_apply(self):
        calls = []
        env = dict(GIT_SHA=SHA, BUCKET='example', AWS_REGION='eu-central-1', CLUSTER_DIR='/opt/utexo/releases', DEPLOY_CONFIG_DIR='/etc/utexo/deploy-config')
        def aws(*args):
            calls.append(args)
            if args[1] == 'send-command':
                return {'Command': {'CommandId': args[3]}}
            return {'Status': 'Success' if args[-1] == 'host1' else 'Failed'}
        with self.assertRaisesRegex(RuntimeError, 'rollout stopped'):
            ssm.deploy(['host1', 'host2'], env, False, call=aws)
        sends = [c for c in calls if c[1] == 'send-command']
        self.assertEqual(len(sends), 2)
        self.assertTrue(all('--apply' not in c[-1] for c in sends))
        payload = ssm.parameters(env, True)
        self.assertIn('--apply', payload['commands'][0])
        self.assertLess(len(json.dumps(payload)), 60000)

    def test_cold_apply_refuses_multiple_hosts_before_ssm(self):
        calls = []
        with self.assertRaisesRegex(RuntimeError, 'exactly one host'):
            ssm.deploy(['primary', 'replica'], {}, True, call=lambda *args: calls.append(args))
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
