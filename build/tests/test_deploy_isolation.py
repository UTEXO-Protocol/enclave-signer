"""Run the host deploy script against a fake host; no AWS, root or Nitro needed."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'deploy/deploy-host.sh'


class DeployIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='deploy-isolation-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.etc = self.base / 'etc'
        self.local = self.base / 'usr/local'
        for folder in ('utexo', 'systemd/system', 'udev/rules.d', 'tmpfiles.d'):
            (self.etc / folder).mkdir(parents=True)
        (self.local / 'bin').mkdir(parents=True)
        self.cluster = self.base / 'artifacts'
        self.cluster.mkdir()
        self.pool = self.base / 'allocator.yaml'
        self.pool.write_text('---\nmemory_mib: 12288\ncpu_count: 6\n')
        self.pages = self.base / 'pages/hugepages-1048576kB'
        self.pages.mkdir(parents=True)
        (self.pages / 'nr_hugepages').write_text('12\n')
        self.state = self.base / 'state.json'
        self.state.write_text(json.dumps({'enclaves': [], 'parents': []}))
        self.calls = self.base / 'calls.jsonl'
        self.source = self.base / 'source'
        self.source.mkdir()
        self.script = self.base / 'deploy-host.sh'
        # Remap only filesystem roots. All deployment decisions and commands
        # run unchanged, including the installed units and verification code.
        self.script.write_text(HOST.read_text().replace('/etc/', f'{self.etc}/')
                               .replace('/usr/local/', f'{self.local}/')
                               .replace('st.st_uid != 0', f'st.st_uid != {os.getuid()}'))
        for cid in (16, 18, 20, 24):
            tls = self.etc / f'utexo/tls/{cid}'
            tls.mkdir(parents=True)
            for name in ('server.pem', 'server.key', 'client-ca.pem', 'clients.acl'):
                (tls / name).write_text('fixture\n')
        proxy_env = self.etc / 'nitro_enclaves/vsock-proxy-kms.env'
        proxy_env.parent.mkdir(parents=True)
        proxy_env.write_text('KMS_REGION=eu-central-1\n')
        self.env = dict(
            PATH=f'{self.bin}:{os.environ["PATH"]}', FAKE_ROOT=str(self.base),
            GIT_SHA='a' * 40, BUCKET='fixture', AWS_REGION='eu-central-1',
            CLUSTER_DIR=str(self.cluster), GRPC_HOST='127.0.0.1',
            NITRO_ALLOCATOR_CONFIG=str(self.pool), NITRO_HUGEPAGES_DIR=str(self.pages.parent),
            ENCLAVE_LIMITS_FILE=str(self.base / 'absent-limits'),
        )
        # One dispatcher emulates external host services and records every call.
        stub = self.bin / 'host-tool'
        stub.write_text('''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ['FAKE_ROOT'])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / 'calls.jsonl').open('a') as out:
    out.write(json.dumps([name, args]) + '\\n')
state_file = root / 'state.json'
state = json.loads(state_file.read_text())
def config(cid):
    return dict(line.split('=', 1) for line in
                (root / f'etc/utexo/enclave-{cid}.env').read_text().splitlines())
if name == 'runuser':
    command = args[args.index('--') + 1:]
    os.execvp(command[0], command)
elif name == 'su':
    os.execvp('sh', ['sh', '-c', args[args.index('-c') + 1]])
elif name == 'aws':
    if args[0] == 's3api':
        if os.environ.get('S3_DENIED') == '1': sys.exit(1)
        if args[1] == 'list-objects-v2':
            exists = os.environ.get('SEED_EXISTS', '1') == '1'
            key = args[args.index('--prefix') + 1]
            print(json.dumps({'Contents': [{'Key': key}] if exists else []}))
        else:
            if os.environ.get('S3_HEAD_DENIED') == '1': sys.exit(1)
            print(json.dumps({'ContentLength': int(os.environ.get('SEED_SIZE', '512'))}))
        sys.exit(0)
    shutil.copyfile(root / 'source' / pathlib.Path(args[2]).name, args[3])
elif name == 'install':
    if '-d' in args:
        for arg in args[1:]: pathlib.Path(arg).mkdir(parents=True, exist_ok=True)
    else:
        shutil.copyfile(args[-2], args[-1])
        os.chmod(args[-1], int(args[args.index('-m') + 1], 8))
elif name == 'nitro-cli':
    if args[0] == 'describe-eif':
        path = pathlib.Path(args[args.index('--eif-path') + 1]).parent / 'PCR.json'
        print(json.dumps({'Measurements': json.loads(path.read_text())}))
    elif args[0] == 'describe-enclaves':
        print(json.dumps(state['enclaves']))
elif name == 'systemctl':
    if args[0] == 'is-active' and os.environ.get('PROXY_DOWN') == '1': sys.exit(1)
    for unit in args[1:]:
        if '@' not in unit: continue
        cid = int(unit.split('@')[1].removesuffix('.service'))
        if args[0] == 'stop':
            if unit.startswith('utexo-parent@'):
                state['parents'] = [p for p in state['parents'] if p != cid]
            else:
                state['enclaves'] = [e for e in state['enclaves'] if e['EnclaveCID'] != cid]
        elif args[0] == 'restart':
            if unit.startswith('utexo-parent@'):
                state['parents'].append(cid)
            else:
                if os.environ.get('START_FAILURE') == '1': sys.exit(1)
                cfg = config(cid)
                pcr = json.loads(pathlib.Path(cfg['PCR_FILE']).read_text())['PCR0']
                entry = {'EnclaveCID': cid, 'State': os.environ.get('TARGET_STATE', 'RUNNING'),
                         'Measurements': {'PCR0': os.environ.get('TARGET_PCR', pcr)}}
                count = int(os.environ.get('TARGET_COUNT', '1'))
                state['enclaves'] = [e for e in state['enclaves'] if e['EnclaveCID'] != cid]
                state['enclaves'].extend([entry] * count)
    state_file.write_text(json.dumps(state))
elif name == 'pkill':
    state['parents'] = []
    state_file.write_text(json.dumps(state))
elif name == 'ss':
    for cid in state['parents']:
        for base in (50051, 50061):
            print(f'LISTEN 0 128 127.0.0.1:{base + (cid - 16) // 2} 0.0.0.0:*')
''')
        stub.chmod(0o755)
        for name in ('runuser', 'su', 'aws', 'install', 'nitro-cli', 'systemctl',
                     'pkill', 'ss', 'getent', 'usermod', 'groupadd', 'udevadm',
                     'systemd-tmpfiles', 'sleep'):
            (self.bin / name).symlink_to(stub)

    def deploy(self, cid=18, role='burn', sha='a' * 40, **extra):
        files = {
            f'utexo-bridge-enclave-{role}.eif': f'image-{role}-{sha}',
            'utexo-bridge-parent': f'parent-{sha}',
            'utexo-bridge-parent-cli': f'cli-{sha}',
            'PCR.json': json.dumps({'PCR0': f'pcr-{role}-{sha}'}),
            'IMAGE-ENV.json': '{}',
        }
        digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
        files['SHA256SUMS'] = digest(files[f'utexo-bridge-enclave-{role}.eif']) + '  image.eif\n'
        files['HOST-SHA256SUMS'] = ''.join(
            f'{digest(files[name])}  {name}\n'
            for name in ('utexo-bridge-parent', 'utexo-bridge-parent-cli'))
        for name, data in files.items():
            (self.source / name).write_text(data)
        ca, path = self.base / f'ca-{cid}', self.base / f'path-{cid}'
        ca.write_text(f'CA for {cid}')
        path.write_text(f'/private/provider-{cid}')
        if role == 'mint':
            defaults = dict(
                KMS_KEY_ARN='arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                KMS_REGION='eu-central-1', KMS_SEED_ID='fixture-mint',
                KMS_S3_BUCKET='fixture-seeds', KMS_S3_KEY='mint/seed.kms',
                KMS_EXPECTED_EVM_ADDRESS='0x' + '11' * 20,
            )
            extra = dict(defaults, **extra)
        return subprocess.run(
            ['bash', str(self.script)], text=True, capture_output=True, timeout=60,
            env=dict(self.env, ENCLAVE_CID=str(cid), SIGNER_ROLE=role, GIT_SHA=sha,
                     EVM_RPC_TLS_CA_DER_FILE=str(ca), EVM_RPC_PATH_FILE=str(path), **extra))

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def config(self, cid):
        return dict(line.split('=', 1) for line in
                    (self.etc / f'utexo/enclave-{cid}.env').read_text().splitlines())

    def snapshots(self):
        return {p: p.read_bytes() for folder in (self.etc, self.local, self.cluster)
                for p in folder.rglob('*') if p.is_file()}

    def test_mixed_roles_and_releases_preserve_every_peer_file_and_parent(self):
        # Existing template-based deployments must also keep their next-boot
        # settings and wrappers when a different CID is migrated.
        legacy = [self.etc / 'utexo/enclave.env', self.etc / 'utexo/evm-rpc-path',
                  self.local / 'bin/utexo-enclave-ctl.sh',
                  self.local / 'bin/utexo-parent-ctl.sh',
                  self.etc / 'systemd/system/utexo-enclave@.service',
                  self.etc / 'systemd/system/utexo-parent@.service']
        for p in legacy:
            p.write_text('legacy peer configuration\n')
        self.state.write_text(json.dumps({
            'enclaves': [{'EnclaveCID': 20, 'State': 'RUNNING',
                          'Measurements': {'PCR0': 'legacy-peer-pcr'}}],
            'parents': [20]}))
        self.assert_success(self.deploy(16, 'mint'))
        before = self.snapshots()
        self.calls.write_text('')
        self.assert_success(self.deploy(18, 'burn', sha='b' * 40))
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content, str(path))
        self.assertEqual(sorted(json.loads(self.state.read_text())['parents']), [16, 18, 20])
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertFalse(any(name == 'pkill' for name, _ in calls))
        for name, args in calls:
            if name == 'systemctl':
                self.assertFalse(any('@16' in arg or '@20' in arg for arg in args), args)
        for cid, role in ((16, 'mint'), (18, 'burn')):
            cfg = self.config(cid)
            self.assertEqual(cfg['SIGNER_ROLE'], role)
            self.assertIn(f'/enclave-{cid}/', cfg['EIF'])
            self.assertEqual(Path(cfg['EVM_RPC_PATH_FILE']).read_text(), f'/private/provider-{cid}')
            self.assertEqual(Path(cfg['EVM_RPC_TLS_CA_DER_FILE']).read_text(), f'CA for {cid}')
            for service in ('enclave', 'parent'):
                unit = self.etc / f'systemd/system/utexo-{service}@{cid}.service'
                self.assertIn(f'{self.local}/lib/utexo/%i/utexo-{service}-ctl.sh', unit.read_text())
        peer = {p: data for p, data in self.snapshots().items()
                if 'enclave-18' in str(p) or '/18/' in str(p) or '@18.' in str(p)}
        self.assert_success(self.deploy(16, 'mint', sha='c' * 40))
        for path, content in peer.items():
            self.assertEqual(path.read_bytes(), content, str(path))
        self.assertEqual(sorted(json.loads(self.state.read_text())['parents']), [16, 18, 20])

    def test_debug_deploy_allows_peers_with_different_measurements(self):
        self.assert_success(self.deploy(16, 'mint'))
        self.assert_success(self.deploy(18, ENCLAVE_DEBUG_MODE='1', TARGET_PCR='0' * 96))
        self.assertEqual(sorted(json.loads(self.state.read_text())['parents']), [16, 18])

    def test_parent_timeout_is_written_for_only_the_selected_cid(self):
        self.assert_success(self.deploy(16, 'mint'))
        peer = self.etc / 'utexo/parent-16.env'
        before = peer.read_bytes()
        self.assertIn(b'GRPC_REQUEST_TIMEOUT_SECS=120\n', before)
        self.assertIn(b'GRPC_MAX_CONCURRENT_SIGN=8\n', before)
        profile = dict(line.split('=', 1) for line in
                       (ROOT / 'deploy/profiles/burn-small-host.env').read_text().splitlines()
                       if line and not line.startswith('#'))
        self.assert_success(self.deploy(18, **profile))
        self.assertEqual(self.config(18)['ENCLAVE_CPU_COUNT'], '2')
        self.assertEqual(self.config(18)['ENCLAVE_MEMORY'], '4096')
        self.assertEqual(peer.read_bytes(), before)
        parent = (self.etc / 'utexo/parent-18.env').read_text()
        self.assertIn('GRPC_REQUEST_TIMEOUT_SECS=335\n', parent)
        self.assertIn('GRPC_MAX_CONCURRENT_SIGN=4\n', parent)

    def test_invalid_parent_timeout_fails_before_host_changes(self):
        before = self.snapshots()
        for name in ('GRPC_REQUEST_TIMEOUT_SECS', 'GRPC_MAX_CONCURRENT_SIGN'):
            for value in ('', '0', '0335', '-1', '1.5', '335s', '10000000',
                          '335\nGRPC_HOST=0.0.0.0'):
                with self.subTest(name=name, value=value):
                    result = self.deploy(**{name: value})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f'{name} must be', result.stderr)
                    self.assertEqual(self.snapshots(), before)
                    self.assertFalse(self.calls.exists())

    def test_invalid_target_never_starts_its_parent_or_stops_a_peer(self):
        self.assert_success(self.deploy(16, 'mint'))
        for mode in ({'TARGET_COUNT': '0'}, {'TARGET_COUNT': '2'},
                     {'TARGET_STATE': 'STOPPED'}, {'TARGET_PCR': 'wrong'},
                     {'START_FAILURE': '1'},
                     {'ENCLAVE_DEBUG_MODE': '1', 'TARGET_COUNT': '0'},
                     {'ENCLAVE_DEBUG_MODE': '1', 'TARGET_COUNT': '2'},
                     {'ENCLAVE_DEBUG_MODE': '1', 'TARGET_STATE': 'STOPPED'}):
            with self.subTest(mode=mode):
                result = self.deploy(18, **mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(self.state.read_text())['parents'], [16])

    def assert_mint_rejected_without_mutation(self, message, **extra):
        before = self.snapshots()
        state = self.state.read_bytes()
        self.calls.write_text('')
        result = self.deploy(24, 'mint', **extra)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)
        self.assertEqual(self.snapshots(), before)
        self.assertEqual(self.state.read_bytes(), state)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        for name, args in calls:
            self.assertFalse(name == 'systemctl' and args[0] in ('stop', 'restart', 'start'), calls)
            self.assertFalse(name == 'aws' and args[0] != 's3api', calls)
            self.assertNotIn(name, ('install', 'usermod', 'groupadd'), calls)

    def test_mint_requires_all_custody_fields_before_changing_a_live_host(self):
        self.assert_success(self.deploy(18))
        for name in ('KMS_KEY_ARN', 'KMS_REGION', 'KMS_SEED_ID', 'KMS_S3_BUCKET', 'KMS_S3_KEY'):
            with self.subTest(name=name):
                self.assert_mint_rejected_without_mutation(name, **{name: ''})

    def test_mint_recovery_requires_approved_pin(self):
        for pin in ('', '0x' + '00' * 20, '0x123', '0x' + '11' * 20 + '\n'):
            self.assert_mint_rejected_without_mutation('recovery requires', KMS_EXPECTED_EVM_ADDRESS=pin)

    def test_invalid_custody_values_are_rejected(self):
        for name, value in (
            ('KMS_REGION', 'eu-west-1'),
            ('KMS_KEY_ARN', 'arn:aws:kms:eu-central-1:123456789012:alias/test'),
            ('KMS_SEED_ID', 'bad\nSIGNER_ROLE=burn'),
            ('KMS_S3_KEY', 'seed$(touch /tmp/unexpected)'),
            ('KMS_S3_BUCKET', 'bad bucket'),
            ('MINT_MODE', 'automatic'),
        ):
            self.assert_mint_rejected_without_mutation('', **{name: value})

    def test_mint_checks_proxy_and_read_only_storage_prerequisites(self):
        for settings, message in (
            ({'PROXY_DOWN': '1'}, 'KMS proxy'),
            ({'S3_DENIED': '1'}, 'cannot inspect seed'),
            ({'SEED_EXISTS': '0'}, 'recovery seed object is absent'),
            ({'S3_HEAD_DENIED': '1'}, 'not readable'),
            ({'SEED_SIZE': '0'}, 'invalid ciphertext size'),
            ({'SEED_SIZE': '6145'}, 'invalid ciphertext size'),
            ({'MINT_MODE': 'bootstrap', 'KMS_EXPECTED_EVM_ADDRESS': ''}, 'seed object exists'),
            ({'MINT_MODE': 'bootstrap'}, 'bootstrap requires an empty address'),
        ):
            with self.subTest(settings=settings):
                self.assert_mint_rejected_without_mutation(message, **settings)

    def test_mint_cid24_bootstrap_and_recovery_preserve_burn_and_write_custody_config(self):
        self.assert_success(self.deploy(16, 'burn'))
        burn = self.etc / 'utexo/parent-16.env'
        before = burn.read_bytes()
        self.assertNotIn(b'KMS_', before)
        self.assert_success(self.deploy(24, 'mint', MINT_MODE='bootstrap',
                                       KMS_EXPECTED_EVM_ADDRESS='', SEED_EXISTS='0'))
        cfg = self.config(24)
        self.assertEqual(cfg['KMS_EXPECTED_EVM_ADDRESS'], '')
        parent = (self.etc / 'utexo/parent-24.env').read_text()
        for line in ('GRPC_PORT=50055', 'HEALTH_PORT=50065', 'AWS_REGION=eu-central-1',
                     'KMS_SEED_ID=fixture-mint', 'KMS_S3_BUCKET=fixture-seeds',
                     'KMS_S3_KEY=mint/seed.kms', 'KMS_ALLOWED_CIDS=24'):
            self.assertIn(line + '\n', parent)
        self.assert_success(self.deploy(24, 'mint'))
        self.assertEqual(self.config(24)['KMS_EXPECTED_EVM_ADDRESS'], '0x' + '11' * 20)
        self.assertEqual(burn.read_bytes(), before)
        self.assertEqual(sorted(json.loads(self.state.read_text())['parents']), [16, 24])
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        for name, args in calls:
            if name == 'aws' and args[0] != 's3':
                self.assertEqual(args[0], 's3api')
                self.assertIn(args[1], ('list-objects-v2', 'head-object'))

    def test_second_mint_broker_is_rejected_before_peer_is_changed(self):
        self.assert_success(self.deploy(16, 'mint'))
        self.assert_mint_rejected_without_mutation('one Mint per host')

    def test_burn_rejects_custody_configuration(self):
        result = self.deploy(KMS_S3_BUCKET='fixture-seeds')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('burn deployment must not', result.stderr)
        self.assertFalse(self.calls.exists())

    def write_mint_config(self):
        cfg = self.base / 'mint.json'
        data = dict(signer_role='mint', enclave_cid=24, settings=dict(
            KMS_KEY_ARN='arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012',
            KMS_REGION='eu-central-1', KMS_SEED_ID='from-json',
            KMS_EXPECTED_EVM_ADDRESS='0x' + '22' * 20,
            KMS_S3_BUCKET='json-seeds', KMS_S3_KEY='mint/json.kms'))
        cfg.write_text(json.dumps(data))
        cfg.chmod(0o600)
        return cfg, data

    def test_json_config_reaches_both_enclave_and_parent(self):
        cfg, _ = self.write_mint_config()
        self.assert_success(self.deploy(24, 'mint', DEPLOY_CONFIG_FILE=str(cfg)))
        self.assertEqual(self.config(24)['KMS_SEED_ID'], 'from-json')
        parent = (self.etc / 'utexo/parent-24.env').read_text()
        self.assertIn('KMS_SEED_ID=from-json\n', parent)
        self.assertIn('KMS_S3_KEY=mint/json.kms\n', parent)

    def test_json_cannot_retarget_deploy_or_execute_shell(self):
        for mutation in ('role', 'cid', 'unknown', 'shell', 'writable', 'missing', 'duplicate'):
            cfg, data = self.write_mint_config()
            if mutation == 'role': data['signer_role'] = 'burn'
            if mutation == 'cid': data['enclave_cid'] = 16
            if mutation == 'unknown': data['settings']['GIT_SHA'] = 'b' * 40
            if mutation == 'shell': data['settings']['KMS_SEED_ID'] = '$(id)'
            if mutation == 'missing': del data['settings']['KMS_KEY_ARN']
            cfg.write_text(json.dumps(data))
            if mutation == 'writable': cfg.chmod(0o666)
            if mutation == 'duplicate': cfg.write_text('{"signer_role":"mint","signer_role":"burn"}')
            self.assert_mint_rejected_without_mutation('', DEPLOY_CONFIG_FILE=str(cfg))

    def test_installed_units_and_wrappers_match_the_standalone_files(self):
        for service in ('enclave', 'parent'):
            for path, standalone in (
                (rf'"\$CONTROL_DIR/utexo-{service}-ctl.sh"', f'utexo-{service}-ctl.sh'),
                (rf'"/etc/systemd/system/utexo-{service}@\$ENCLAVE_CID.service"',
                 f'utexo-{service}@.service')):
                body = re.search(rf"cat > {path} <<'EOF'\n(.*?)\nEOF\n", HOST.read_text(), re.S)
                self.assertIsNotNone(body)
                self.assertEqual(body[1] + '\n', (ROOT / 'deploy/systemd' / standalone).read_text())


if __name__ == '__main__':
    unittest.main()
