#!/usr/bin/env python3
"""Cold Mint/Burn deployment. Preflight is read-only except temporary artifact downloads."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
SAFE_VALUE = re.compile(r"[A-Za-z0-9_./:@,+=-]*")
PCR_KEYS = ('PCR0', 'PCR1', 'PCR2')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def env_file(path):
    result = {}
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        require('=' in line, f'{path}:{n}: expected KEY=value')
        key, value = line.split('=', 1)
        require(re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in result,
                f'{path}:{n}: invalid or duplicate setting')
        require(SAFE_VALUE.fullmatch(value) is not None and value != 'TBD',
                f'{path}:{n}: use literal unquoted values without placeholders')
        result[key] = value
    return result


def number(value, label, low=1, high=65535):
    require(re.fullmatch(r'[1-9][0-9]*', str(value)) is not None, f'invalid {label}')
    n = int(value)
    require(low <= n <= high, f'{label} outside {low}..{high}')
    return n


def cids(text):
    values = [number(x, 'CID', 4, 4294967294) for x in text.split()]
    require(len(values) == len(set(values)), 'duplicate CID')
    return values


def cmd(args, check=True):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=900)
    # Do not echo command output: endpoint errors can include credentials.
    require(not check or result.returncode == 0, f'{args[0]} {args[1]} failed (exit {result.returncode})')
    return result


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def checksums(directory, manifest, expected):
    records = {}
    for line in (directory / manifest).read_text().splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64})\s+\*?([A-Za-z0-9_.-]+)', line)
        require(match is not None, f'invalid checksum entry in {manifest}')
        expected_digest, name = match.groups()
        require(name not in records, f'duplicate checksum for {name}')
        records[name] = expected_digest.lower()
    require(set(records) == set(expected), f'{manifest}: unexpected file set')
    for name, expected_digest in records.items():
        require(digest(directory / name) == expected_digest, f'checksum mismatch: {name}')


def image_env(path):
    data = json.loads(path.read_text())
    require(isinstance(data, list), 'IMAGE-ENV must be an array')
    result = {}
    for item in data:
        require(isinstance(item, str) and '=' in item, 'invalid IMAGE-ENV entry')
        k, v = item.split('=', 1)
        require(k not in result, 'duplicate IMAGE-ENV setting')
        result[k] = v
    return result


def pcrs(data):
    result = {}
    for key in PCR_KEYS:
        value = data.get(key, '')
        require(isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{96}', value)
                and int(value, 16) != 0, f'invalid or zero {key}')
        result[key] = value.lower()
    return result


class Deployment:
    def __init__(self, config, release, bucket, region, sha, run=cmd, root=Path('/')):
        require(re.fullmatch(r'[0-9a-f]{40}', sha), 'GIT_SHA must be 40 lowercase hex characters')
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket), 'invalid BUCKET')
        require(re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]+', region), 'invalid AWS_REGION')
        self.config, self.release = Path(config).resolve(), Path(release).resolve()
        require(SAFE_VALUE.fullmatch(str(self.release)), 'CLUSTER_DIR must be a plain absolute path')
        # Never overwrite an earlier release's files while its processes are running.
        self.destination = self.release / sha
        self.bucket, self.region, self.sha, self.run, self.root = bucket, region, sha, run, root
        self.nodes, self.expected, self.measurements = {}, {}, {}
        self.retired = cids((self.config / 'retire-cids').read_text()) if (self.config / 'retire-cids').exists() else []
        ports = set()
        for path in sorted(self.config.glob('enclave-*.env')):
            match = re.fullmatch(r'enclave-([0-9]+)\.env', path.name)
            require(match, 'invalid enclave config filename')
            cid = number(match[1], 'CID', 4, 4294967294)
            e, p = env_file(path), env_file(self.config / f'parent-{cid}.env')
            role = e.get('SIGNER_ROLE')
            require(role in ('mint', 'burn'), f'CID {cid}: role must be mint or burn')
            require(e.get('ENCLAVE_DEBUG_MODE', '0') == '0', 'debug Nitro mode is not supported by this release deployer')
            require(p.get('USE_VSOCK') == 'true' and p.get('ENCLAVE_VSOCK_CID') == str(cid)
                    and p.get('ENCLAVE_VSOCK_PORT') == '5000', f'CID {cid}: invalid Parent vsock settings')
            require('GRPC_ALLOW_INSECURE_LOOPBACK' not in p and 'KMS_BROKER_TCP' not in p,
                    'insecure transport overrides must be absent')
            require(ipaddress.ip_address(p['GRPC_HOST']).is_private
                    and not ipaddress.ip_address(p['GRPC_HOST']).is_loopback, 'GRPC_HOST must be a private non-loopback IP')
            require(p.get('HEALTH_HOST') == '127.0.0.1', 'health endpoint must bind loopback')
            for field in ('GRPC_PORT', 'HEALTH_PORT'):
                port = number(p[field], field)
                require(port not in ports, 'duplicate gRPC/health port')
                ports.add(port)
            for field, default, limit in (('HEADER_SYNC_INTERVAL_SECS', '10', 600),
                                          ('GRPC_MAX_CONNECTIONS', '64', 4096),
                                          ('GRPC_CLONE_MAX_PER_MINUTE', '30', 10000)):
                number(p.get(field, default), field, high=limit)
            for field in ('ENCLAVE_CPU_COUNT', 'ENCLAVE_MEMORY'):
                number(e[field], field, high=1048576)
            require(e.get('ELECTRUM_URL') == p.get('HEADER_ELECTRUM_URL'), 'enclave and Parent Electrum endpoints must match')
            endpoint = urllib.parse.urlsplit(e['ELECTRUM_URL'])
            require(endpoint.scheme == 'ssl' and endpoint.hostname and endpoint.port
                    and not endpoint.username and not endpoint.password and not endpoint.path
                    and not endpoint.query and not endpoint.fragment,
                    'this deployer requires ssl://Electrum-host:port')
            require(re.fullmatch(r'[A-Za-z0-9.-]+', e['EVM_RPC_HOST']), 'invalid RPC host')
            number(e['EVM_RPC_TLS_PORT'], 'EVM RPC TLS port')
            for field in ('EVM_RPC_TLS_CA_DER_FILE', 'EVM_RPC_PATH_FILE'):
                require(e.get(field, '').startswith('/'), f'{field} requires an absolute path')
            if role == 'burn':
                require(not any(k.startswith('KMS_') for k in e | p), 'Burn must not receive KMS settings')
            else:
                require(re.fullmatch(r'arn:aws:kms:([a-z0-9-]+):[0-9]{12}:key/[a-f0-9-]{36}', e.get('KMS_KEY_ARN', '')),
                        'Mint needs a full KMS key ARN')
                require(e['KMS_KEY_ARN'].split(':')[3] == e.get('KMS_REGION') == p.get('AWS_REGION') == region,
                        'KMS/S3 regions must match this host region')
                require(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', e.get('KMS_SEED_ID', ''))
                        and e['KMS_SEED_ID'] == p.get('KMS_SEED_ID'), 'Mint seed IDs must match')
                require(p.get('KMS_S3_BUCKET') and p.get('KMS_S3_KEY'), 'Mint S3 settings missing')
                require(p.get('KMS_ALLOWED_CIDS') == str(cid) and p.get('KMS_BROKER_PORT', '8004') == '8004',
                        'only the Mint CID may use broker 8004')
                pin = e.get('KMS_EXPECTED_EVM_ADDRESS', '')
                require(not pin or re.fullmatch(r'(0x)?[0-9a-fA-F]{40}', pin), 'invalid Mint recovery address')
            bundle = self.destination / role
            e.update(EIF=str(bundle / f'utexo-bridge-enclave-{role}.eif'), CLI=str(bundle / 'utexo-bridge-parent-cli'),
                     PCR_FILE=str(bundle / 'PCR.json'), IMAGE_ENV=str(bundle / 'IMAGE-ENV.json'),
                     ENCLAVE_DEBUG_MODE='0')
            p['CLUSTER_DIR'] = str(bundle)
            self.nodes[cid] = (e, p)
        require(1 <= len(self.nodes) <= 4, 'configure 1..4 enclave per EC2')
        require(not set(self.nodes) & set(self.retired), 'retire-cids overlaps desired CIDs')
        require(sum(e['SIGNER_ROLE'] == 'mint' for e, p in self.nodes.values()) <= 1,
                'only one Mint/broker per host is supported')
        common = ('ELECTRUM_URL', 'EVM_RPC_HOST', 'EVM_RPC_TLS_PORT', 'EVM_RPC_TLS_CA_DER_FILE', 'EVM_RPC_PATH_FILE')
        first = next(iter(self.nodes.values()))[0]
        require(all(all(e[k] == first[k] for k in common) for e, _ in self.nodes.values()),
                'shared host relays require identical endpoint settings')
        for role in self.roles:
            self.expected[role] = env_file(self.config / f'image-{role}.env')
            require(all(self.expected[role].get(k) for k in ('RGB_ASSET_ID', 'BITCOIN_NETWORK', 'EVM_CHAIN_ID',
                        'EVM_PROXY_CONTRACT_ADDRESS', 'FUNDS_IN_CONTRACT', 'TOKEN_CONTRACT')),
                    f'{role}: expected image pins are incomplete')
        self.ports = ports

    @property
    def roles(self):
        return sorted({e['SIGNER_ROLE'] for e, _ in self.nodes.values()})

    def inventory(self):
        data = json.loads(self.run(['nitro-cli', 'describe-enclaves']).stdout)
        require(isinstance(data, list), 'invalid Nitro inventory')
        require(len({x['EnclaveCID'] for x in data}) == len(data), 'duplicate runtime CID')
        return data

    def preflight(self):
        # No service/configuration changes are allowed in this phase.
        require(os.uname().machine == 'x86_64', 'this deployer requires an x86_64 host')
        for binary in ('aws', 'nitro-cli', 'systemctl', 'ss', 'openssl', 'runuser', 'ip', 'nproc',
                       'getent', 'groupadd', 'usermod', 'udevadm', 'systemd-tmpfiles', 'timeout', 'flock'):
            require(shutil.which(binary), f'{binary} is required')
        require(os.access('/usr/bin/vsock-proxy', os.X_OK), '/usr/bin/vsock-proxy is required')
        running = self.inventory()
        allowed = set(self.nodes) | set(self.retired)
        require(all(x['EnclaveCID'] in allowed for x in running),
                'unmanaged enclave present; explicitly list removed CIDs in retire-cids')
        require(all(x.get('EnclaveName') == f"enclave-{x['EnclaveCID']}" for x in running),
                'refusing to replace an enclave not managed by the expected systemd units')
        for node in running:
            require(self.loaded(f"utexo-enclave@{node['EnclaveCID']}.service"), 'running enclave has no loaded systemd unit')
        enabled = self.run(['systemctl', 'list-unit-files', '--no-legend', '--no-pager',
                            'utexo-enclave@*.service', 'utexo-parent@*.service']).stdout
        for line in enabled.splitlines():
            fields = line.split()
            match = re.fullmatch(r'utexo-(?:enclave|parent)@([0-9]+)\.service', fields[0]) if fields else None
            if match and len(fields) > 1 and fields[1] in ('enabled', 'enabled-runtime'):
                require(int(match[1]) in allowed, 'enabled old CID missing from retire-cids')
        cpu = sum(int(e['ENCLAVE_CPU_COUNT']) for e, _ in self.nodes.values())
        memory = sum(int(e['ENCLAVE_MEMORY']) for e, _ in self.nodes.values())
        total_cpu = int(self.run(['nproc', '--all']).stdout)
        # x86 SMT hosts reserve complete cores; this deployment targets x86_64.
        require(cpu <= total_cpu - 2 and all(int(e['ENCLAVE_CPU_COUNT']) % 2 == 0 for e, _ in self.nodes.values()),
                'insufficient CPU: reserve two vCPU for host and allocate even enclave CPU counts')
        allocator = (self.root / 'etc/nitro_enclaves/allocator.yaml').read_text()
        def pool(key):
            match = re.search(rf'(?m)^\s*{key}:\s*([0-9]+)\s*(?:#.*)?$', allocator)
            require(match, f'allocator must explicitly configure {key}')
            return int(match[1])
        require(cpu <= pool('cpu_count') <= total_cpu - 2 and pool('memory_mib') >= memory,
                'allocator CPU/memory pool is insufficient; prepare it before deployment')
        mem_total = int(re.search(r'MemTotal:\s+(\d+)', (self.root / 'proc/meminfo').read_text())[1]) // 1024
        require(pool('memory_mib') <= mem_total - 2048, 'reserve at least 2048 MiB for the host')
        private_ips = {a['local'] for iface in json.loads(self.run(['ip', '-j', 'address']).stdout)
                       for a in iface.get('addr_info', []) if a.get('family') == 'inet'}
        for cid, (e, p) in self.nodes.items():
            require(p['GRPC_HOST'] in private_ips, f'CID {cid}: GRPC_HOST is not a local interface')
            for key in ('GRPC_TLS_CERT_FILE', 'GRPC_TLS_KEY_FILE', 'GRPC_TLS_CLIENT_CA_FILE', 'GRPC_TLS_ACL_FILE'):
                path = p.get(key, '')
                require(path.startswith('/') and Path(path).is_file(), f'CID {cid}: {key} file missing')
                self.run(['runuser', '-u', 'ubuntu', '--', 'test', '-r', path])
            require(Path(p['GRPC_TLS_KEY_FILE']).stat().st_mode & 0o077 == 0, 'TLS private key must have no group/world permissions')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(p['GRPC_TLS_CERT_FILE'], p['GRPC_TLS_KEY_FILE'])
            context.load_verify_locations(p['GRPC_TLS_CLIENT_CA_FILE'])
            self.run(['openssl', 'x509', '-in', p['GRPC_TLS_CERT_FILE'], '-noout', '-checkend', '86400'])
            self.run(['openssl', 'x509', '-in', p['GRPC_TLS_CERT_FILE'], '-noout', '-checkip', p['GRPC_HOST']])
            entries = [x.split('#')[0].strip() for x in Path(p['GRPC_TLS_ACL_FILE']).read_text().splitlines()]
            entries = [x for x in entries if x]
            require(0 < len(entries) <= 512 and all(re.fullmatch(r'[a-fA-F0-9]{64}\s+(listener|observer|clone-operator)', x)
                    for x in entries), 'invalid or empty Parent ACL')
            require(len({x.split()[0].lower() for x in entries}) == len(entries), 'duplicate ACL fingerprint')
        self.check_ports(allowed)
        e = next(iter(self.nodes.values()))[0]
        for field in ('EVM_RPC_TLS_CA_DER_FILE', 'EVM_RPC_PATH_FILE'):
            self.run(['runuser', '-u', 'ubuntu', '--', 'test', '-r', e[field]])
        require(Path(e['EVM_RPC_PATH_FILE']).stat().st_mode & 0o077 == 0, 'RPC path file must be private')
        self.check_rpc(e)
        endpoint = urllib.parse.urlsplit(e['ELECTRUM_URL'])
        with socket.create_connection((endpoint.hostname, endpoint.port), timeout=10) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=endpoint.hostname):
                pass
        for e, p in self.nodes.values():
            if e['SIGNER_ROLE'] != 'mint':
                continue
            head = self.run(['runuser', '-u', 'ubuntu', '--', 'aws', 's3api', 'head-object', '--bucket', p['KMS_S3_BUCKET'],
                             '--key', p['KMS_S3_KEY'], '--region', self.region], check=False)
            exists = head.returncode == 0
            require(exists or '(404)' in head.stderr, 'Mint seed storage check failed (permissions/network)')
            require(exists == bool(e.get('KMS_EXPECTED_EVM_ADDRESS')), 'Mint bootstrap/recovery pin does not match seed object presence')

    def check_ports(self, allowed):
        pids = set()
        for cid in allowed:
            r = self.run(['systemctl', 'show', '-p', 'MainPID', '--value', f'utexo-parent@{cid}.service'], check=False)
            if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout) > 0:
                pids.add(int(r.stdout))
        for line in self.run(['ss', '-ltnpH']).stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            port = fields[3].rsplit(':', 1)[-1]
            if port.isdigit() and int(port) in self.ports:
                owners = set(map(int, re.findall(r'pid=(\d+)', line)))
                require(owners and owners <= pids, 'target port is held by an unmanaged process')

    def check_rpc(self, e):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        path = Path(e['EVM_RPC_PATH_FILE']).read_text().rstrip('\r\n')
        require(len(path) <= 2048 and re.fullmatch(r'/[A-Za-z0-9/._~-]*', path)
                and not path.startswith('//') and not any(x in ('.', '..') for x in path.split('/')),
                'invalid RPC path (redacted)')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(Path(e['EVM_RPC_TLS_CA_DER_FILE']).read_bytes()))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
        try:
            for method in ('eth_chainId', 'eth_blockNumber'):
                req = urllib.request.Request(f"https://{e['EVM_RPC_HOST']}:{e['EVM_RPC_TLS_PORT']}{path}",
                    data=json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=[])).encode(),
                    headers={'Content-Type': 'application/json'})
                with opener.open(req, timeout=15) as response:
                    data = json.loads(response.read(65536))
                value = int(data['result'], 16)
                if method == 'eth_chainId':
                    require(all(value == int(pins['EVM_CHAIN_ID']) for pins in self.expected.values()), 'RPC chain mismatch')
        except Exception:
            raise ValueError('authenticated RPC preflight failed (URL, key and response redacted)') from None

    def fetch(self, staging):
        for role in self.roles:
            directory = staging / role
            directory.mkdir()
            eif = f'utexo-bridge-enclave-{role}.eif'
            files = (eif, 'PCR.json', 'IMAGE-ENV.json', 'metadata.json', 'SHA256SUMS',
                     'utexo-bridge-parent', 'utexo-bridge-parent-cli', 'HOST-SHA256SUMS')
            for name in files:
                self.run(['aws', 's3', 'cp', f's3://{self.bucket}/eif/{self.sha}/rgb-{role}/{name}',
                          directory / name, '--region', self.region, '--no-progress'])
            checksums(directory, 'SHA256SUMS', (eif,))
            checksums(directory, 'HOST-SHA256SUMS', ('utexo-bridge-parent', 'utexo-bridge-parent-cli'))
            # CI publishes static musl host binaries; do not run them through
            # the host's GNU dynamic loader (which rejects static executables).
            manifest = pcrs(json.loads((directory / 'PCR.json').read_text()))
            actual = pcrs(json.loads(self.run(['nitro-cli', 'describe-eif', '--eif-path', directory / eif]).stdout)['Measurements'])
            require(actual == manifest, f'{role}: EIF measurements do not match PCR manifest')
            metadata = json.loads((directory / 'metadata.json').read_text())
            require(metadata.get('git_sha') == self.sha and metadata.get('variant') == f'rgb-{role}'
                    and metadata.get('eif_name') == eif and metadata.get('debug_features') == '', 'wrong artifact metadata/role or debug build')
            measured_env = image_env(directory / 'IMAGE-ENV.json')
            require(all(measured_env.get(k) == v for k, v in self.expected[role].items()), f'{role}: image pins differ from approved configuration')
            require(metadata.get('rgb_asset_id') == measured_env['RGB_ASSET_ID'], 'asset metadata mismatch')
            self.measurements[role] = manifest
            final = self.destination / role
            if final.exists():
                require(final.is_dir() and all((final / name).is_file() and
                    digest(final / name) == digest(directory / name) for name in files),
                    'existing release directory differs; refusing to overwrite')

    def write(self, path, text, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + '.new')
        temp.write_text(text)
        temp.chmod(mode)
        temp.replace(path)

    def install_relays(self):
        first = next(iter(self.nodes.values()))[0]
        electrum = urllib.parse.urlsplit(first['ELECTRUM_URL'])
        relays = [('electrs', 8001, electrum.hostname, electrum.port),
                  ('evmrpc', 8002, first['EVM_RPC_HOST'], int(first['EVM_RPC_TLS_PORT']))]
        if 'mint' in self.roles:
            relays.append(('kms', 8003, f'kms.{self.region}.amazonaws.com', 443))
        for name, port, host, target in relays:
            config = f'/etc/nitro_enclaves/vsock-proxy-{name}.yaml'
            self.write(self.root / config.lstrip('/'), json.dumps({'allowlist': [{'address': host, 'port': target}]}) + '\n')
            self.write(self.root / f'etc/systemd/system/vsock-proxy-{name}.service', f'''[Unit]
Description=Enclave {name} TLS relay
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/vsock-proxy {port} {host} {target} --config {config}
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
''')
        return [f'vsock-proxy-{name}.service' for name, *_ in relays]

    def loaded(self, unit):
        result = self.run(['systemctl', 'show', '-p', 'LoadState', '--value', unit], check=False)
        require(result.returncode == 0 or result.stdout.strip() == 'not-found', 'cannot determine unit load state')
        require(result.stdout.strip() in ('loaded', 'not-found'), 'unit is masked or has an invalid configuration')
        return result.stdout.strip() == 'loaded'

    def save_configuration(self):
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        backup = self.release / 'config-backups' / stamp
        backup.mkdir(parents=True, mode=0o700)
        for relative in ('etc/utexo', 'etc/systemd/system', 'etc/nitro_enclaves',
                         'usr/local/bin', 'etc/tmpfiles.d', 'etc/udev/rules.d'):
            source = self.root / relative
            # Config/unit files only, no certificate private keys or seed objects.
            patterns = ('enclave*.env', 'parent-*.env') if relative == 'etc/utexo' else (
                'utexo-*', 'vsock-proxy-*', '*nitro-enclaves*')
            for pattern in patterns:
                for path in source.glob(pattern):
                    if path.is_file() and not path.is_symlink():
                        target = backup / relative / path.name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(path, target)
                        target.chmod(0o600)
        print(f'Previous configuration saved: {backup} (does not preserve volatile enclave keys)')

    def apply(self, staging):
        managed = sorted(set(self.nodes) | set(self.retired))
        # Versioned artifacts are installed before stopping; never replace an old bundle.
        self.destination.mkdir(parents=True, exist_ok=True)
        for role in self.roles:
            if not (self.destination / role).exists():
                shutil.copytree(staging / role, self.destination / role)
            for binary in ('utexo-bridge-parent', 'utexo-bridge-parent-cli'):
                (self.destination / role / binary).chmod(0o755)
        self.save_configuration()
        # Stop with OLD units/envs before writing new configs or changing relays.
        for cid in managed:
            for kind in ('parent', 'enclave'):
                unit = f'utexo-{kind}@{cid}.service'
                if self.loaded(unit):
                    self.run(['systemctl', 'stop', unit])
        require(not self.inventory(), 'enclaves remain after service stop; no unmanaged process is killed')
        try:
            if self.run(['getent', 'group', 'ne'], check=False).returncode:
                self.run(['groupadd', '--system', 'ne'])
            self.run(['usermod', '-aG', 'ne', 'ubuntu'])
            for source, target in (
                ('utexo-enclave-ctl.sh', 'usr/local/bin/utexo-enclave-ctl.sh'),
                ('utexo-parent-ctl.sh', 'usr/local/bin/utexo-parent-ctl.sh'),
                ('utexo-enclave@.service', 'etc/systemd/system/utexo-enclave@.service'),
                ('utexo-parent@.service', 'etc/systemd/system/utexo-parent@.service'),
                ('99-nitro-enclaves.rules', 'etc/udev/rules.d/99-nitro-enclaves.rules'),
                ('10-nitro-enclaves.tmpfiles.conf', 'etc/tmpfiles.d/10-nitro-enclaves.conf')):
                self.write(self.root / target, (HERE / 'systemd' / source).read_text(), 0o755 if target.endswith('.sh') else 0o644)
            for cid, (e, p) in self.nodes.items():
                for prefix, settings in (('enclave', e), ('parent', p)):
                    self.write(self.root / f'etc/utexo/{prefix}-{cid}.env', ''.join(f'{k}={v}\n' for k, v in settings.items()), 0o600)
                # Burn units must never inherit the Mint-only dependency.
                dropin = self.root / f'etc/systemd/system/utexo-enclave@{cid}.service.d/20-kms.conf'
                if e['SIGNER_ROLE'] == 'mint':
                    self.write(dropin, '[Unit]\nRequires=vsock-proxy-kms.service\nAfter=vsock-proxy-kms.service\n')
                elif dropin.exists():
                    dropin.unlink()
            relays = self.install_relays()
            self.run(['udevadm', 'control', '--reload'])
            self.run(['udevadm', 'trigger', '--subsystem-match=misc'])
            self.run(['systemd-tmpfiles', '--create', '/etc/tmpfiles.d/10-nitro-enclaves.conf'])
            self.run(['systemctl', 'daemon-reload'])
            for cid in self.retired:
                self.run(['systemctl', 'disable', f'utexo-parent@{cid}.service', f'utexo-enclave@{cid}.service'])
            if 'mint' not in self.roles and self.loaded('vsock-proxy-kms.service'):
                self.run(['systemctl', 'disable', '--now', 'vsock-proxy-kms.service'])
            for relay in relays:
                self.run(['systemctl', 'enable', relay])
                self.run(['systemctl', 'restart', relay])
                self.run(['systemctl', 'is-active', '--quiet', relay])
            for cid in self.nodes:
                self.run(['systemctl', 'enable', f'utexo-enclave@{cid}.service', f'utexo-parent@{cid}.service'])
                self.run(['systemctl', 'start', f'utexo-enclave@{cid}.service'])
            self.verify_runtime()
            for cid in self.nodes:
                self.run(['systemctl', 'start', f'utexo-parent@{cid}.service'])
                self.run(['systemctl', 'is-active', '--quiet', f'utexo-parent@{cid}.service'])
            for attempt in range(30):
                # Check ownership too, not just an unrelated listener's port.
                self.check_ports(set(self.nodes))
                listening = {int(line.split()[3].rsplit(':', 1)[-1]) for line in self.run(['ss', '-ltnpH']).stdout.splitlines()}
                if self.ports <= listening:
                    break
                time.sleep(1)
            else:
                raise ValueError('not all Parent ports are listening after 30 seconds')
        except Exception:
            for cid in self.nodes:
                self.run(['systemctl', 'stop', f'utexo-parent@{cid}.service', f'utexo-enclave@{cid}.service'], check=False)
            raise
        print('PROCESSES STARTED; signing NOT approved. Initialize/recover identities, check readiness and complete identity map before routing.')

    def verify_runtime(self):
        running = self.inventory()
        require({x['EnclaveCID'] for x in running} == set(self.nodes), 'runtime enclave set mismatch')
        for x in running:
            role = self.nodes[x['EnclaveCID']][0]['SIGNER_ROLE']
            require(x.get('State') == 'RUNNING' and pcrs(x.get('Measurements', {})) == self.measurements[role],
                    'runtime state/PCR mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='stop/recreate explicitly configured CIDs after preflight; volatile Burn keys are lost')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'run on the parent host as root')
    d = Deployment(os.environ['DEPLOY_CONFIG_DIR'], os.environ['CLUSTER_DIR'], os.environ['BUCKET'], os.environ['AWS_REGION'], os.environ['GIT_SHA'])
    d.preflight()
    d.release.mkdir(parents=True, exist_ok=True)
    # Staging is private and deleted even on errors. It is never a current bundle.
    with tempfile.TemporaryDirectory(prefix='.preflight-', dir=d.release) as directory:
        d.fetch(Path(directory))
        print('PREFLIGHT PASSED: configuration, resources, TLS/RPC, storage and role bundles checked; KMS attested access still requires a hardware init/recovery test.')
        if args.apply:
            d.apply(Path(directory))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        # Deliberately do not echo arbitrary subprocess/network errors containing secrets.
        print('Deployment failed: ' + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
