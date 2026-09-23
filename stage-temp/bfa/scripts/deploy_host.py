#!/usr/bin/env python3
"""Check or switch the existing three-CID stage host to an isolated BFA bundle."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from verify_bundle import verify

CIDS = (16, 18, 20)
ROOT = Path('/etc/utexo/stage-temp-solution-bfa')

def run(*args):
    return subprocess.check_output(args, text=True)

def edit_env(text, updates):
    lines = []
    for line in text.splitlines():
        if line.split('=', 1)[0] not in updates:
            lines.append(line)
    lines.extend(f'{key}={value}' for key, value in updates.items())
    return '\n'.join(lines) + '\n'

def dropin(kind, cid):
    return Path(f'/etc/systemd/system/utexo-{kind}@{cid}.service.d/stage-bfa-temp.conf')

def current_env(kind, cid):
    override = dropin(kind, cid)
    if override.exists():
        lines = override.read_text().splitlines()
        files = [line.removeprefix('EnvironmentFile=') for line in lines
                 if line.startswith('EnvironmentFile=') and line != 'EnvironmentFile=']
        if len(files) != 1 or not Path(files[0]).is_relative_to(ROOT):
            raise ValueError('unknown temporary environment override')
        return Path(files[0])
    return Path('/etc/utexo/enclave.env' if kind == 'enclave' else f'/etc/utexo/parent-{cid}.env')

def runtime():
    return json.loads(run('nitro-cli', 'describe-enclaves'))

def exact_cids(rows):
    if sorted(e['EnclaveCID'] for e in rows if e['State'] == 'RUNNING') != list(CIDS):
        raise ValueError('expected exactly the running CIDs 16, 18 and 20')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('bundle', type=Path)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--traffic-paused', action='store_true')
    args = p.parse_args()
    bundle = args.bundle.resolve()
    if not bundle.is_relative_to('/home/ubuntu/stage-temp-solution-bfa') or not re.fullmatch(r'[a-zA-Z0-9_/.-]+', str(bundle)):
        raise ValueError('bundle must be under /home/ubuntu/stage-temp-solution-bfa with no shell characters')
    data = verify(bundle, args.manifest_sha256)
    exact_cids(runtime())
    sources = {}
    for cid in CIDS:
        for kind in ('enclave', 'parent'):
            unit = f'utexo-{kind}@{cid}.service'
            if run('systemctl', 'show', unit, '--property=LoadState', '--value').strip() != 'loaded':
                raise ValueError('expected an existing stage service')
            source = current_env(kind, cid)
            text = source.read_text()
            if kind == 'parent':
                for key in ('GRPC_TLS_CERT_FILE', 'GRPC_TLS_KEY_FILE', 'GRPC_TLS_CLIENT_CA_FILE', 'GRPC_TLS_ACL_FILE'):
                    value = next((line.split('=', 1)[1] for line in text.splitlines() if line.startswith(key+'=')), '')
                    if not value or not Path(value).is_file():
                        raise ValueError(f'missing parent TLS file for CID {cid}: {key}')
            sources[(kind, cid)] = (source, text)
    print(f"Preflight passed: {data['mode']}, three CIDs, complete bundle and TLS paths.")
    if not args.apply:
        print('No services changed. Stop business traffic before using --apply --traffic-paused.')
        return
    if os.geteuid() != 0 or not args.traffic_paused:
        raise ValueError('apply requires root and --traffic-paused')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = ROOT / stamp
    target.mkdir(parents=True, mode=0o700)
    for (kind, cid), (source, text) in sources.items():
        shutil.copyfile(source, target / f'before-{kind}-{cid}.env')
        previous = dropin(kind, cid)
        if previous.exists():
            shutil.copyfile(previous, target / f'before-{kind}-{cid}.conf')
        updates = {'EIF': str(bundle / 'stage-bfa-temp.eif'), 'ENCLAVE_DEBUG_MODE': '1'} if kind == 'enclave' else {'CLUSTER_DIR': str(bundle)}
        (target / f'{kind}-{cid}.env').write_text(edit_env(text, updates))
    (target / 'bundle.json').write_text(json.dumps(data, indent=2)+'\n')
    for name in ('utexo-bridge-parent', 'utexo-bridge-parent-cli'):
        (bundle / name).chmod(0o755)
    # From this point a failure leaves traffic paused. Restore keys before routing.
    run('systemctl', 'stop', *(f'utexo-parent@{cid}' for cid in CIDS))
    run('systemctl', 'stop', *(f'utexo-enclave@{cid}' for cid in CIDS))
    for kind, cid in sources:
        file = dropin(kind, cid)
        file.parent.mkdir(parents=True, exist_ok=True)
        content = '[Service]\nEnvironmentFile=\n'+f'EnvironmentFile={target}/{kind}-{cid}.env\n'
        temporary = file.with_suffix('.new')
        temporary.write_text(content)
        temporary.replace(file)
    run('systemctl', 'daemon-reload')
    for cid in CIDS:
        run('systemctl', 'start', f'utexo-enclave@{cid}')
    rows = runtime()
    exact_cids(rows)
    if any('DEBUG_MODE' not in row.get('Flags', '') for row in rows):
        raise ValueError('an enclave did not start in debug mode')
    run('systemctl', 'start', *(f'utexo-parent@{cid}' for cid in CIDS))
    for cid in CIDS:
        run('systemctl', 'is-active', f'utexo-parent@{cid}')
    print(f'Switched bundle. Config snapshots: {target}')
    print('Keys are EMPTY. Import retained donor seeds, clone requesters, and compare identities before routing.')

if __name__ == '__main__':
    main()
