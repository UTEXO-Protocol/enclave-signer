#!/usr/bin/env python3
"""Capture public keys or compare the complete three-signer public key set."""
import argparse
import json
from pathlib import Path
import subprocess

KEY_FIELDS = ('EVM address', 'BTC pubkey', 'BTC xpub', 'Master fingerprint',
              'Account xpub vanilla', 'Account xpub colored', 'EVM gas TX address',
              'EVM gas TX pubkey', 'CCD Ed25519 pubkey')
POLICY_FIELDS = ('Bridge chain_id', 'Bridge contract', 'RGB asset id')

def capture(cli):
    records = {}
    for cid in (16, 18, 20):
        out = subprocess.check_output([str(cli), '--addr', f'vsock://{cid}:5000', 'get-keys'], text=True, timeout=30)
        fields = dict(line.strip().split(':', 1) for line in out.splitlines() if ':' in line)
        fields = {key: value.strip() for key, value in fields.items()}
        if any(not fields.get(key) for key in KEY_FIELDS) or any(key not in fields for key in POLICY_FIELDS):
            raise ValueError(f'incomplete public identity for CID {cid}')
        records[str(cid)] = {key: fields[key] for key in KEY_FIELDS + POLICY_FIELDS}
    if len({row['Master fingerprint'] for row in records.values()}) != 3:
        raise ValueError('the three signer identities must be distinct')
    return records

def compare(before, after, same_image):
    if set(before) != {'16', '18', '20'} or set(after) != set(before):
        raise ValueError('incomplete CID set')
    fields = KEY_FIELDS + POLICY_FIELDS if same_image else KEY_FIELDS
    for cid in before:
        for field in fields:
            if not before[cid].get(field) and field != 'RGB asset id':
                raise ValueError(f'missing expected identity: CID {cid}, {field}')
            if before[cid][field] != after[cid][field]:
                raise ValueError(f'identity mismatch: CID {cid}, {field}')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    cap = sub.add_parser('capture')
    cap.add_argument('--cli', type=Path, required=True)
    check = sub.add_parser('compare')
    check.add_argument('before', type=Path)
    check.add_argument('after', type=Path)
    check.add_argument('--same-image', action='store_true', help='also compare public deployment pins')
    args = p.parse_args()
    if args.action == 'capture':
        print(json.dumps(capture(args.cli.resolve()), indent=2))
    else:
        compare(json.loads(args.before.read_text()), json.loads(args.after.read_text()), args.same_image)
        print('PASS: all three public identities match.'
              ' Signed 13-field attestation verification remains a separate gate.')

if __name__ == '__main__':
    main()
