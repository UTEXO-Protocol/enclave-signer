#!/usr/bin/env python3
"""Create retained stage keys, or import one exact stored version over local vsock."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

CIDS = (16, 18, 20)
AWS_OPTIONS = []

def aws(args, payload=None):
    result = subprocess.run(['aws', *AWS_OPTIONS, *args, '--output', 'json'],
                            input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('AWS request failed; check credentials, permissions and parameter state')
    return json.loads(result.stdout)

def parameter(prefix, cid):
    if not re.fullmatch(r'/utexo/stage-temp/bfa/[a-zA-Z0-9_-]+', prefix):
        raise ValueError('prefix must be /utexo/stage-temp/bfa/<keyset-name>')
    if cid not in CIDS:
        raise ValueError('expected CID 16, 18 or 20')
    return f'{prefix}/signer-{cid}'

def create(args):
    # Each signer has its own seed and clone secret. PutParameter never overwrites.
    for cid in ([args.cid] if args.cid else CIDS):
        name = parameter(args.prefix, cid)
        payload = {'Name': name, 'Type': 'SecureString', 'KeyId': args.kms_key_id,
                   'Value': json.dumps({'seed_hex': secrets.token_hex(64),
                                        'cloning_secret': secrets.token_hex(32)}),
                   'Overwrite': False,
                   'Description': 'Temporary BFA stage identity. Retain across EIF rebuilds.'}
        response = aws(['ssm', 'put-parameter', '--cli-input-json', 'file:///dev/stdin'], payload)
        print(json.dumps({'cid': cid, 'parameter': name, 'version': response['Version']}), flush=True)

def restore(args):
    name = parameter(args.prefix, args.cid)
    if args.version < 1:
        raise ValueError('an exact positive parameter version is required')
    data = json.loads(aws(['ssm', 'get-parameter', '--name', f'{name}:{args.version}',
                           '--with-decryption'])['Parameter']['Value'])
    if set(data) != {'seed_hex', 'cloning_secret'} or not re.fullmatch(r'[0-9a-f]{128}', data['seed_hex']):
        raise ValueError('invalid retained seed record')
    if not re.fullmatch(r'[0-9a-f]{64}', data['cloning_secret']):
        raise ValueError('invalid retained cloning secret')
    if not args.cli.is_file() or not os.access(args.cli, os.X_OK):
        raise ValueError('CLI is not executable')
    # The kernel memory filesystem avoids a persistent plaintext file on disk.
    with tempfile.TemporaryDirectory(prefix='stage-bfa-temp-', dir='/dev/shm') as directory:
        seed, clone = Path(directory) / 'seed', Path(directory) / 'clone'
        for file, content in ((seed, data['seed_hex']), (clone, data['cloning_secret'])):
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as out:
                out.write(content)
        cli_env = dict(os.environ, RUST_LOG='error')
        cli_env.pop('UTEXO_CLONING_SECRET', None)
        result = subprocess.run([str(args.cli.resolve()), '--addr', f'vsock://{args.cid}:5000',
                                 'init-stage-seed', '--seed-file', str(seed),
                                 '--cloning-secret-file', str(clone)],
                                env=cli_env, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise RuntimeError('seed import failed; do not retry by generating another seed')
    # Read keys separately. Do not forward the initialization response or diagnostics.
    subprocess.run([str(args.cli.resolve()), '--addr', f'vsock://{args.cid}:5000', 'get-keys'],
                   env=cli_env, check=True, timeout=30)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prefix', required=True)
    p.add_argument('--account-id', required=True)
    p.add_argument('--region', required=True)
    p.add_argument('--profile')
    sub = p.add_subparsers(dest='action', required=True)
    make = sub.add_parser('create')
    make.add_argument('--kms-key-id', required=True)
    make.add_argument('--cid', type=int, choices=CIDS, help='create only a missing signer after a partial failure')
    make.set_defaults(run=create)
    load = sub.add_parser('restore')
    load.add_argument('--cid', type=int, choices=CIDS, required=True)
    load.add_argument('--version', type=int, required=True)
    load.add_argument('--cli', type=Path, required=True)
    load.set_defaults(run=restore)
    args = p.parse_args()
    parameter(args.prefix, 16)
    if not re.fullmatch(r'[0-9]{12}', args.account_id):
        raise ValueError('invalid account ID')
    AWS_OPTIONS.extend(['--region', args.region])
    if args.profile:
        AWS_OPTIONS.extend(['--profile', args.profile])
    if aws(['sts', 'get-caller-identity'])['Account'] != args.account_id:
        raise ValueError('AWS account does not match the intended stage account')
    args.run(args)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # CLI errors may carry request data. Do not print exceptions or tracebacks.
        raise SystemExit('Stage key operation failed. Preserve all existing parameter versions.')
