#!/usr/bin/env python3
"""Check a downloaded bundle against an independently obtained manifest hash."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

NAMES = {'stage-bfa-temp.eif', 'PCR.json', 'SHA256SUMS', 'HOST-SHA256SUMS',
         'metadata.json', 'utexo-bridge-parent', 'utexo-bridge-parent-cli'}

def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()

def verify(directory, expected, describe=True):
    manifest = directory / 'BUNDLE-SHA256SUMS'
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or manifest.is_symlink() or digest(manifest) != expected:
        raise ValueError('bundle manifest hash differs from approved value')
    rows = manifest.read_text().splitlines()
    seen = set()
    for row in rows:
        checksum, name = row.split('  ', 1)
        if name not in NAMES or name in seen or (directory / name).is_symlink():
            raise ValueError('unexpected, repeated or linked bundle file')
        if digest(directory / name) != checksum:
            raise ValueError(f'bundle file hash mismatch: {name}')
        seen.add(name)
    if seen != NAMES:
        raise ValueError('incomplete bundle')
    data = json.loads((directory / 'metadata.json').read_text())
    if (data['variant'] != 'stage-bfa-temp' or data['security_policy'] != 'Development'
            or data['runtime_debug_required'] is not True or data['cargo_profile'] != 'stage-bfa-temp'):
        raise ValueError('wrong bundle policy')
    if data['mode'] not in ('bootstrap', 'configured') or bool(data['rgb_asset_id']) != (data['mode'] == 'configured'):
        raise ValueError('wrong mode or asset')
    if describe:
        actual = json.loads(subprocess.check_output(['nitro-cli', 'describe-eif', '--eif-path',
                                                     str(directory / 'stage-bfa-temp.eif')]))
        expected_pcr = json.loads((directory / 'PCR.json').read_text())
        for name in ('PCR0', 'PCR1', 'PCR2'):
            if actual['Measurements'][name] != expected_pcr[name]:
                raise ValueError(f'EIF {name} differs from build measurements')
    return data

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--manifest-sha256', required=True)
    args = p.parse_args()
    print(json.dumps(verify(args.directory, args.manifest_sha256), indent=2))
