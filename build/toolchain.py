#!/usr/bin/env python3
"""Validate a builder profile and record the tools actually used by CI."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

FIELDS = {
    'docker_version', 'docker_sha256', 'buildx_version', 'buildx_sha256',
    'buildkit_image', 'rust_version', 'rustup_version', 'rustup_sha256',
    'nitro_version', 'nitro_commit', 'nitro_build_image',
    'awscli_version', 'awscli_sha256',
}
EVIDENCE = ('toolchain.json', 'builder-info.json', 'host-packages.txt')


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate(profile):
    if not isinstance(profile, dict) or set(profile) != FIELDS:
        raise ValueError('Toolchain profile must contain exactly the documented fields')
    for key, value in profile.items():
        if not isinstance(value, str):
            raise ValueError(f'{key} must be a string')
        if key.endswith('_sha256'):
            pattern = r'[0-9a-f]{64}'
        elif key.endswith('_version'):
            pattern = r'[0-9]+\.[0-9]+\.[0-9]+'
        elif key == 'nitro_commit':
            pattern = r'[0-9a-f]{40}'
        else:
            pattern = r'[a-zA-Z0-9._:/-]+@sha256:[0-9a-f]{64}'
        if not re.fullmatch(pattern, value) or value.split(':')[-1] in {'0' * 40, '0' * 64}:
            raise ValueError(f'{key} requires an exact version, commit, checksum or image digest')
    return profile


def load(path):
    return validate(json.loads(Path(path).read_text()))


def check_rust(profile, root):
    text = (root / 'rust-toolchain.toml').read_text()
    match = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.M)
    if not match or match[1] != profile['rust_version']:
        raise ValueError('toolchain.json Rust version differs from rust-toolchain.toml')


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def version_matches(text, expected):
    return re.search(r'(?<![0-9.])' + re.escape(expected) + r'(?![0-9.])', text) is not None


def validate_observations(profile, info):
    if not isinstance(info, dict):
        raise ValueError('Missing builder observations')
    if not isinstance(info.get('versions'), dict):
        raise ValueError('Missing observed tool versions')
    for tool in ('docker_client', 'docker_server', 'buildx', 'rust', 'rustup', 'awscli', 'nitro'):
        key = 'docker' if tool.startswith('docker_') else tool
        value = info.get('versions', {}).get(tool)
        if not isinstance(value, str) or not version_matches(value, profile[key + '_version']):
            raise ValueError(f'Observed {tool} version differs from toolchain.json')
    for key in ('buildkit_image', 'nitro_build_image', 'nitro_commit'):
        if info.get(key) != profile[key]:
            raise ValueError(f'Observed {key} differs from toolchain.json')
    hashes = info.get('hashes', {})
    if not isinstance(hashes, dict) or not {'nitro-cli', 'blobs/bzImage', 'blobs/init', 'blobs/linuxkit'}.issubset(hashes):
        raise ValueError('Missing Nitro CLI/blob measurements')
    if any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v) or int(v, 16) == 0
           for v in hashes.values()):
        raise ValueError('Invalid builder binary measurement')


def record(profile_path, destination):
    profile = load(profile_path)
    check_rust(profile, Path(__file__).resolve().parents[1])
    source = Path(os.environ['NITRO_SOURCE_DIR'])
    blobs = Path(os.environ['NITRO_CLI_BLOBS'])
    builder = os.environ['BUILDX_BUILDER']
    output('docker', 'buildx', 'inspect', builder, '--bootstrap')
    container = json.loads(output('docker', 'inspect', f'buildx_buildkit_{builder}0'))[0]
    if container['Config']['Image'] != profile['buildkit_image']:
        raise ValueError('Selected builder does not use the pinned BuildKit image')
    image = json.loads(output('docker', 'image', 'inspect', profile['buildkit_image']))[0]
    if container['Image'] != image['Id']:
        raise ValueError('Running BuildKit container image differs from the pinned image')
    recipe = (source / 'tools/Dockerfile').read_text()
    if not recipe.startswith('FROM ' + profile['nitro_build_image'] + '\n'):
        raise ValueError('Nitro build base image differs from the profile')
    info = {
        'versions': {
            'docker_client': output('docker', 'version', '--format', '{{.Client.Version}}'),
            'docker_server': output('docker', 'version', '--format', '{{.Server.Version}}'),
            'buildx': output('docker', 'buildx', 'version'),
            'rust': output('rustc', '--version'),
            'rustup': output('rustup', '--version'),
            'awscli': output('aws', '--version'),
            'nitro': output('nitro-cli', '--version'),
        },
        'nitro_commit': output('git', '-C', str(source), 'rev-parse', 'HEAD'),
        'nitro_build_image': profile['nitro_build_image'],
        'buildkit_image': container['Config']['Image'],
        'buildkit_image_id': container['Image'],
        'hashes': {'nitro-cli': digest(shutil.which('nitro-cli')),
                   **{'blobs/' + str(p.relative_to(blobs)): digest(p)
                      for p in blobs.rglob('*') if p.is_file()}},
        'host_os': Path('/etc/os-release').read_text(),
        'host_arch': os.uname().machine,
    }
    validate_observations(profile, info)
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(profile_path, destination / 'toolchain.json')
    (destination / 'builder-info.json').write_text(json.dumps(info, indent=2) + '\n')
    (destination / 'host-packages.txt').write_text(output('dpkg-query', '-W') + '\n')
    (destination / 'TOOLCHAIN-SHA256SUMS').write_text(''.join(
        f'{digest(destination / name)}  {name}\n' for name in EVIDENCE))


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'check':
            check_rust(load(sys.argv[2]), Path(__file__).resolve().parents[1])
            print('TOOLCHAIN_PROFILE_VALID')
        elif len(sys.argv) == 4 and sys.argv[1] == 'record':
            record(Path(sys.argv[2]), Path(sys.argv[3]))
        else:
            raise ValueError('Usage: toolchain.py check PROFILE | record PROFILE OUTPUT_DIR')
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f'Toolchain check failed: {error}')
