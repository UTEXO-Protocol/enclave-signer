#!/usr/bin/env python3
"""Install the release profile on a disposable GitHub-hosted Ubuntu runner only."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

from toolchain import check_rust, digest, load


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def download(url, checksum, destination):
    with urllib.request.urlopen(url, timeout=120) as response, destination.open('wb') as stream:
        shutil.copyfileobj(response, stream)
    if digest(destination) != checksum:
        destination.unlink()
        raise ValueError('Downloaded tool checksum mismatch: ' + destination.name)


def pin_nitro_base(recipe, image):
    text, count = re.subn(r'^FROM\s+\S+', 'FROM ' + image, recipe.read_text(), count=1, flags=re.M)
    if count != 1:
        raise ValueError('Unsupported Nitro build recipe')
    recipe.write_text(text)


def main():
    cfg = load(sys.argv[1])
    check_rust(cfg, Path(__file__).resolve().parents[1])
    # This replaces the Docker service. Never use it on a runtime host or local machine.
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise ValueError('Installer requires a disposable GitHub-hosted runner')
    release = Path('/etc/os-release').read_text()
    if 'ID=ubuntu\n' not in release or 'VERSION_ID="22.04"' not in release or os.uname().machine != 'x86_64':
        raise ValueError('Installer requires Ubuntu 22.04 x86_64')
    root = Path(os.environ['RUNNER_TEMP']) / 'eif-toolchain'
    root.mkdir()  # Refuse reuse of an already prepared tool directory.
    run('sudo', 'apt-get', 'update')
    run('sudo', 'apt-get', 'install', '-y', 'ca-certificates', 'curl', 'git', 'make', 'cmake',
        'gcc', 'g++', 'iptables', 'xz-utils', 'musl-tools', 'pkg-config', 'libssl-dev',
        'clang', 'libclang-dev', 'llvm-dev', 'jq', 'unzip')
    docker = root / 'docker.tgz'
    download(f"https://download.docker.com/linux/static/stable/x86_64/docker-{cfg['docker_version']}.tgz",
             cfg['docker_sha256'], docker)
    run('tar', '-xzf', docker, '-C', root)
    run('sudo', 'systemctl', 'stop', 'docker.service', 'docker.socket', 'containerd.service')
    for binary in (root / 'docker').iterdir():
        run('sudo', 'install', '-m', '0755', binary, '/usr/local/bin/' + binary.name)
    # Use fresh daemon state; do not consume the runner's preloaded image cache.
    unit = root / 'docker.service'
    unit.write_text('''[Unit]
Description=Pinned Docker Engine for EIF builds
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/dockerd --host=unix:///var/run/docker.sock --data-root=/var/lib/eif-docker
Restart=on-failure
Environment="PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Delegate=yes
[Install]
WantedBy=multi-user.target
''')
    run('sudo', 'install', '-m', '0644', unit, '/etc/systemd/system/docker.service')
    run('sudo', 'systemctl', 'daemon-reload')
    run('sudo', 'systemctl', 'start', 'docker.service')
    docker_config = root / 'docker-config'
    plugins = docker_config / 'cli-plugins'
    plugins.mkdir(parents=True)
    plugin = plugins / 'docker-buildx'
    download(f"https://github.com/docker/buildx/releases/download/v{cfg['buildx_version']}/buildx-v{cfg['buildx_version']}.linux-amd64",
             cfg['buildx_sha256'], plugin)
    plugin.chmod(0o755)
    env = {
        'DOCKER_CONFIG': str(docker_config), 'DOCKER_HOST': 'unix:///var/run/docker.sock',
        'CARGO_HOME': str(root / 'cargo'), 'RUSTUP_HOME': str(root / 'rustup'),
        'NITRO_SOURCE_DIR': str(root / 'nitro-src'),
        'NITRO_CLI_BLOBS': str(root / 'nitro-src/blobs/x86_64'),
        'BUILDX_BUILDER': 'eif-builder', 'NITRO_CLI_VERSION': cfg['nitro_version'],
    }
    paths = [str(root / 'cargo/bin'), str(root / 'bin'), '/usr/local/bin']
    os.environ.update(env)
    os.environ.pop('BUILDX_BUILDER', None)
    os.environ['PATH'] = ':'.join(paths) + ':' + os.environ['PATH']
    # Ignore any inherited context; DOCKER_HOST must select the installed daemon.
    os.environ.pop('DOCKER_CONTEXT', None)
    run('timeout', '60', 'bash', '-c', 'until docker info >/dev/null 2>&1; do sleep 1; done')
    (root / 'bin').mkdir()
    (root / 'bin/docker').symlink_to('/usr/local/bin/docker')
    aws = root / 'aws.zip'
    download(f"https://awscli.amazonaws.com/awscli-exe-linux-x86_64-{cfg['awscli_version']}.zip",
             cfg['awscli_sha256'], aws)
    run('unzip', '-q', aws, '-d', root)
    run(root / 'aws/install', '--install-dir', root / 'aws-cli', '--bin-dir', root / 'bin')
    rustup = root / 'rustup-init'
    download(f"https://static.rust-lang.org/rustup/archive/{cfg['rustup_version']}/x86_64-unknown-linux-gnu/rustup-init",
             cfg['rustup_sha256'], rustup)
    rustup.chmod(0o755)
    run(rustup, '-y', '--no-modify-path', '--profile', 'minimal', '--default-toolchain',
        cfg['rust_version'], '--target', 'x86_64-unknown-linux-musl')
    run('rustup', 'set', 'auto-self-update', 'disable')
    for name in ('cargo', 'rustc', 'rustup'):
        (root / 'bin' / name).symlink_to(root / 'cargo/bin' / name)
    src = Path(env['NITRO_SOURCE_DIR'])
    run('git', 'init', src)
    run('git', '-C', src, 'remote', 'add', 'origin', 'https://github.com/aws/aws-nitro-enclaves-cli.git')
    run('git', '-C', src, 'fetch', '--depth', '1', 'origin', cfg['nitro_commit'])
    run('git', '-C', src, 'checkout', '--detach', 'FETCH_HEAD')
    observed = subprocess.check_output(['git', '-C', str(src), 'rev-parse', 'HEAD'], text=True).strip()
    if observed != cfg['nitro_commit']:
        raise ValueError('Unexpected Nitro source commit')
    pin_nitro_base(src / 'tools/Dockerfile', cfg['nitro_build_image'])
    run('make', 'nitro-cli', cwd=src)
    binaries = {p.resolve() for p in (src / 'build').glob('**/release/nitro-cli') if p.is_file()}
    if len(binaries) != 1:
        raise ValueError('Expected exactly one Nitro CLI binary')
    run('install', '-m', '0755', next(iter(binaries)), root / 'bin/nitro-cli')
    user = subprocess.check_output(['id', '-un'], text=True).strip()
    group = subprocess.check_output(['id', '-gn'], text=True).strip()
    run('sudo', 'install', '-d', '-o', user, '-g', group, '-m', '0750',
        '/var/log/nitro_enclaves', '/run/nitro_enclaves')
    os.environ['BUILDX_BUILDER'] = env['BUILDX_BUILDER']
    run('docker', 'buildx', 'create', '--name', env['BUILDX_BUILDER'], '--driver', 'docker-container',
        '--driver-opt', 'image=' + cfg['buildkit_image'], '--use')
    run('docker', 'buildx', 'inspect', '--bootstrap')
    # GitHub applies these values to subsequent steps, including artifact upload.
    with open(os.environ['GITHUB_ENV'], 'a') as stream:
        for key, value in env.items():
            stream.write(f'{key}={value}\n')
    with open(os.environ['GITHUB_PATH'], 'a') as stream:
        stream.write(str(root / 'bin') + '\n')
    print('Pinned builder installed; record and validate observations before building the EIF.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, IndexError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f'Builder setup failed: {error}')
