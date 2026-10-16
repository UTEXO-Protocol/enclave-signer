#!/usr/bin/env python3
"""Ship reviewed deploy sources; preflight every host before any cold apply."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time

HERE = Path(__file__).resolve().parent


def parameters(env, apply=False):
    # Explicit source files only: never ship local configuration or credentials.
    files = ['deploy-host.sh', 'deploy_host.py', 'verify-identity.sh']
    files += [str(p.relative_to(HERE)) for p in sorted((HERE / 'systemd').glob('*')) if p.is_file()]
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as archive:
        for name in files:
            archive.add(HERE / name, arcname='deploy/' + name)
    payload = data.getvalue()
    exports = '\n'.join(f'export {k}={shlex.quote(env[k])}' for k in
                        ('GIT_SHA', 'BUCKET', 'AWS_REGION', 'CLUSTER_DIR', 'DEPLOY_CONFIG_DIR'))
    script = f'''#!/bin/bash
set -euo pipefail
umask 077
work=$(mktemp -d /var/tmp/utexo-deploy.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
printf '%s' '{base64.b64encode(payload).decode()}' | base64 -d > "$work/source.tar.gz"
printf '%s  %s\\n' '{hashlib.sha256(payload).hexdigest()}' "$work/source.tar.gz" | sha256sum -c -
tar -xzf "$work/source.tar.gz" -C "$work"
{exports}
bash "$work/deploy/deploy-host.sh"{' --apply' if apply else ''}
'''
    # AWS-RunShellScript may use /bin/sh: invoke bash explicitly.
    body = {'commands': ['bash -c ' + shlex.quote(script)], 'executionTimeout': ['3600']}
    if len(json.dumps(body).encode()) > 60000:
        raise ValueError('deployment payload too large for inline SSM delivery')
    return body


def aws(*args):
    result = subprocess.run(['aws', *args, '--region', os.environ['AWS_REGION'], '--output', 'json'],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        # Invocation may take a moment to become visible. No credential-bearing output.
        if 'InvocationDoesNotExist' in result.stderr:
            return None
        raise RuntimeError('AWS command failed: ' + args[0] + ' ' + args[1])
    return json.loads(result.stdout)


def deploy(instances, env, apply, call=aws, sleep=time.sleep, now=time.monotonic):
    if apply and len(instances) != 1:
        raise RuntimeError('cold apply requires exactly one host; recover and verify its identities before deploying another host')
    # Stop immediately on any failed preflight; no host has been stopped yet.
    for phase in ([False, True] if apply else [False]):
        payload = json.dumps(parameters(env, phase))
        for instance in instances:
            result = call('ssm', 'send-command', '--instance-ids', instance,
                          '--document-name', 'AWS-RunShellScript', '--timeout-seconds', '600',
                          '--parameters', payload)
            command = result['Command']['CommandId']
            print(f'{instance}: {"apply" if phase else "preflight"} command {command}', flush=True)
            deadline = now() + 4200
            while now() < deadline:
                result = call('ssm', 'get-command-invocation', '--command-id', command, '--instance-id', instance)
                if result and result['Status'] not in ('Pending', 'InProgress', 'Delayed'):
                    print(result.get('StandardOutputContent', ''), flush=True)
                    print(result.get('StandardErrorContent', ''), flush=True)
                    if result['Status'] != 'Success':
                        raise RuntimeError(f'{instance}: {result["Status"]}; rollout stopped')
                    break
                sleep(5)
            else:
                raise RuntimeError(f'{instance}: polling deadline exceeded; inspect/cancel SSM command {command} before retrying')


def main():
    env = dict(os.environ)
    if not re.fullmatch('[0-9a-f]{40}', env.get('GIT_SHA', '')):
        raise ValueError('GIT_SHA must be 40 hex characters')
    # Workflow checkout must match artifacts, not whichever branch dispatched it.
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if head != env['GIT_SHA']:
        raise ValueError('source checkout differs from requested release SHA')
    for key in ('BUCKET', 'AWS_REGION', 'CLUSTER_DIR', 'DEPLOY_CONFIG_DIR'):
        if not env.get(key):
            raise ValueError(f'{key} required')
    instances = (env.get('INSTANCES_INPUT') or env.get('INSTANCES_SECRET', '')).split()
    if not instances or len(instances) != len(set(instances)) or not all(re.fullmatch(r'i-[0-9a-f]{17}', x) for x in instances):
        raise ValueError('supply unique EC2 instance IDs')
    deploy(instances, env, env.get('APPLY') == 'true')


if __name__ == '__main__':
    main()
