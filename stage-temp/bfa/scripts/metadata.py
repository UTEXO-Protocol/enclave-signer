#!/usr/bin/env python3
import datetime, hashlib, json, os, subprocess, sys
from pathlib import Path
from config import read_config
root = Path(__file__).resolve().parents[3]
config = read_config(root / 'stage-temp/bfa/config.json')
out = Path(sys.argv[1])
sha = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
image = 'stage-bfa-temp:' + config['mode']
# Inspect the built image rather than copying the requested asset into metadata blindly.
inspection = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True))[0]
env = dict(row.split('=', 1) for row in inspection['Config']['Env'])
assert env['RGB_ASSET_ID'] == config['rgb_asset_id']
assert env['BITCOIN_NETWORK'] == 'bitcoin'
assert env['EVM_CHAIN_ID'] == '42161'
data = dict(config, git_sha=sha, variant='stage-bfa-temp', eif_name='stage-bfa-temp.eif',
            security_policy='Development', runtime_debug_required=True,
            features=['vsock','rgb','bfa-mint','allow-seed-import','allow-debug-pcrs','stage-bfa-temp'],
            cargo_profile='stage-bfa-temp', image_id=inspection['Id'],
            nitro_cli_version=os.environ['NITRO_CLI_VERSION'],
            run_id=os.environ.get('GITHUB_RUN_ID','local'), run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT','1'),
            built_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
(out / 'metadata.json').write_text(json.dumps(data, indent=2)+'\n')
names = ['stage-bfa-temp.eif','PCR.json','SHA256SUMS','HOST-SHA256SUMS','metadata.json',
         'utexo-bridge-parent','utexo-bridge-parent-cli']
(out / 'BUNDLE-SHA256SUMS').write_text(''.join(f'{hashlib.file_digest((out / n).open("rb"),"sha256").hexdigest()}  {n}\n' for n in names))
