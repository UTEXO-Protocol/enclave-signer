#!/usr/bin/env python3
"""Read public build configuration. No secret inputs are accepted."""
import json, re, sys
from pathlib import Path

def read_config(path):
    data = json.loads(Path(path).read_text())
    if set(data) != {'mode', 'rgb_asset_id'}:
        raise ValueError('config must contain only mode and rgb_asset_id')
    mode, asset = data['mode'], data['rgb_asset_id']
    if mode not in ('bootstrap', 'configured') or not isinstance(asset, str):
        raise ValueError('invalid mode or asset')
    if mode == 'bootstrap' and asset:
        raise ValueError('bootstrap must not carry an asset')
    if mode == 'configured' and not re.fullmatch(r'rgb:[A-Za-z0-9_~!\-]+', asset):
        raise ValueError('configured requires an RGB contract ID')
    return data

if __name__ == '__main__':
    data = read_config(sys.argv[1])
    print(data['mode'])
    print(data['rgb_asset_id'])
