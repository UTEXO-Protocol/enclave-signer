#!/usr/bin/env python3
"""Select production or explicitly requested public-signet stage EIF artifacts."""
import json
import sys


def matrix(profile):
    if profile == 'public-signet-stage':
        return {'include': [
            dict(variant=f'stage-{role}', dockerfile='Dockerfile.enclave.stage',
                 signer_role=f'{role}-signer',
                 eif_name=f'utexo-bridge-enclave-stage-{role}.eif',
                 s3_subpath=f'stage-signet/{role}/', artifact_suffix=f'-stage-{role}')
            for role in ('mint', 'burn')
        ]}
    if profile != 'production':
        raise ValueError(f'unknown EIF profile: {profile}')
    return {'include': [
        dict(variant=variant, dockerfile=f'Dockerfile.enclave{suffix}',
             eif_name=f'utexo-bridge-enclave{name}.eif',
             s3_subpath=subpath, artifact_suffix=artifact)
        for variant, suffix, name, subpath, artifact in (
            ('combined', '', '', '', ''),
            ('rgb', '.rgb', '-rgb', 'rgb/', '-rgb'),
            ('rgb-mint', '.mint', '-mint', 'rgb-mint/', '-mint'),
            ('rgb-burn', '.burn', '-burn', 'rgb-burn/', '-burn'),
            ('ccd', '.ccd', '-ccd', 'ccd/', '-ccd'),
        )
    ]}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: eif-matrix.py production|public-signet-stage')
    try:
        print(json.dumps(matrix(sys.argv[1])))
    except ValueError as exc:
        sys.exit(str(exc))
