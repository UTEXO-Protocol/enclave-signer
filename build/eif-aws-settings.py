#!/usr/bin/env python3
"""Select explicit production AWS settings without repository Stage fallback."""
import os
import re
import sys


def select(env, operation):
    profile = env.get('BUILD_PROFILE', 'default')
    if profile not in ('default', 'stage-signet', 'stage-mainnet', 'prod-mainnet'):
        raise ValueError('Unknown build profile')
    prod = profile == 'prod-mainnet'
    prefix = 'PROD_' if prod else ''
    role = 'AWS_OIDC_ROLE_ARN' if operation == 'build' else 'EIF_RELEASE_READ_ROLE_ARN'
    settings = {
        'AWS_ROLE': env.get(prefix + role, ''),
        'AWS_REGION': env.get(prefix + 'AWS_REGION', ''),
        'EIF_S3_BUCKET': env.get(prefix + 'EIF_S3_BUCKET', ''),
        'AWS_ACCOUNT_ID': env.get('PROD_AWS_ACCOUNT_ID' if prod else 'EIF_RELEASE_AWS_ACCOUNT_ID', ''),
    }
    if prod:
        if env.get('GITHUB_REF') not in ('refs/heads/dev', 'refs/heads/stage', 'refs/heads/main'):
            raise ValueError('Production requires an approved dev/stage/main workflow branch')
    if prod or operation == 'publish':
        account = settings['AWS_ACCOUNT_ID']
        if not re.fullmatch(r'[0-9]{12}', account):
            raise ValueError('Set the selected AWS account ID (12 digits)')
        if not re.fullmatch(r'arn:aws:iam::' + account + r':role/[A-Za-z0-9_+=,.@/-]+', settings['AWS_ROLE']):
            raise ValueError('Selected OIDC role must belong to the selected AWS account')
        if not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]+', settings['AWS_REGION']):
            raise ValueError('Set the selected AWS region')
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', settings['EIF_S3_BUCKET']):
            raise ValueError('Set the selected EIF bucket')
    if any('\n' in v or '\r' in v for v in settings.values()):
        raise ValueError('AWS settings must be single-line values')
    return settings


if __name__ == '__main__':
    try:
        operation = sys.argv[1]
        if operation not in ('build', 'publish'):
            raise ValueError('Expected build or publish')
        settings = select(os.environ, operation)
        with open(os.environ['GITHUB_ENV'], 'a') as output:
            for key, value in settings.items():
                output.write(f'{key}={value}\n')
    except (ValueError, KeyError) as error:
        sys.exit(str(error))
