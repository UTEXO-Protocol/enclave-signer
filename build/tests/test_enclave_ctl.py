"""Enclave start script regressions with stub Nitro/CLI; nothing is launched."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CTL = ROOT / 'deploy/systemd/utexo-enclave-ctl.sh'
HOST = ROOT / 'deploy/deploy-host.sh'
MEMORY_CHECK = re.compile(r'    case "\$MEM" in\n.*?\n    fi\n', re.S)


def bash_expands_empty_arrays():
    """bash before 4.4 stops on "${empty[@]}" under set -u; the control script
    expands one on the start path. The deploy hosts run a newer bash."""
    out = subprocess.run(
        ['bash', '-c', 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"'],
        capture_output=True, text=True,
    ).stdout.strip()
    major, minor = (int(part) for part in out.split('.')[:2])
    return (major, minor) >= (4, 4)


def embedded_ctl():
    """The copy of the control script that deploy-host.sh installs on the host."""
    match = re.search(
        r"cat > /usr/local/bin/utexo-enclave-ctl\.sh <<'EOF'\n(.*?)\nEOF\n", HOST.read_text(), re.S)
    assert match, 'embedded control script not found in deploy-host.sh'
    return match.group(1) + '\n'


class EnclaveCtlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='enclave-ctl-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.calls = self.base / 'nitro-cli.calls'
        self.embedded = self.base / 'embedded-ctl.sh'
        self.embedded.write_text(embedded_ctl())
        self.env = dict(
            PATH=f'{self.base}:{os.environ["PATH"]}',
            EIF='/dev/null', PCR_FILE='PCR.json', IMAGE_ENV='IMAGE-ENV.json',
            SIGNER_ROLE='mint', CLI=str(self.base / 'utexo-bridge-parent-cli'),
            UTEXO_ENCLAVE_LOCK=str(self.base / 'start.lock'), CALLS=str(self.calls),
        )
        # nitro-cli records its arguments; describe-enclaves reports no enclave.
        self.stub('nitro-cli', '''
import os, sys
with open(os.environ['CALLS'], 'a') as f:
    f.write(' '.join(sys.argv[1:]) + '\\n')
if 'describe-enclaves' in sys.argv:
    print('[]')
''')
        # The parent CLI reports a ready enclave and accepts every command.
        self.stub('utexo-bridge-parent-cli', '''
import sys
if 'health' in sys.argv:
    print('Endpoints set: yes')
''')
        # flock and GNU timeout are not on every developer machine.
        self.stub('flock', '')
        self.stub('timeout', '''
import os, sys
args = sys.argv[1:]
while args and (args[0].startswith('-') or args[0][0].isdigit()):
    args = args[1:]
os.execvp(args[0], args)
''')

    def stub(self, name, body):
        path = self.base / name
        path.write_text('#!/usr/bin/env python3\n' + body)
        path.chmod(0o700)

    def start(self, script, memory):
        env = dict(self.env)
        if memory is not None:
            env['ENCLAVE_MEMORY'] = memory
        return subprocess.run(
            ['bash', str(script), 'start', '16'],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def assert_refused(self, result, text):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(text, result.stderr)
        self.assertFalse(self.calls.exists(), 'nitro-cli ran')

    def test_too_little_memory_is_refused_before_run_enclave(self):
        for script in (CTL, self.embedded):
            for memory in ('2688', '3071', '0'):
                with self.subTest(script=script.name, memory=memory):
                    result = self.start(script, memory)
                    self.assert_refused(
                        result, f'ENCLAVE_MEMORY={memory} MiB is below the 3072 MiB minimum')

    def test_a_value_that_is_not_a_number_is_refused(self):
        for script in (CTL, self.embedded):
            for memory in ('3g', '3072 ', '-3072', '3072.0', '99999999999999999999'):
                with self.subTest(script=script.name, memory=memory):
                    result = self.start(script, memory)
                    self.assert_refused(result, 'ENCLAVE_MEMORY must be a whole number of MiB')

    def test_the_default_and_a_large_value_reach_run_enclave(self):
        if not bash_expands_empty_arrays():
            self.skipTest('bash 4.4 or later is needed for the start path')
        for script in (CTL, self.embedded):
            for memory, expected in ((None, '3072'), ('3072', '3072'), ('4096', '4096')):
                with self.subTest(script=script.name, memory=memory):
                    if self.calls.exists():
                        self.calls.unlink()
                    result = self.start(script, memory)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    calls = self.calls.read_text()
                    self.assertIn('run-enclave', calls)
                    self.assertIn(f'--memory {expected} --enclave-cid 16', calls)

    def test_deploy_host_refuses_before_any_step(self):
        env = dict(
            PATH=self.env['PATH'], GIT_SHA='0' * 40, BUCKET='bucket',
            AWS_REGION='eu-central-1', CLUSTER_DIR=str(self.base),
        )
        for memory, text in (('2688', 'is below the 3072 MiB minimum'),
                             ('3g', 'must be a whole number of MiB')):
            with self.subTest(memory=memory):
                result = subprocess.run(
                    ['bash', str(HOST)], env=dict(env, ENCLAVE_MEMORY=memory),
                    capture_output=True, text=True, timeout=30,
                )
                self.assert_refused(result, text)

    def test_the_embedded_check_equals_the_standalone_one(self):
        standalone = MEMORY_CHECK.search(CTL.read_text())
        embedded = MEMORY_CHECK.search(embedded_ctl())
        self.assertTrue(standalone and embedded, 'memory check block not found')
        self.assertEqual(standalone.group(0), embedded.group(0))


if __name__ == '__main__':
    unittest.main()
