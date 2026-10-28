"""Enclave control and host deploy script regressions with stub tools. No test starts an enclave."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CTL = ROOT / 'deploy/systemd/utexo-enclave-ctl.sh'
HOST = ROOT / 'deploy/deploy-host.sh'
# Blocks that the two copies of the control script must share word for word.
SHARED_BLOCKS = {
    'unit env load': re.compile(r'# systemd gives `start` the values.*?\nfi\n', re.S),
    'pool helpers': re.compile(r'# The Nitro allocator reserves hugepages.*?\npages_mib\(\) \{\n.*?\n\}\n', re.S),
    'memory check': re.compile(r'    case "\$MEM" in\n.*?\n    fi\n', re.S),
    # The checks that run before anything is touched, up to the exit of `check`.
    'start and check': re.compile(r'  start\|check\)\n.*?\n      exit 0\n    fi\n', re.S),
    'free pages': re.compile(r'    # Refuse with one clear message, not five failed attempts.*?\n    fi\n', re.S),
}


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
        self.pool = self.base / 'allocator.yaml'
        self.pages = self.base / 'hugepages'
        self.env_file = self.base / 'enclave.env'
        # Three enclaves of 4096 MiB: twelve 1 GiB pages.
        self.write_pool(12288)
        self.write_pages(gib=12)
        self.env = dict(
            PATH=f'{self.base}:{os.environ["PATH"]}',
            EIF='/dev/null', PCR_FILE='PCR.json', IMAGE_ENV='IMAGE-ENV.json',
            SIGNER_ROLE='mint', CLI=str(self.base / 'utexo-bridge-parent-cli'),
            UTEXO_ENCLAVE_LOCK=str(self.base / 'start.lock'), CALLS=str(self.calls),
            NITRO_ALLOCATOR_CONFIG=str(self.pool), NITRO_HUGEPAGES_DIR=str(self.pages),
            # Never read the unit env file of the machine that runs the tests.
            # An empty ENCLAVE_ENV makes check use the environment.
            ENCLAVE_ENV='',
        )
        # nitro-cli records its arguments. describe-enclaves reports no enclave.
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

    def write_pool(self, memory_mib):
        # The layout of the file that the aws-nitro-enclaves-cli package installs.
        self.pool.write_text(
            '---\n# Enclave configuration file.\n#\n'
            '# How much memory to allocate for enclaves (in MiB).\n'
            f'memory_mib: {memory_mib}\n#\n'
            '# How many CPUs to reserve for enclaves.\ncpu_count: 6\n')

    def write_pages(self, gib, free_gib=None, mib2=0, free_mib2=None):
        # The counters of each hugepage size, as /sys/kernel/mm/hugepages shows them.
        for size_kb, total, free in ((1048576, gib, gib if free_gib is None else free_gib),
                                     (2048, mib2, mib2 if free_mib2 is None else free_mib2)):
            folder = self.pages / f'hugepages-{size_kb}kB'
            folder.mkdir(parents=True, exist_ok=True)
            (folder / 'nr_hugepages').write_text(f'{total}\n')
            (folder / 'free_hugepages').write_text(f'{free}\n')

    def write_env(self, text):
        # check takes its keys from the unit env file only. The last two lines
        # give it the pool and the pages of the test.
        self.env_file.write_bytes(text + (f'NITRO_ALLOCATOR_CONFIG={self.pool}\n'
                                          f'NITRO_HUGEPAGES_DIR={self.pages}\n').encode())

    def stub(self, name, body):
        path = self.base / name
        path.write_text('#!/usr/bin/env python3\n' + body)
        path.chmod(0o700)

    def run_ctl(self, script, memory, action='start', **extra):
        env = dict(self.env, **extra)
        if memory is not None:
            env['ENCLAVE_MEMORY'] = memory
        # macOS scans each new stub the first time it runs. On a busy host
        # this can take more than a minute.
        return subprocess.run(
            ['bash', str(script), action, '16'],
            env=env, capture_output=True, text=True, errors='replace', timeout=300,
        )

    def run_host(self, **extra):
        env = dict(
            PATH=self.env['PATH'], GIT_SHA='0' * 40, BUCKET='bucket',
            AWS_REGION='eu-central-1', CLUSTER_DIR=str(self.base),
            NITRO_ALLOCATOR_CONFIG=str(self.pool), NITRO_HUGEPAGES_DIR=str(self.pages),
        )
        env.update(extra)
        return subprocess.run(['bash', str(HOST)], env=env, capture_output=True, text=True,
                              timeout=300)

    def assert_refused(self, result, text):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(text, result.stderr)
        self.assertFalse(self.calls.exists(), 'nitro-cli ran')

    def scripts(self):
        return (CTL, self.embedded)

    def test_too_little_memory_is_refused_before_run_enclave(self):
        for script in self.scripts():
            for action in ('start', 'check'):
                for memory in ('3584', '4095', '0'):
                    with self.subTest(script=script.name, action=action, memory=memory):
                        result = self.run_ctl(script, memory, action)
                        self.assert_refused(
                            result, f'ENCLAVE_MEMORY={memory} MiB is below the 4096 MiB minimum')

    def test_a_value_that_is_not_a_number_is_refused(self):
        for script in self.scripts():
            # bash reads a leading zero as an octal number, and nitro-cli reads
            # it as a decimal one.
            for memory in ('4g', '4096 ', '-4096', '4096.0', '99999999999999999999',
                           '010000', '020000', '010240', '04096'):
                with self.subTest(script=script.name, memory=memory):
                    result = self.run_ctl(script, memory)
                    self.assert_refused(result, 'ENCLAVE_MEMORY must be a whole number of MiB')

    def test_a_value_that_is_not_a_whole_number_of_gib_is_refused(self):
        for script in self.scripts():
            for action in ('start', 'check'):
                for memory in ('4608', '5000', '8193'):
                    with self.subTest(script=script.name, action=action, memory=memory):
                        result = self.run_ctl(script, memory, action)
                        self.assert_refused(
                            result, f'ENCLAVE_MEMORY={memory} MiB is not a whole number of GiB')

    def test_an_invalid_cid_list_is_refused(self):
        # Unset or empty means one enclave on CID 16. Multiple enclaves require
        # an explicit, unique list; there is no independent count setting.
        for script in self.scripts():
            for action in ('start', 'check'):
                for cids in ('0', '03', 'three', '100', '16 16', '16 22', ' '):
                    with self.subTest(script=script.name, action=action, cids=cids):
                        result = self.run_ctl(script, None, action, ENCLAVE_CIDS=cids)
                        self.assert_refused(result, 'ENCLAVE_CIDS must')

    def test_the_default_and_a_larger_value_reach_run_enclave(self):
        if not bash_expands_empty_arrays():
            self.skipTest('bash 4.4 or later is needed for the start path')
        self.write_pages(gib=16)
        for script in self.scripts():
            for memory, expected in ((None, '4096'), ('4096', '4096'), ('8192', '8192')):
                with self.subTest(script=script.name, memory=memory):
                    if self.calls.exists():
                        self.calls.unlink()
                    result = self.run_ctl(script, memory)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    calls = self.calls.read_text()
                    self.assertIn('run-enclave', calls)
                    self.assertIn(f'--memory {expected} --enclave-cid 16', calls)

    def test_start_needs_only_free_pages_for_its_own_enclave(self):
        # At boot a pool that is short for every enclave still starts the ones
        # that fit. Free pages of both sizes count.
        if not bash_expands_empty_arrays():
            self.skipTest('bash 4.4 or later is needed for the start path')
        self.write_pool(9216)
        self.write_pages(gib=3, mib2=512)
        for script in self.scripts():
            with self.subTest(script=script.name):
                if self.calls.exists():
                    self.calls.unlink()
                result = self.run_ctl(script, None)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('--memory 4096 --enclave-cid 16', self.calls.read_text())

    def test_start_refuses_when_the_free_pages_cannot_hold_its_enclave(self):
        for gib, free_gib, mib2, free_mib2, free_mib in ((12, 3, 0, 0, 3072), (3, 3, 511, 511, 4094)):
            self.write_pages(gib=gib, free_gib=free_gib, mib2=mib2, free_mib2=free_mib2)
            for script in self.scripts():
                with self.subTest(script=script.name, free_mib=free_mib):
                    if self.calls.exists():
                        self.calls.unlink()
                    result = self.run_ctl(script, None)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f'only {free_mib} MiB of hugepages are free', result.stderr)
                    self.assertNotIn('run-enclave', self.calls.read_text())

    def test_check_passes_and_changes_nothing(self):
        for script in self.scripts():
            with self.subTest(script=script.name):
                result = self.run_ctl(script, None, 'check')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('1 enclave of 4096 MiB fit: memory_mib 12288 MiB, hugepages '
                              '12288 MiB, values from the environment', result.stdout)
                self.assertFalse(self.calls.exists(), 'nitro-cli ran')

    def test_check_refuses_an_allocator_file_that_cannot_hold_every_enclave(self):
        for script in self.scripts():
            for pool in (10752, 9216):
                with self.subTest(script=script.name, pool=pool):
                    self.write_pool(pool)
                    result = self.run_ctl(script, None, 'check', ENCLAVE_CIDS='16 18 20')
                    self.assert_refused(
                        result, f'memory_mib in {self.pool} is {pool} MiB, and 3 enclaves '
                        '(ENCLAVE_CIDS) of 4096 MiB need 12288 MiB')
                    self.assertNotIn('restart nitro-enclaves-allocator', result.stderr)
                    self.assertIn('restarts every enclave of this host', result.stderr)

    def test_check_refuses_pages_that_the_kernel_does_not_hold_yet(self):
        self.write_pages(gib=9)
        for script in self.scripts():
            with self.subTest(script=script.name):
                result = self.run_ctl(script, None, 'check', ENCLAVE_CIDS='16 18 20')
                self.assert_refused(result, 'the kernel holds 9216 MiB of hugepages')
                self.assertIn('restarts every enclave of this host', result.stderr)

    def test_check_counts_the_pages_of_every_size(self):
        self.write_pages(gib=10, mib2=1024)
        for script in self.scripts():
            with self.subTest(script=script.name):
                result = self.run_ctl(script, None, 'check')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('hugepages 12288 MiB', result.stdout)

    def test_check_reads_the_allocator_file_as_the_allocator_does(self):
        # The allocator removes the double quotes around a value.
        for script in self.scripts():
            for value, ok in (('"12288"', True), ('"12287"', False)):
                with self.subTest(script=script.name, value=value):
                    self.write_pool(value)
                    result = self.run_ctl(script, None, 'check', ENCLAVE_CIDS='16 18 20')
                    if ok:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    else:
                        self.assert_refused(result, f'memory_mib in {self.pool} is 12287 MiB')

    def test_a_file_that_the_allocator_refuses_is_refused(self):
        # The allocator refuses each of these files. It keeps a comment after
        # the value, and a double quote with no blank before it. It ignores the
        # lines before "---", so it reads nothing in a CRLF file or in a file
        # with no "---" line. It ignores a last line with no newline. It reads a
        # leading zero as an octal number.
        for text in ('---\nmemory_mib: 12288 # pool\ncpu_count: 6\n',
                     '---\nmemory_mib:"12288"\ncpu_count: 6\n',
                     '---\r\nmemory_mib: 12288\r\ncpu_count: 6\r\n',
                     'memory_mib: 12288\ncpu_count: 6\n',
                     '---\ncpu_count: 6\nmemory_mib: 12288',
                     '---\nmemory_mib: 012288\ncpu_count: 6\n'):
            self.pool.write_bytes(text.encode())
            for script in self.scripts():
                with self.subTest(script=script.name, text=text):
                    self.assert_refused(self.run_ctl(script, None, 'check'),
                                        'cannot read memory_mib from')
            with self.subTest(script=HOST.name, text=text):
                self.assert_refused(
                    self.run_host(GRPC_HOST='10.0.0.1', PARENT_TLS_DIR=str(self.base / 'tls')),
                    'cannot read memory_mib from')

    def test_check_reads_the_unit_env_file(self):
        self.write_env(b'ENCLAVE_MEMORY=8192\nENCLAVE_CIDS=16 18 20\n')
        for script in self.scripts():
            with self.subTest(script=script.name):
                result = self.run_ctl(script, None, 'check', ENCLAVE_ENV=str(self.env_file))
                self.assert_refused(result, 'of 8192 MiB need 24576 MiB')
        self.write_pool(24576)
        self.write_pages(gib=24)
        for script in self.scripts():
            with self.subTest(script=script.name, pool='large'):
                result = self.run_ctl(script, None, 'check', ENCLAVE_ENV=str(self.env_file))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'values from {self.env_file}', result.stdout)

    def test_check_reads_the_env_file_as_systemd_does(self):
        # systemd keeps a comment after a value. It removes the blanks around
        # the key and the value, and a carriage return at the end of a line.
        # It removes one pair of quotes around the whole value. It ignores a
        # comment line. The last line of a key wins. An empty value gives the
        # default.
        for text, refusal in ((b'ENCLAVE_MEMORY=4096 # note\n', "got '4096 # note'"),
                              (b'ENCLAVE_CIDS=3 # replicas\n', "got '3'"),
                              (b'ENCLAVE_MEMORY=8192;\n', "got '8192;'"),
                              (b'ENCLAVE_MEMORY = 8192\n', 'of 8192 MiB need 24576 MiB'),
                              (b"ENCLAVE_MEMORY='8192'\n", 'of 8192 MiB need 24576 MiB'),
                              (b'\tENCLAVE_MEMORY\t= "8192" \n', 'of 8192 MiB need 24576 MiB'),
                              (b'; a comment\nENCLAVE_MEMORY=8192\n', 'of 8192 MiB need 24576 MiB'),
                              (b'# ENCLAVE_MEMORY=8192\n', None),
                              (b'ENCLAVE_MEMORY=8192\nENCLAVE_MEMORY=4096\n', None),
                              (b'ENCLAVE_MEMORY=8192\nENCLAVE_MEMORY=\n', None),
                              (b'ENCLAVE_MEMORY=4096\r\nENCLAVE_CIDS=16 18 20\r\n', None),
                              (b'\nENCLAVE_MEMORY=8192\n \t\n\r\n', 'of 8192 MiB need 24576 MiB')):
            self.write_env(b'ENCLAVE_CIDS=16 18 20\n' + text)
            for script in self.scripts():
                with self.subTest(script=script.name, text=text):
                    result = self.run_ctl(script, None, 'check', ENCLAVE_ENV=str(self.env_file))
                    if refusal is None:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('3 enclaves of 4096 MiB fit', result.stdout)
                    else:
                        self.assert_refused(result, refusal)

    def test_check_refuses_a_line_that_is_not_plain(self):
        # In each file, a reader that skips the line that is not plain gets
        # ENCLAVE_MEMORY=4096, which the pool holds.
        for text, line in (
                # systemd ignores an export line.
                (b'ENCLAVE_MEMORY=4096\nexport ENCLAVE_MEMORY=8192\n', 2),
                # systemd gives start 8192. After a backslash at the end of a
                # line or an open quote, the value of KMS_REGION continues on
                # the next line.
                (b'ENCLAVE_MEMORY=8192\nKMS_REGION=eu-central-1\\\nENCLAVE_MEMORY=4096\n', 2),
                (b'ENCLAVE_MEMORY=8192\nKMS_REGION="eu-central-1\nENCLAVE_MEMORY=4096\n"\n', 2),
                (b"ENCLAVE_MEMORY=8192\nKMS_REGION='eu-central-1\nENCLAVE_MEMORY=4096\n'\n", 2),
                # systemd gives start 8192. A carriage return ends a line, also
                # in a comment.
                (b'ENCLAVE_MEMORY=4096\n# old\rENCLAVE_MEMORY=8192\n', 2),
                (b'ENCLAVE_MEMORY=4096\nKMS_REGION=eu-central-1\rENCLAVE_MEMORY=8192\n', 2),
                # systemd gives start 8192. It removes the backslash and joins
                # the quoted part to the rest of the value.
                (b'ENCLAVE_MEMORY=4096\nENCLAVE_MEMORY=81\\92\n', 2),
                (b'ENCLAVE_MEMORY=4096\nENCLAVE_MEMORY="81"92\n', 2),
                # systemd ignores the first key of a file that starts with a
                # byte order mark. It refuses a file that is not UTF-8, and
                # the unit does not start.
                (b'\xef\xbb\xbfENCLAVE_MEMORY=4096\n', 1),
                (b'ENCLAVE_MEMORY=4096\nKMS_SEED_ID=caf\xe9\n', 2),
                # systemd refuses a file with a NUL byte, and awk can miss
                # that byte.
                (b'ENCLAVE_MEMORY=8192\nKMS_SEED_ID=seed\x00\nENCLAVE_MEMORY=4096\n', 2),
                # systemd cannot start the unit with a value of more than
                # 128 KiB or with a much larger file. check refuses a line of
                # more than 4096 bytes and a file of more than 65536 bytes.
                (b'ENCLAVE_MEMORY=4096\nKMS_SEED_ID=' + b'x' * 140000 + b'\n', 2),
                (b'ENCLAVE_MEMORY=4096\n' + b'# note\n' * 10000, 9361),
                # systemd gives start 8192. A quote alone, or a quote after a
                # quoted part, opens a value that continues on the next line.
                (b'ENCLAVE_MEMORY=8192\nKMS_REGION="\nENCLAVE_MEMORY=4096\nKMS_SEED_ID="seed-1"\n', 2),
                (b'ENCLAVE_MEMORY=8192\nKMS_REGION="eu-central-1" "\nENCLAVE_MEMORY=4096\n'
                 b'KMS_SEED_ID="seed-1"\n', 2),
                # systemd before version 254 gives start 8192. After a backslash
                # at the end of a comment line, the comment continues on the
                # next line.
                (b'ENCLAVE_MEMORY=8192\n# was 8192 before the resize \\\nENCLAVE_MEMORY=4096\n', 2)):
            self.write_env(text)
            # gawk in a UTF-8 locale does not see a byte that is not UTF-8.
            for script, locale in ((s, l) for s in self.scripts() for l in ('C', 'C.UTF-8')):
                with self.subTest(script=script.name, text=text, locale=locale):
                    result = self.run_ctl(script, None, 'check', ENCLAVE_ENV=str(self.env_file),
                                          LC_ALL=locale)
                    self.assert_refused(
                        result, f'line {line} of {self.env_file} is not a plain line')
                    self.assertIn('Write the file again with plain KEY=value lines', result.stderr)

    def test_check_takes_its_keys_from_the_env_file_only(self):
        # systemd does not give start the environment of the shell that runs
        # check. A key that is not in the file gets its default.
        self.write_env(b'')
        for script in self.scripts():
            with self.subTest(script=script.name):
                result = self.run_ctl(script, '8192', 'check', ENCLAVE_ENV=str(self.env_file),
                                      ENCLAVE_CIDS='16 18 20')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('1 enclave of 4096 MiB fit', result.stdout)
        # systemd does not start the unit when the file is missing. check also
        # cannot see the values in a file that it cannot read.
        unreadable = self.base / 'unreadable.env'
        unreadable.write_bytes(b'ENCLAVE_MEMORY=4096\n')
        unreadable.chmod(0)
        paths = (self.base / 'absent.env', self.base) + ((unreadable,) if os.geteuid() else ())
        for path in paths:
            for script in self.scripts():
                with self.subTest(script=script.name, path=path.name):
                    result = self.run_ctl(script, None, 'check', ENCLAVE_ENV=str(path))
                    self.assert_refused(result, f'cannot read {path}.')

    def test_check_reads_the_file_that_deploy_host_writes(self):
        # bash expands the heredoc of deploy-host.sh as on a host. The values
        # are paths, a URL, an ARN, an address and numbers. Some are empty.
        heredoc = re.search(r'cat > /etc/utexo/enclave\.env <<EOF\n(.*?\nEOF\n)',
                            HOST.read_text(), re.S)
        self.assertTrue(heredoc, 'enclave.env heredoc not found in deploy-host.sh')
        self.write_pool(24576)
        self.write_pages(gib=24)
        optional = dict(
            ELECTRUM_URL='https://user%40example.org:p%3Aw@esplora.example.org:8443'
                         '/api?network=bitcoin&limit=25',
            EVM_RPC_TLS_CA_DER_FILE='',
            KMS_KEY_ARN='arn:aws:kms:eu-central-1:123456789012:key/'
                        '0f0e0d0c-0b0a-0908-0706-050403020100',
            KMS_REGION='eu-central-1', KMS_SEED_ID='seed-1',
            KMS_EXPECTED_EVM_ADDRESS='0x52908400098527886E0F7030069857D2E4169EE7')
        for empty in (False, True):
            values = dict(
                EIF='/home/ubuntu/cluster/utexo-bridge-enclave.eif', ENCLAVE_CPU_COUNT='2',
                ENCLAVE_MEMORY='8192', NITRO_ALLOCATOR_CONFIG=str(self.pool),
                NITRO_HUGEPAGES_DIR=str(self.pages), ENCLAVE_DEBUG_MODE='0',
                DIR='/home/ubuntu/cluster',
                **{key: '' if empty else value for key, value in optional.items()})
            subprocess.run(['bash', '-c', 'set -eu\nCIDS=(16 18 20)\ncat > "$OUT" <<EOF\n'
                            + heredoc.group(1)],
                           env=dict(values, OUT=str(self.env_file), PATH=os.environ['PATH']),
                           check=True)
            for script in self.scripts():
                with self.subTest(script=script.name, empty=empty):
                    # The environment gives other values. check takes the ones in the file.
                    result = self.run_ctl(script, '4096', 'check', ENCLAVE_ENV=str(self.env_file),
                                          ENCLAVE_CIDS='16',
                                          NITRO_ALLOCATOR_CONFIG=str(self.base / 'absent.yaml'),
                                          NITRO_HUGEPAGES_DIR=str(self.base / 'absent'))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('3 enclaves of 8192 MiB fit: memory_mib 24576 MiB, hugepages '
                                  f'24576 MiB, values from {self.env_file}', result.stdout)

    def test_a_missing_allocator_file_is_refused(self):
        for script in self.scripts():
            with self.subTest(script=script.name):
                result = self.run_ctl(script, None, 'check',
                                      NITRO_ALLOCATOR_CONFIG=str(self.base / 'absent.yaml'))
                self.assert_refused(result, 'cannot read memory_mib from')

    def test_deploy_host_refuses_before_any_step(self):
        for cids in ('16 16', '16 22', ' '):
            with self.subTest(cids=cids):
                self.assert_refused(self.run_host(ENCLAVE_CIDS=cids), 'ENCLAVE_CIDS must')
        for memory, text in (('3584', 'is below the 4096 MiB minimum'),
                             ('4g', 'must be a whole number of MiB'),
                             ('010000', 'must be a whole number of MiB'),
                             ('4608', 'is not a whole number of GiB')):
            with self.subTest(memory=memory):
                self.assert_refused(self.run_host(ENCLAVE_MEMORY=memory), text)
        for pool, gib, text in ((10752, 12, f'memory_mib in {self.pool} is 10752 MiB'),
                                (None, 12, 'cannot read memory_mib from'),
                                (12288, 9, 'the kernel holds 9216 MiB of hugepages')):
            with self.subTest(pool=pool, gib=gib):
                if pool is None:
                    self.pool.unlink()
                else:
                    self.write_pool(pool)
                self.write_pages(gib=gib)
                self.assert_refused(self.run_host(ENCLAVE_CIDS='16 18 20'), text)
        # The default one-enclave deployment needs only its own pool. The script
        # then stops at the mTLS files, the first step after the checks. It
        # declares associative arrays before that, which bash 3 does not have.
        if not bash_expands_empty_arrays():
            return
        self.write_pool(4096)
        self.write_pages(gib=4)
        result = self.run_host(GRPC_HOST='10.0.0.1', PARENT_TLS_DIR=str(self.base / 'tls'))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('provision readable mTLS file', result.stdout + result.stderr)
        self.assertFalse(self.calls.exists(), 'nitro-cli ran')

    def test_the_embedded_copy_equals_the_standalone_one(self):
        standalone, embedded = CTL.read_text(), embedded_ctl()
        for name, block in SHARED_BLOCKS.items():
            with self.subTest(block=name):
                ours, theirs = block.search(standalone), block.search(embedded)
                self.assertTrue(ours and theirs, f'{name} block not found')
                self.assertEqual(ours.group(0), theirs.group(0))

    def test_deploy_host_reads_the_allocator_file_with_the_same_function(self):
        # deploy-host.sh has a third copy of file_pool_mib, at the top level.
        # All copies must read memory_mib as the allocator reads it.
        function = re.compile(r'\nfile_pool_mib\(\) \{\n.*?\n\}\n', re.S)
        ours, theirs = function.findall(CTL.read_text()), function.findall(HOST.read_text())
        self.assertEqual(len(ours), 1)
        self.assertEqual(theirs, ours * 2)


if __name__ == '__main__':
    unittest.main()
