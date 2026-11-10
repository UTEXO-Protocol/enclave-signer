"""The burn-signer CI job skips the unit-test modules in build/ci-mint-only-tests.txt.

Each module must run the same code in the mint and burn builds, and the mint
build must compile it. These tests fail when a listed module, its declaration,
or a module it names gains role code. The mint-signer job also fails when a
listed module runs no test there.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'enclave/src'
LIST = ROOT / 'build/ci-mint-only-tests.txt'
ROLE = re.compile(
    r'feature\s*=\s*"(mint-signer|burn-signer|kms-persistence)"|\bevm_to_rgb\b|\brgb_to_evm\b'
)
# The crate root holds the role guards and module declarations (checked one by
# one below). The error type has one KMS variant; its other variants do not
# change with the role.
EXEMPT = {SRC / 'lib.rs', SRC / 'main.rs', SRC / 'error.rs'}
PATH = re.compile(r'\b(crate|super)((?:::\w+)+)')


def file_of(parts):
    """The file that holds module `parts`, or of its nearest parent with one."""
    for k in range(len(parts), -1, -1):
        base = SRC.joinpath(*parts[:k]) if k else SRC / 'lib'
        for candidate in (base.with_suffix('.rs'), base / 'mod.rs'):
            if candidate.is_file():
                return candidate, parts[:k]
    raise AssertionError(f'no source file for {parts}')


def listed():
    lines = LIST.read_text().splitlines()
    return [l.strip() for l in lines if l.strip() and not l.lstrip().startswith('#')]


def role_files():
    return {f for f in SRC.rglob('*.rs') if f not in EXEMPT and ROLE.search(f.read_text())}


def attributes_above(lines, index):
    out = []
    while index > 0 and lines[index - 1].strip().startswith(('#[', '//')):
        index -= 1
        out.append(lines[index])
    return out


class MintOnlyTests(unittest.TestCase):
    def test_every_line_names_a_test_module(self):
        for line in listed():
            with self.subTest(line=line):
                self.assertTrue(line.endswith('::'), 'end each line with :: so --skip matches only that module')
                f, _ = file_of(line[:-2].split('::'))
                self.assertRegex(f.read_text(), r'#\[(tokio::)?test', f'{f} has no test')

    def test_no_declaration_on_the_path_has_a_role_cfg(self):
        for line in listed():
            parts = line[:-2].split('::')
            for k in range(1, len(parts) + 1):
                parent, _ = file_of(parts[: k - 1])
                lines = parent.read_text().splitlines()
                decl = re.compile(r'^\s*(pub(\([^)]*\))?\s+)?mod\s+%s\b' % re.escape(parts[k - 1]))
                for i, text in enumerate(lines):
                    if decl.search(text):
                        with self.subTest(line=line, declaration='::'.join(parts[:k])):
                            self.assertIsNone(ROLE.search('\n'.join(attributes_above(lines, i))))

    def test_no_listed_module_has_or_reaches_role_code(self):
        roles = role_files()
        for line in listed():
            parts = line[:-2].split('::')
            files = [file_of(parts)]
            if parts[-1] == 'tests' and file_of(parts[:-1])[0] != files[0][0]:
                files.append(file_of(parts[:-1]))
            for f, mod in files:
                with self.subTest(line=line, file=str(f.relative_to(ROOT))):
                    text = f.read_text()
                    self.assertIsNone(ROLE.search(text), 'the module has role code')
                    for m in PATH.finditer(text):
                        # `super` is resolved one level up from the file's
                        # module: wider than Rust's rule, never narrower.
                        base = [] if m.group(1) == 'crate' else mod[:-1]
                        target = base + [p for p in m.group(2).split('::') if p and p != 'super']
                        holder, _ = file_of(target)
                        self.assertFalse(
                            holder in roles,
                            f'{m.group(0)} reaches {holder.relative_to(ROOT)}, which has role code',
                        )


if __name__ == '__main__':
    unittest.main()
