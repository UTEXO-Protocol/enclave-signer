"""The parent unit that deploy-host.sh installs keeps its memory limit."""
from pathlib import Path
import re
import unittest

HOST = Path(__file__).resolve().parents[2] / 'deploy/deploy-host.sh'


def parent_unit():
    match = re.search(
        r"cat > \"/etc/systemd/system/utexo-parent@\$ENCLAVE_CID\.service\" <<'EOF'\n(.*?)\nEOF\n",
        HOST.read_text(), re.S)
    assert match, 'parent unit not found in deploy-host.sh'
    return match.group(1).splitlines()


class ParentUnitTests(unittest.TestCase):
    def test_the_parent_unit_has_a_memory_limit_and_restarts(self):
        # A parent above the limit stops alone, and systemd starts it again.
        unit = parent_unit()
        self.assertIn('MemoryMax=1G', unit)
        self.assertIn('Restart=on-failure', unit)


if __name__ == '__main__':
    unittest.main()
