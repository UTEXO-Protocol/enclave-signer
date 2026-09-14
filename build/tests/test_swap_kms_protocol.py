"""Cross-language custody ABI and deadline guards; no SDK or AWS required."""
import ast
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


def number(expression):
    # These protocol declarations contain integers or products of integers.
    # Do not execute source when inspecting the three implementation languages.
    parts = expression.strip().strip("()").split("*")
    value = 1
    for part in parts:
        value *= int(part.strip().replace("_", ""))
    return value


def rust_constant(path, name):
    source = (ROOT / path).read_text()
    match = re.search(rf"\bconst {name}: [^=]+ = (.+);", source)
    if match is None:
        raise AssertionError(f"missing Rust protocol constant: {name}")
    expression = match[1]
    duration = re.fullmatch(r"Duration::from_secs\((\d+)\)", expression)
    return int(duration[1]) if duration else number(expression)


def c_constant(name):
    source = (ROOT / "enclave/kms-tool/main.c").read_text()
    match = re.search(rf"^#define {name} (.+)$", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing C protocol constant: {name}")
    return number(match[1])


def broker_constants():
    tree = ast.parse((ROOT / "deploy/swap-seed-broker.py").read_text())
    return {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
    }


class CustodyProtocolTests(unittest.TestCase):
    def test_ciphertext_and_frame_bounds_agree_across_processes(self):
        broker = broker_constants()
        rust = "enclave/src/swap_kms.rs"
        self.assertEqual(rust_constant(rust, "MAX_CIPHERTEXT_BYTES"), c_constant("CIPHERTEXT_LIMIT"))
        self.assertEqual(rust_constant(rust, "MAX_CIPHERTEXT_BYTES"), broker["MAX_CIPHERTEXT_BYTES"])
        self.assertEqual(rust_constant(rust, "MAX_MESSAGE_BYTES"), c_constant("MESSAGE_LIMIT"))
        self.assertEqual(rust_constant(rust, "MAX_MESSAGE_BYTES"), broker["MAX_FRAME_BYTES"])
        self.assertEqual(rust_constant(rust, "SEED_BYTES"), c_constant("SEED_BYTES"))

    def test_inner_deadlines_fit_the_outer_request_budget(self):
        persistence = "enclave/src/swap_persistence.rs"
        recovery = rust_constant(persistence, "RECOVERY_TIMEOUT")
        broker = rust_constant(persistence, "BROKER_TIMEOUT")
        self.assertLess(broker_constants()["OPERATION_TIMEOUT_SECONDS"], broker)
        self.assertLess(broker, recovery)
        self.assertLess(rust_constant("enclave/src/swap_kms.rs", "HELPER_TIMEOUT"), recovery)
        reserve = rust_constant(persistence, "RESPONSE_RESERVE")
        total = rust_constant("enclave/src/conn.rs", "TOTAL_REQUEST_TIMEOUT")
        self.assertLessEqual(recovery + reserve, total)
        self.assertLessEqual(total, rust_constant("parent/src/client.rs", "READ_TIMEOUT"))


if __name__ == "__main__":
    unittest.main()
