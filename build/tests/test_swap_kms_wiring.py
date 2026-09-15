"""Exercise swap build configuration without Docker, Nitro, AWS, or builds."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
KMS_CONFIG = {
    "SWAP_KMS_KEY_ARN": "arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "SWAP_KMS_REGION": "eu-central-1",
    "SWAP_KMS_SEED_ID": "swaps-test",
    "SWAP_KMS_EXPECTED_EVM_ADDRESS": "0x1111111111111111111111111111111111111111",
}
KMS_NAMES = tuple(KMS_CONFIG)
REQUIRED_KMS_NAMES = tuple(name for name in KMS_CONFIG if name != "SWAP_KMS_EXPECTED_EVM_ADDRESS")


class SwapBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="swap-build-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.log = self.base / "docker.jsonl"
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("SWAP_KMS_")}
        self.env.update({
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "OUT_DIR": str(self.base / "output"),
            "GITHUB_TOKEN": "fixture-not-a-real-token",
            "SOURCE_DATE_EPOCH": "1700000000",
            "TEST_DOCKER_LOG": str(self.log),
            "TEST_DOCKER_EXIT": "73",
        })
        docker = self.bin / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['TEST_DOCKER_LOG'], 'a') as log:\n"
            "    json.dump({'argv':sys.argv[1:], 'kms_env':{key:value for key,value in os.environ.items() if key.startswith('SWAP_KMS_')}}, log)\n"
            "    log.write('\\n')\n"
            "raise SystemExit(int(os.environ['TEST_DOCKER_EXIT']))\n"
        )
        docker.chmod(0o700)
        for name in ("nitro-cli", "jq"):
            executable = self.bin / name
            executable.write_text("#!/bin/sh\nexit 99\n")
            executable.chmod(0o700)

    def logs(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_script(self, dockerfile, config):
        return subprocess.run(
            ["bash", str(ROOT / "build/build-enclave.sh")],
            cwd=ROOT, env=dict(self.env, DOCKERFILE=dockerfile, **config),
            capture_output=True, text=True,
        )

    def run_make(self, target, config, assignments=()):
        return subprocess.run(
            ["make", target, *assignments], cwd=ROOT,
            env=dict(self.env, TEST_DOCKER_EXIT="0", **config),
            capture_output=True, text=True,
        )

    def test_swap_script_passes_all_measured_pins(self):
        for dockerfile in ("Dockerfile.enclave", "Dockerfile.enclave.rgb"):
            with self.subTest(dockerfile=dockerfile):
                result = self.run_script(dockerfile, KMS_CONFIG)
                self.assertEqual(result.returncode, 73, result.stderr)
                arguments = self.logs()[-1]["argv"]
                for name, value in KMS_CONFIG.items():
                    self.assertIn(f"{name}={value}", arguments)

    def test_swap_script_accepts_automatic_creation_without_an_identity_pin(self):
        config = dict(KMS_CONFIG)
        del config["SWAP_KMS_EXPECTED_EVM_ADDRESS"]
        result = self.run_script("Dockerfile.enclave.rgb", config)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("SWAP_KMS_EXPECTED_EVM_ADDRESS=", self.logs()[0]["argv"])

    def test_missing_swap_pins_fail_before_docker_runs(self):
        for name in REQUIRED_KMS_NAMES:
            with self.subTest(name=name):
                config = {key: value for key, value in KMS_CONFIG.items() if key != name}
                result = self.run_script("Dockerfile.enclave.rgb", config)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertEqual(self.logs(), [])

    def test_other_flow_scripts_neither_require_nor_pass_kms_build_arguments(self):
        for dockerfile in ("Dockerfile.enclave.mint-burn", "Dockerfile.enclave.ccd", "Dockerfile.enclave.bfa"):
            with self.subTest(dockerfile=dockerfile):
                result = self.run_script(dockerfile, {})
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertFalse(any(argument.startswith("SWAP_KMS_") for argument in self.logs()[-1]["argv"]))

    def test_make_passes_environment_pins_to_both_swap_tags(self):
        for target in ("build_enclave", "build_enclave_rgb"):
            with self.subTest(target=target):
                result = self.run_make(target, KMS_CONFIG)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.logs()[-2:]
                self.assertEqual(len(calls), 2)
                for call in calls:
                    for name in KMS_NAMES:
                        index = call["argv"].index(name)
                        self.assertEqual(call["argv"][index - 1], "--build-arg")
                    self.assertEqual(call["kms_env"], KMS_CONFIG)

    def test_make_accepts_command_line_pins_and_exports_them_without_shell_interpolation(self):
        result = self.run_make("build_enclave_rgb", {}, [f"{name}={value}" for name, value in KMS_CONFIG.items()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs()[0]["kms_env"], KMS_CONFIG)

    def test_make_accepts_automatic_creation_without_an_identity_pin(self):
        config = {key: value for key, value in KMS_CONFIG.items() if key != "SWAP_KMS_EXPECTED_EVM_ADDRESS"}
        result = self.run_make("build_enclave", config)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logs()[0]["kms_env"], dict(config, SWAP_KMS_EXPECTED_EVM_ADDRESS=""))

    def test_ccd_make_target_does_not_gain_kms_env_or_build_arguments(self):
        result = self.run_make("build_enclave_ccd", {})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.logs()), 2)
        for call in self.logs():
            self.assertEqual(call["kms_env"], {})
            self.assertFalse(any(argument.startswith("SWAP_KMS_") for argument in call["argv"]))


if __name__ == "__main__":
    unittest.main()
