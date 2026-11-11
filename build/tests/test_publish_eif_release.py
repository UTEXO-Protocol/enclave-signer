import importlib.util
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("publisher", ROOT / "build/publish-eif-release.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
SHA = "a" * 40
TAG = "stage-signet-v0.1.0"
REPO = "example/signer"
RUN = "12345"


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundles = self.root / "s3"
        self.references = self.root / "actions"
        self.output = self.root / "output"
        for role, digit in (("burn", "1"), ("mint", "2")):
            directory = self.bundles / role
            directory.mkdir(parents=True)
            eif = f"utexo-bridge-enclave-{role}.eif"
            (directory / eif).write_bytes(f"fixture-{role}-eif".encode())
            for name in ("utexo-bridge-parent", "utexo-bridge-parent-cli"):
                (directory / name).write_bytes(b"fixture-host-binary")
            self.write_json(directory / "PCR.json", {
                "HashAlgorithm": "Sha384 { ... }", "PCR0": digit * 96,
                "PCR1": "3" * 96, "PCR2": "4" * 96})
            self.write_json(directory / "IMAGE-ENV.json", [
                "BITCOIN_NETWORK=signet", "EVM_CHAIN_ID=42161", "RGB_ASSET_ID=rgb:test-asset"])
            self.write_json(directory / "metadata.json", {
                "git_sha": SHA, "variant": f"rgb-{role}", "build_profile": "stage-signet",
                "eif_name": eif, "run_id": RUN, "rgb_asset_id": "rgb:test-asset"})
            for manifest, names in (("SHA256SUMS", [eif]), ("HOST-SHA256SUMS", [
                    "utexo-bridge-parent", "utexo-bridge-parent-cli"])):
                (directory / manifest).write_text("".join(
                    f"{publisher.digest(directory / name)}  {name}\n" for name in names))
            shutil.copytree(directory, self.references / role)

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value))

    def package(self):
        publisher.package(self.bundles, self.references, self.output, SHA, RUN, TAG, REPO, "stage")

    def edit_both(self, role, name, edit):
        for root in (self.bundles, self.references):
            path = root / role / name
            value = json.loads(path.read_text())
            self.write_json(path, edit(value))

    def test_complete_packages_and_measurements(self):
        self.package()
        assets = self.output / "assets"
        publisher.verify_sums(assets, "SHA256SUMS", {
            f"{TAG}-burn.tar.gz", f"{TAG}-mint.tar.gz", "PCR-burn.json", "PCR-mint.json",
            "release-manifest.json"})
        manifest = json.loads((assets / "release-manifest.json").read_text())
        self.assertEqual(manifest["git_sha"], SHA)
        self.assertEqual(manifest["bitcoin_network"], "signet")
        for role in publisher.ROLES:
            with tarfile.open(assets / f"{TAG}-{role}.tar.gz") as archive:
                self.assertEqual(set(archive.getnames()), {
                    f"{role}/{name}" for name in publisher.file_names(role)})
                self.assertEqual(archive.getmember(f"{role}/utexo-bridge-parent-cli").mode, 0o755)
        notes = (self.output / "notes.md").read_text()
        self.assertIn("Public Signet", notes)
        self.assertIn("1" * 96, notes)
        self.assertIn("2" * 96, notes)
        self.assertIn("does not deploy", notes)

    def test_missing_mint_prevents_any_package(self):
        (self.bundles / "mint/PCR.json").unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            self.package()
        self.assertFalse(self.output.exists())

    def test_s3_overwrite_is_rejected_even_with_new_checksum(self):
        path = self.bundles / "burn/utexo-bridge-enclave-burn.eif"
        path.write_bytes(b"replacement-build")
        (path.parent / "SHA256SUMS").write_text(f"{publisher.digest(path)}  {path.name}\n")
        with self.assertRaisesRegex(ValueError, "differs from"):
            self.package()

    def test_invalid_checksum_in_both_sources_is_rejected(self):
        for root in (self.bundles, self.references):
            (root / "burn/SHA256SUMS").write_text("0" * 64 + "  utexo-bridge-enclave-burn.eif\n")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            self.package()

    def test_checksum_cannot_escape_bundle(self):
        for root in (self.bundles, self.references):
            (root / "mint/HOST-SHA256SUMS").write_text("0" * 64 + "  ../../file\n")
        with self.assertRaisesRegex(ValueError, "Invalid checksum"):
            self.package()

    def test_wrong_role_commit_profile_or_run(self):
        for key, value in (("variant", "rgb-burn"), ("git_sha", "b" * 40),
                           ("build_profile", "default"), ("run_id", "456")):
            with self.subTest(key=key):
                files = [root / "mint/metadata.json" for root in (self.bundles, self.references)]
                originals = [path.read_text() for path in files]
                self.edit_both("mint", "metadata.json", lambda data: dict(data, **{key: value}))
                with self.assertRaisesRegex(ValueError, "Wrong mint metadata"):
                    self.package()
                for path, original in zip(files, originals):
                    path.write_text(original)

    def test_zero_pcr_rejected(self):
        self.edit_both("burn", "PCR.json", lambda data: dict(data, PCR0="0" * 96))
        with self.assertRaisesRegex(ValueError, "Invalid or zero"):
            self.package()

    def test_debug_feature_build_is_rejected(self):
        self.edit_both("burn", "metadata.json", lambda data: dict(data, debug_features="allow-debug-pcrs"))
        with self.assertRaisesRegex(ValueError, "Debug build"):
            self.package()

    def test_mainnet_mislabeled_as_signet_rejected(self):
        self.edit_both("mint", "IMAGE-ENV.json", lambda data: [
            item.replace("signet", "bitcoin") for item in data])
        with self.assertRaisesRegex(ValueError, "Expected Public Signet"):
            self.package()

    def test_different_assets_rejected(self):
        self.edit_both("mint", "IMAGE-ENV.json", lambda data: [
            item.replace("test-asset", "other-asset") for item in data])
        self.edit_both("mint", "metadata.json", lambda data: dict(data, rgb_asset_id="rgb:other-asset"))
        with self.assertRaisesRegex(ValueError, "different assets"):
            self.package()

    def test_wrong_run_provenance(self):
        good = {"status": "completed", "conclusion": "success", "head_sha": SHA,
                "path": ".github/workflows/build-eif.yml", "event": "workflow_dispatch",
                "head_repository": {"full_name": REPO}}
        publisher.validate_run(good, REPO, SHA)
        for key, value in (("conclusion", "failure"), ("status", "in_progress"),
                           ("head_sha", "b" * 40), ("event", "pull_request"),
                           ("path", ".github/workflows/other.yml"),
                           ("head_repository", {"full_name": "fork/signer"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                publisher.validate_run(dict(good, **{key: value}), REPO, SHA)

    def test_existing_tag_rejected(self):
        with patch.object(publisher, "api", return_value={"ref": "existing"}):
            with self.assertRaisesRegex(ValueError, "already exists"):
                publisher.unused_tag(REPO, TAG)

    def test_invalid_input_cannot_be_shell_or_ref(self):
        env = {"GH_REPO": REPO, "RELEASE_SHA": SHA, "RELEASE_TAG": TAG}
        for key, value in (("RELEASE_TAG", "v1.0.0"), ("RELEASE_SHA", "stage"),
                           ("RELEASE_TAG", "stage-signet-v1.0.0;echo secret")):
            with patch.dict(os.environ, dict(env, **{key: value})), self.assertRaises(ValueError):
                publisher.inputs()

    def publish_with_fake_upload(self, corrupt=False):
        self.package()
        calls = []

        def fake_run(*args):
            calls.append(args)
            if args[:3] == ("gh", "release", "download"):
                destination = Path(args[args.index("--dir") + 1])
                for path in (self.output / "assets").iterdir():
                    shutil.copyfile(path, destination / path.name)
                if corrupt:
                    (destination / "PCR-burn.json").write_text("corrupt")
            return ""

        env = {"GH_REPO": REPO, "RELEASE_SHA": SHA, "RELEASE_TAG": TAG}
        with patch.dict(os.environ, env), patch.object(publisher, "OUTPUT", self.output), \
                patch.object(publisher, "unused_tag"), patch.object(publisher, "run", side_effect=fake_run):
            if corrupt:
                with self.assertRaisesRegex(ValueError, "Uploaded asset mismatch"):
                    publisher.publish()
            else:
                publisher.publish()
        return calls

    def test_publish_only_after_complete_upload_verification(self):
        calls = self.publish_with_fake_upload()
        create = next(call for call in calls if call[:3] == ("gh", "release", "create"))
        self.assertIn("--draft", create)
        self.assertIn("--verify-tag", create)
        self.assertIn("--latest=false", create)
        self.assertEqual(calls[-1][:3], ("gh", "release", "edit"))
        self.assertIn("--draft=false", calls[-1])

    def test_failed_upload_never_publishes(self):
        calls = self.publish_with_fake_upload(corrupt=True)
        self.assertFalse(any(call[:3] == ("gh", "release", "edit") for call in calls))


if __name__ == "__main__":
    unittest.main()
