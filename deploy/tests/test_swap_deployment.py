"""Offline policy gate regressions; mock describe-eif only inside these tests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("swap_deployment", Path(__file__).resolve().parents[1] / "validate-swap-kms-deployment.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def measurement(label):
    return hashlib.sha384(label.encode()).hexdigest()


def approval(phase="transition"):
    images = [dict(eif="bootstrap.eif", pcr_file="bootstrap-PCR.json", sha256=hashlib.sha256(b"bootstrap").hexdigest(), pcr0=measurement("bootstrap"), mode="bootstrap", expected_evm_address=""), dict(eif="restore.eif", pcr_file="restore-PCR.json", sha256=hashlib.sha256(b"restore").hexdigest(), pcr0=measurement("restore"), mode="restore", expected_evm_address="0x7d024ab55b3b8a48d252fed98a48efbc559e2c31")]
    if phase == "bootstrap":
        images = images[:1]
    elif phase == "restore":
        images = images[1:]
    return dict(version=1, phase=phase, approved_by="release-reviewer", approval_reference="release-42", account_id="947263850162", signer_role="swap-signer", key_admin_role="swap-key-admin", key_arn="arn:aws:kms:eu-central-1:947263850162:key/dae39a52-e6c4-4ec9-87db-cccf8d7a0912", region="eu-central-1", seed_id="swap-signer-1", bitcoin_network="bitcoin", bucket="swap-seed-custody", object_key="swaps/signer-1/seed.kms", images=images)


class DeploymentApprovalTests(unittest.TestCase):
    def test_lifecycle_permissions_and_retirement(self):
        for phase in ("bootstrap", "transition", "restore"):
            a = approval(phase)
            m.validate_approval(a)
            policies = m.rendered_policies(a)
            for policy in policies.values():
                m.compare_policy(policy, policy)
            statements = {s["Sid"]: s for s in policies[m.POLICIES[0]]["Statement"]}
            pcrs = [image["pcr0"] for image in a["images"]]
            self.assertEqual(statements["AllowAttestedSeedRecovery"]["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"], pcrs)
            self.assertEqual(statements["DenyDecryptOutsideApprovedImages"]["Condition"]["StringNotEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"], pcrs)
            if phase == "restore":
                self.assertNotIn("AllowBootstrapGenerateDataKey", statements)
                self.assertNotIn("Condition", statements["DenySeedGenerationAfterBootstrap"])
            else:
                self.assertIn("AllowBootstrapGenerateDataKey", statements)

    def test_multiple_restore_versions_require_same_pinned_identity(self):
        a = approval("restore")
        new = dict(a["images"][0], eif="new.eif", pcr0=measurement("new"))
        a["images"].append(new)
        m.validate_approval(a)
        new["expected_evm_address"] = "0x6d024ab55b3b8a48d252fed98a48efbc559e2c31"
        with self.assertRaises(m.ValidationError):
            m.validate_approval(a)

    def test_rejects_placeholders_roles_wildcards_fixture_accounts_and_context(self):
        for field, value in (("account_id", "123456789012"), ("account_id", "111122223333"), ("seed_id", "REPLACE_SEED_ID"), ("seed_id", "official-sdk-build-validation-only"), ("signer_role", "swap-key-admin"), ("region", "us-gov-west-1"), ("bitcoin_network", "mainnet"), ("object_key", "swaps/*"), ("object_key", "${aws:username}"), ("bucket", "bad*bucket"), ("approval_reference", ""), ("key_arn", "arn:aws:kms:us-east-1:947263850162:key/dae39a52-e6c4-4ec9-87db-cccf8d7a0912")):
            with self.subTest(field=field, value=value):
                a = approval()
                a[field] = value
                with self.assertRaises(m.ValidationError):
                    m.validate_approval(a)

    def test_rejects_debug_fixture_pcrs_empty_pins_and_wrong_phase(self):
        for field, value in (("pcr0", "0" * 96), ("pcr0", "ab" * 48), ("sha256", "f" * 64), ("expected_evm_address", ""), ("expected_evm_address", "0x" + "0" * 40), ("mode", "bootstrap")):
            a = approval("restore")
            a["images"][0][field] = value
            with self.subTest(field=field), self.assertRaises(m.ValidationError):
                m.validate_approval(a)

    def test_policy_tampering_or_stale_pcr_is_rejected(self):
        policies = m.rendered_policies(approval())
        for filename, expected in policies.items():
            for mutation in ("remove_deny", "extra_allow", "wrong_role", "changed_scope"):
                candidate = copy.deepcopy(expected)
                statements = candidate["Statement"]
                if mutation == "remove_deny":
                    statements.remove(next(s for s in statements if s["Effect"] == "Deny"))
                elif mutation == "extra_allow":
                    statements.append(dict(Sid="Backdoor", Effect="Allow", Action="*", Resource="*"))
                elif mutation == "wrong_role":
                    statements[0]["Principal"] = {"AWS": "arn:aws:iam::947263850162:role/unapproved"}
                else:
                    statements[0]["Resource"] = "unapproved"
                with self.subTest(filename=filename, mutation=mutation), self.assertRaises(m.ValidationError):
                    m.compare_policy(candidate, expected)
        key = copy.deepcopy(policies[m.POLICIES[0]])
        statement = next(s for s in key["Statement"] if s["Sid"] == "AllowAttestedSeedRecovery")
        statement["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"] = [measurement("stale")]
        with self.assertRaises(m.ValidationError):
            m.compare_policy(key, policies[m.POLICIES[0]])

    def test_bucket_denies_protection_changes_and_keeps_global_delete_deny(self):
        policies = m.rendered_policies(approval())
        statements = {s["Sid"]: s for s in policies[m.POLICIES[1]]["Statement"]}
        bucket = statements["DenySignerStoragePolicyAndRetentionChanges"]
        self.assertEqual(bucket["Resource"], "arn:aws:s3:::swap-seed-custody")
        self.assertTrue({"s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls", "s3:PutBucketAcl", "s3:PutEncryptionConfiguration", "s3:PutReplicationConfiguration"}.issubset(bucket["Action"]))
        obj = statements["DenySignerObjectAccessAndRetentionChanges"]
        self.assertEqual(obj["Resource"], "arn:aws:s3:::swap-seed-custody/swaps/signer-1/seed.kms")
        self.assertTrue({"s3:PutObjectAcl", "s3:PutObjectVersionAcl", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold"}.issubset(obj["Action"]))
        self.assertEqual(statements["DenySeedDeletionIncludingVersionDeletion"]["Principal"], "*")
        self.assertNotIn("Condition", statements["DenySeedDeletionIncludingVersionDeletion"])

    def test_full_role_is_explicitly_denied_other_actions_and_resources(self):
        policy = m.rendered_policies(approval())[m.POLICIES[2]]
        statements = {s["Sid"]: s for s in policy["Statement"]}
        self.assertEqual(set(statements["DenyActionsOutsideDedicatedSeedRole"]["NotAction"]), {"kms:GenerateDataKey", "kms:Decrypt", "s3:GetObject", "s3:PutObject", "s3:ListBucket"})
        self.assertEqual(statements["DenyOtherKmsKeys"]["NotResource"], approval()["key_arn"])
        self.assertEqual(statements["DenyOtherObjects"]["NotResource"], "arn:aws:s3:::swap-seed-custody/swaps/signer-1/seed.kms")

    def test_live_gate_requires_unapproved_and_debug_pcr_evidence(self):
        a = approval("restore")
        evidence = dict(approval_reference=a["approval_reference"], checks={name: dict(passed=True, evidence="retained-aws-request-id-and-attestation-record") for name in m.LIVE_CHECKS})
        m.validate_live_evidence(evidence, a)
        for check in ("unapproved_pcr_denied", "debug_pcr_denied", "independent_backup_recovery"):
            altered = copy.deepcopy(evidence)
            del altered["checks"][check]
            with self.assertRaises(m.ValidationError):
                m.validate_live_evidence(altered, a)
        evidence["checks"]["unapproved_pcr_denied"]["passed"] = False
        with self.assertRaises(m.ValidationError):
            m.validate_live_evidence(evidence, a)

    def test_duplicate_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"version":1,"version":2}')
            with self.assertRaises(m.ValidationError):
                m.read_json(path)


class ArtifactBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.approved = approval("restore")
        self.image = self.approved["images"][0]
        (self.directory / self.image["eif"]).write_bytes(b"restore")
        self.measurements = {"PCR0": self.image["pcr0"], "PCR1": measurement("kernel"), "PCR2": measurement("app")}
        (self.directory / self.image["pcr_file"]).write_text(json.dumps(self.measurements))
        env = dict(zip(m.PUBLIC_PINS, (self.approved["key_arn"], self.approved["region"], self.approved["seed_id"], "0", self.image["expected_evm_address"])))
        env["BITCOIN_NETWORK"] = "bitcoin"
        self.info = dict(CheckCRC=True, EifVersion=4, IsSigned=False, Measurements=self.measurements, Metadata={"DockerInfo": {"Config": {"Env": [f"{k}={v}" for k, v in env.items()]}}})

    def verify(self):
        return m.verify_image(self.approved, self.image, self.directory, describe=lambda _: self.info)

    def test_recomputes_digest_and_pcr_and_checks_baked_public_config(self):
        self.assertEqual(self.verify()["pcr0"], self.image["pcr0"])

    def test_actual_eif_content_must_match_independent_approval(self):
        (self.directory / self.image["eif"]).write_bytes(b"other image")
        with self.assertRaises(m.ValidationError):
            self.verify()

    def test_wrong_baked_key_seed_network_mode_address_is_rejected(self):
        for name in (*m.PUBLIC_PINS, "BITCOIN_NETWORK"):
            original = copy.deepcopy(self.info)
            env = self.info["Metadata"]["DockerInfo"]["Config"]["Env"]
            env[:] = [f"{name}=wrong" if e.startswith(name + "=") else e for e in env]
            with self.subTest(name=name), self.assertRaises(m.ValidationError):
                self.verify()
            self.info = original

    def test_missing_metadata_bad_crc_or_signed_image_check_is_rejected(self):
        for field, value in (("Metadata", {}), ("CheckCRC", False), ("IsSigned", True)):
            original = copy.deepcopy(self.info)
            self.info[field] = value
            with self.subTest(field=field), self.assertRaises(m.ValidationError):
                self.verify()
            self.info = original

    def test_stale_pcr_file_and_approved_pcr_are_rejected(self):
        (self.directory / self.image["pcr_file"]).write_text(json.dumps(dict(self.measurements, PCR0=measurement("old"))))
        with self.assertRaises(m.ValidationError):
            self.verify()
        (self.directory / self.image["pcr_file"]).write_text(json.dumps(self.measurements))
        self.image["pcr0"] = measurement("different approved")
        with self.assertRaises(m.ValidationError):
            self.verify()

    def test_static_credentials_duplicate_and_test_environment_are_rejected(self):
        for extra in ("AWS_SECRET_ACCESS_KEY=should-never-be-present", "SWAP_KMS_TEST_ENDPOINT=127.0.0.1", "SWAP_KMS_ALLOW_CREATE=1"):
            env = self.info["Metadata"]["DockerInfo"]["Config"]["Env"]
            env.append(extra)
            with self.subTest(extra=extra), self.assertRaises(m.ValidationError):
                self.verify()
            env.pop()


if __name__ == "__main__":
    unittest.main()
