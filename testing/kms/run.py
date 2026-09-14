#!/usr/bin/env python3
"""Process E2E for the kms-testing branch; never contacts AWS.

Requires the pinned Python/Node tools in this directory and authenticated Git
access for the repository's private Cargo dependencies. All subprocesses receive
isolated local AWS credentials. Generated files live under .artifacts/kms-e2e.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import requests
import boto3
import cbor2
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BOOTSTRAP = "aa" * 48
RESTORE = "bb" * 48


def isolated_env():
    env = {k: v for k, v in os.environ.items() if not (
        k.startswith(("AWS_", "SWAP_", "EVM_", "GAS_", "RGB_", "BITCOIN_", "HELIOS_"))
        or k in {"ELECTRUM_URL", "ESPLORA_URL"}
        or k.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    )}
    env.update(AWS_EC2_METADATA_DISABLED="true", AWS_CONFIG_FILE=os.devnull,
               AWS_SHARED_CREDENTIALS_FILE=os.devnull, PYTHONUNBUFFERED="1")
    return env


def git_env():
    env = isolated_env()
    aliases = ["github-rgb-consensus", "github-rgb-ops", "github-rgb-schemas",
               "github-rgb-consignment", "github-federated-signer"]
    offset = int(env.get("GIT_CONFIG_COUNT", "0"))
    env["GIT_CONFIG_COUNT"] = str(offset + len(aliases))
    env["GIT_TERMINAL_PROMPT"] = "0"
    for i, alias in enumerate(aliases, offset):
        env[f"GIT_CONFIG_KEY_{i}"] = "url.https://github.com/UTEXO-Protocol/.insteadOf"
        env[f"GIT_CONFIG_VALUE_{i}"] = f"ssh://git@{alias}/UTEXO-Protocol/"
    return env


def certificates(directory):
    """Fresh local CA, with a normal verified TLS server certificate."""
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LOCAL KMS E2E ONLY")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False, key_agreement=False,
              key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "kms.eu-west-1.amazonaws.com")]))
            .issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("kms.eu-west-1.amazonaws.com"), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(ca_key, hashes.SHA256()))
    paths = {name: directory / name for name in ("ca.pem", "server.pem", "server-key.pem")}
    paths["ca.pem"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths["server.pem"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths["server-key.pem"].write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths["server-key.pem"].chmod(0o600)
    return paths


class Suite:
    def __init__(self, args):
        self.args = args
        self.artifacts = args.artifacts.resolve()
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.certs = certificates(self.artifacts)
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
        self.enclave = target / "debug/utexo-bridge-enclave"
        self.client = target / "debug/kms-e2e-client"
        parent_target = Path(os.environ.get("KMS_E2E_PARENT_TARGET_DIR", ROOT / "parent/target")).resolve()
        self.parent = parent_target / "debug/utexo-bridge-parent"
        self.grpc_client = parent_target / "debug/kms-e2e-grpc-client"
        self.http = requests.Session()
        self.http.trust_env = False
        self.control = f"http://127.0.0.1:{args.control_port}"
        self.processes = []
        self.results = []
        self.counter = 0
        self.fixture = None

    def api(self, path, data=None):
        response = self.http.request("GET" if data is None else "POST",
            self.control + path, json=data, timeout=30)
        response.raise_for_status()
        return response.json()

    def start(self, name, command, env=None, port=None):
        self.counter += 1
        log_path = self.artifacts / f"{self.counter:03d}-{name}.log"
        log = log_path.open("w")
        process = subprocess.Popen([str(v) for v in command], cwd=ROOT,
            env=env or isolated_env(), stdout=log, stderr=subprocess.STDOUT)
        self.processes.append((process, log))
        if port is not None:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError(f"{name} exited {process.returncode}; see {log_path}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        return process
                except OSError:
                    time.sleep(.05)
            raise AssertionError(f"{name} did not listen on {port}; see {log_path}")
        return process

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def cleanup(self):
        for process, log in reversed(self.processes):
            self.stop(process)
            log.close()

    @contextmanager
    def case(self, name):
        started = time.monotonic()
        print(f"RUN  {name}", flush=True)
        item = {"name": name, "status": "failed"}
        self.results.append(item)
        try:
            yield item
        except Exception as error:
            item["error"] = str(error)
            raise
        else:
            item["status"] = "passed"
            print(f"PASS {name}", flush=True)
        finally:
            item["seconds"] = round(time.monotonic() - started, 3)

    def fixture_reset(self, suffix):
        self.fixture = self.api("/setup", {"seed_id": f"swap-{suffix}",
            "bucket": "local-swap-kms-e2e", "object_key": f"seeds/{suffix}.kms"})
        return self.fixture

    def broker(self):
        f = self.fixture
        env = isolated_env()
        creds = f["credentials"]
        env.update(AWS_ACCESS_KEY_ID=creds["access_key_id"],
            AWS_SECRET_ACCESS_KEY=creds["secret_access_key"], AWS_SESSION_TOKEN=creds["session_token"],
            AWS_REGION=f["region"], AWS_DEFAULT_REGION=f["region"],
            AWS_ENDPOINT_URL_S3=f["aws_tls_endpoint"], AWS_CA_BUNDLE=str(self.certs["ca.pem"]),
            SWAP_KMS_SEED_ID=f["seed_id"], SWAP_KMS_S3_BUCKET=f["bucket"],
            SWAP_KMS_S3_KEY=f["object_key"])
        return self.start("broker", [sys.executable, ROOT / "deploy/swap-seed-broker.py",
            "--tcp", f"127.0.0.1:{self.args.broker_port}"], env, self.args.broker_port)

    def signer(self, restore_address=None, **overrides):
        f = self.fixture
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = isolated_env()
        env.update(SWAP_KMS_KEY_ARN=f["key_arn"], SWAP_KMS_REGION=f["region"],
            SWAP_KMS_SEED_ID=f["seed_id"], SWAP_KMS_ALLOW_CREATE="0" if restore_address else "1",
            SWAP_KMS_E2E_CA_PEM=str(self.certs["ca.pem"]),
            SWAP_KMS_E2E_PCR0=RESTORE if restore_address else BOOTSTRAP,
            SWAP_KMS_E2E_PORT=str(self.args.kms_port),
            SWAP_KMS_E2E_BROKER_PORT=str(self.args.broker_port),
            ENCLAVE_LISTEN_ADDR=f"127.0.0.1:{port}", BITCOIN_NETWORK="regtest",
            EVM_CHAIN_ID="1", EVM_PROXY_CONTRACT_ADDRESS="0x" + "bb" * 20,
            RGB_ASSET_ID="rgb:test", GAS_TX_ALLOWED_TO="0x" + "aa" * 20,
            GAS_TX_MAX_GAS_LIMIT="30000", GAS_TX_MAX_FEE_PER_GAS="1000",
            GAS_TX_ALLOWED_SELECTORS="deadbeef", RUST_LOG="info")
        if restore_address:
            env["SWAP_KMS_EXPECTED_EVM_ADDRESS"] = restore_address
        env.update(overrides)
        env = {key: value for key, value in env.items() if value is not None}
        process = self.start("enclave", [self.enclave], env, port)
        return process, f"127.0.0.1:{port}"

    def call(self, address, command, success=True):
        result = subprocess.run([str(self.client), "--addr", address, *command.split()],
            cwd=ROOT, env=isolated_env(), capture_output=True, text=True, timeout=40)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(f"Invalid client output {result.stdout}: {result.stderr}") from error
        assert data["ok"] is success and (result.returncode == 0) is success, data
        if not success:
            assert data["error"]["code"] != 0, data  # actual enclave refusal, not socket failure
        return data

    def failed_init(self, address):
        result = self.call(address, "init", False)
        self.call(address, "keys", False)
        self.call(address, "sign", False)
        return result

    def parent_signature(self, address, expected):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = isolated_env()
        env.update(GRPC_HOST="127.0.0.1", GRPC_PORT=str(port), ENCLAVE_ADDR=address, USE_VSOCK="0")
        parent = self.start("parent", [self.parent], env, port)
        try:
            result = subprocess.run([str(self.grpc_client), "--addr", f"http://127.0.0.1:{port}",
                "sign", expected["unsigned_tx"]], capture_output=True, text=True, timeout=30, env=isolated_env())
            data = json.loads(result.stdout)
            assert result.returncode == 0 and data["ok"], result.stderr
            assert data["signature"] == expected["signature"]
        finally:
            self.stop(parent)

    def audit(self):
        data = self.api("/audit")
        return data if isinstance(data, list) else data["events"]

    def actions(self, action):
        return [event for event in self.audit() if event["action"] == action]

    def object(self):
        return self.api("/object")["ciphertext"]

    def fault(self, name, value=True):
        return self.api("/fault", {"name": name, "value": value})

    def lifecycle(self):
        self.fixture_reset("lifecycle")
        broker = self.broker()
        with self.case("bootstrap: persist encrypted seed before signing") as result:
            enclave, address = self.signer()
            first = self.call(address, "init")["keys"]
            signature = self.call(address, "sign")
            assert signature["verified"]
            assert len(self.actions("GenerateDataKey")) == 1
            assert len(self.actions("Decrypt")) == 1
            ciphertext = self.object()
            assert ciphertext and 64 < len(base64.b64decode(ciphertext)) <= 6144
            for event in self.actions("GenerateDataKey") + self.actions("Decrypt"):
                assert "Plaintext" not in event["response_fields"]
                assert "CiphertextForRecipient" in event["response_fields"]
                assert event["payload_hash_validated"]
            result["ciphertext_sha256"] = hashlib.sha256(base64.b64decode(ciphertext)).hexdigest()
        with self.case("real parent gRPC routes the same verified gas signature"):
            self.parent_signature(address, signature)
        with self.case("swap cloning and seed import remain disabled"):
            for command in ("clone", "clone-get", "clone-set", "import"):
                self.call(address, command, False)
        self.stop(enclave)
        self.stop(broker)
        with self.case("cold signer and broker restart: identical identity and signature"):
            self.api("/audit/reset", {})
            broker = self.broker()
            enclave, address = self.signer(first["evm_address"])
            assert self.call(address, "init")["keys"] == first
            assert self.call(address, "sign") == signature
            assert not self.actions("GenerateDataKey")
            assert self.object() == ciphertext
            self.parent_signature(address, signature)
        with self.case("second replica: identical identity and signature without cloning"):
            replica, replica_address = self.signer(first["evm_address"])
            assert self.call(replica_address, "init")["keys"] == first
            assert self.call(replica_address, "sign") == signature
            assert not self.actions("GenerateDataKey")
            self.stop(replica)
        self.stop(enclave)
        for fault in ("kms_denied", "kms_wrong_algorithm", "kms_plaintext", "kms_wrong_key",
                      "kms_invalid_cms", "kms_short_seed"):
            with self.case(f"restore {fault}: preserve ciphertext and recover after retry"):
                self.fault(fault)
                enclave, address = self.signer(first["evm_address"])
                self.failed_init(address)
                assert self.object() == ciphertext
                self.fault(fault, False)
                assert self.call(address, "init")["keys"] == first
                assert self.call(address, "sign") == signature
                assert not self.actions("GenerateDataKey")
                self.stop(enclave)
        with self.case("identity pin refuses a different valid KMS ciphertext"):
            self.api("/object", {"replacement": True})
            assert self.object() != ciphertext
            enclave, address = self.signer(first["evm_address"])
            self.failed_init(address)
            assert not self.actions("GenerateDataKey")
            self.stop(enclave)
        self.api("/object", {"ciphertext": ciphertext})
        with self.case("wrong expected identity fails closed"):
            enclave, address = self.signer("11" * 20)
            self.failed_init(address)
            assert self.object() == ciphertext
            self.stop(enclave)
        with self.case("ciphertext corruption fails without replacement"):
            corrupt = bytearray(base64.b64decode(ciphertext))
            corrupt[-1] ^= 1
            damaged = base64.b64encode(corrupt).decode()
            self.api("/object", {"ciphertext": damaged})
            enclave, address = self.signer(first["evm_address"])
            self.failed_init(address)
            assert self.object() == damaged
            self.stop(enclave)
        with self.case("missing recovery state never creates a replacement identity"):
            self.api("/object", {"ciphertext": None})
            self.api("/audit/reset", {})
            enclave, address = self.signer(first["evm_address"])
            self.failed_init(address)
            assert self.object() is None and not self.actions("GenerateDataKey")
            self.stop(enclave)
        self.stop(broker)

    def concurrent_bootstrap(self):
        self.fixture_reset("concurrent")
        broker = self.broker()
        with self.case("concurrent bootstrap converges on one conditional S3 write"):
            self.fault("bootstrap_barrier")
            a, aa = self.signer()
            b, ba = self.signer()
            with ThreadPoolExecutor(max_workers=2) as pool:
                one = pool.submit(self.call, aa, "init")
                two = pool.submit(self.call, ba, "init")
                assert one.result()["keys"] == two.result()["keys"]
            assert self.call(aa, "sign") == self.call(ba, "sign")
            assert self.object() is not None
            assert len(self.actions("GenerateDataKey")) == 2
            assert len(self.actions("PutObject")) == 2
            self.stop(a)
            self.stop(b)
        self.stop(broker)

    def failures(self):
        for fault in ("s3_read_denied", "s3_write_denied", "kms_denied", "kms_plaintext",
                      "kms_wrong_key", "kms_invalid_cms", "kms_short_seed", "kms_http_error"):
            self.fixture_reset(fault.replace("_", "-"))
            broker = self.broker()
            with self.case(f"{fault}: initialization fails and same-process retry recovers"):
                self.fault(fault)
                enclave, address = self.signer()
                self.failed_init(address)
                assert self.object() is None
                if fault == "s3_read_denied":
                    assert not self.actions("GenerateDataKey")
                self.fault(fault, False)
                self.call(address, "init")
                assert self.call(address, "sign")["verified"]
                self.stop(enclave)
            self.stop(broker)

    def aws_client(self, service, secure=True, bad_signature=False):
        f = self.fixture
        credentials = f["credentials"]
        return boto3.client(service, region_name=f["region"],
            endpoint_url=f["aws_tls_endpoint"] if secure else f["aws_endpoint"],
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key="intentionally-wrong" if bad_signature else credentials["secret_access_key"],
            aws_session_token=credentials["session_token"], verify=str(self.certs["ca.pem"]),
            config=Config(retries={"total_max_attempts": 1}, s3={"addressing_style": "path"}, proxies={}))

    def denied(self, operation, **arguments):
        try:
            operation(**arguments)
        except ClientError as error:
            status = error.response["ResponseMetadata"]["HTTPStatusCode"]
            assert status in (400, 403), error.response
            code = error.response["Error"]["Code"]
            # Moto emits an XML SignatureDoesNotMatch error even for JSON KMS;
            # botocore retains that XML in Message and reports Code="403".
            detail = code + " " + error.response["Error"].get("Message", "")
            assert any(word in detail.lower() for word in ("denied", "signature", "access", "token")), code
        else:
            raise AssertionError("forbidden local AWS call was accepted")

    def policy_checks(self):
        f = self.fixture_reset("policies")
        context = {"application": "utexo-enclave-signer", "flow": "rgb-swap",
                   "seed_id": f["seed_id"], "bitcoin_network": "regtest"}
        policy_context = {"kms:RecipientAttestation:PCR0": BOOTSTRAP,
                          "kms:EncryptionContextKeys": list(context),
                          **{f"kms:EncryptionContext:{k}": v for k, v in context.items()}}
        with self.case("exact production KMS policy: allowed bootstrap and recovery"):
            for action, pcr in (("kms:GenerateDataKey", BOOTSTRAP), ("kms:Decrypt", BOOTSTRAP),
                                ("kms:Decrypt", RESTORE)):
                verdict = self.api("/simulate", {"action": action, "context": {
                    **policy_context, "kms:RecipientAttestation:PCR0": pcr}})
                assert verdict["result"] == "Allowed", verdict
        with self.case("exact production KMS policy: role, PCR, context and plaintext denials"):
            cases = [
                {"context": {k: v for k, v in policy_context.items() if k != "kms:RecipientAttestation:PCR0"}},
                {"context": {**policy_context, "kms:RecipientAttestation:PCR0": "cc" * 48}},
                {"context": {**policy_context, "kms:EncryptionContext:flow": "rgb-mint-burn"}},
                {"context": {**policy_context, "kms:EncryptionContext:seed_id": "another-seed"}},
                {"context": {**policy_context, "kms:EncryptionContext:bitcoin_network": "bitcoin"}},
                {"context": {**policy_context, "kms:EncryptionContextKeys": [*context, "extra"]}},
                {"principal": "arn:aws:iam::123456789012:role/wrong-role"},
                {"action": "kms:GenerateDataKey", "context": {**policy_context, "kms:RecipientAttestation:PCR0": RESTORE}},
                {"action": "kms:Encrypt"}, {"action": "kms:GenerateDataKeyWithoutPlaintext"},
            ]
            for case in cases:
                verdict = self.api("/simulate", {"action": "kms:Decrypt", "context": policy_context, **case})
                assert verdict["result"] in ("ExplicitlyDenied", "ImplicitlyDenied"), (case, verdict)
        with self.case("local AWS API rejects a missing Recipient and invalid SigV4"):
            kms = self.aws_client("kms")
            self.denied(kms.generate_data_key, KeyId=f["key_arn"], NumberOfBytes=64, EncryptionContext=context)
            self.denied(kms.encrypt, KeyId=f["key_arn"], Plaintext=b"test-only", EncryptionContext=context)
            # Both calls carry the SAME otherwise authorized request. A missing
            # Recipient must not mask a disabled signature verifier in this test.
            recipient_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            document = cbor2.dumps({"module_id": "mock", "digest": "SHA384",
                "pcrs": {0: bytes.fromhex(BOOTSTRAP)}, "nonce": os.urandom(32),
                "public_key": recipient_key.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)})
            arguments = {"KeyId": f["key_arn"], "NumberOfBytes": 64, "EncryptionContext": context,
                "Recipient": {"KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256", "AttestationDocument": document}}
            assert "CiphertextForRecipient" in kms.generate_data_key(**arguments)
            try:
                self.aws_client("kms", bad_signature=True).generate_data_key(**arguments)
            except ClientError as error:
                assert "SignatureDoesNotMatch" in str(error), error
            else:
                raise AssertionError("Moto accepted an invalid SigV4 on an otherwise authorized KMS call")
        with self.case("SigV4 rejects modified body bytes and a modified body hash"):
            # The exact request is otherwise authorized, including Recipient.
            # Exercise the explicit body-hash header emitted by the Rust client.
            payload = {**arguments, "Recipient": {
                **arguments["Recipient"],
                "AttestationDocument": base64.b64encode(document).decode(),
            }}
            body = json.dumps(payload, separators=(",", ":")).encode()
            url = f["aws_tls_endpoint"] + "/"
            signed = AWSRequest(method="POST", url=url, data=body, headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "TrentService.GenerateDataKey",
                "X-Amz-Content-SHA256": hashlib.sha256(body).hexdigest(),
            })
            credentials = f["credentials"]
            SigV4Auth(Credentials(credentials["access_key_id"],
                credentials["secret_access_key"], credentials["session_token"]),
                "kms", f["region"]).add_auth(signed)
            headers = dict(signed.headers)

            def send(body_bytes, request_headers):
                return self.http.post(url, data=body_bytes, headers=request_headers,
                    verify=str(self.certs["ca.pem"]), timeout=10)

            baseline = send(body, headers)
            assert baseline.status_code == 200, baseline.text
            assert "CiphertextForRecipient" in baseline.json()
            # This also remains a valid GenerateDataKey request under the same
            # policies, so a policy denial cannot mask failed body validation.
            tampered = body.replace(b'"NumberOfBytes":64', b'"NumberOfBytes":63', 1)
            assert tampered != body and len(tampered) == len(body)
            response = send(tampered, headers)
            assert response.status_code == 403 and "SignatureDoesNotMatch" in response.text
            # Replacing the hash must still fail Moto's native SigV4 verifier.
            rehashed = {**headers, "X-Amz-Content-SHA256": hashlib.sha256(tampered).hexdigest()}
            response = send(tampered, rehashed)
            assert response.status_code == 403 and "SignatureDoesNotMatch" in response.text
        with self.case("local S3 API enforces HTTPS, conditional creation and no deletion"):
            s3 = self.aws_client("s3")
            self.denied(s3.put_object, Bucket=f["bucket"], Key=f["object_key"], Body=b"no-condition")
            self.denied(s3.delete_object, Bucket=f["bucket"], Key=f["object_key"])
            self.denied(self.aws_client("s3", secure=False).put_object,
                Bucket=f["bucket"], Key=f["object_key"], Body=b"cleartext-transport", IfNoneMatch="*")
            self.denied(s3.put_object, Bucket=f["bucket"], Key="other/seed", Body=b"wrong-key", IfNoneMatch="*")
            s3.put_object(Bucket=f["bucket"], Key=f["object_key"], Body=b"first", IfNoneMatch="*")
            try:
                s3.put_object(Bucket=f["bucket"], Key=f["object_key"], Body=b"second", IfNoneMatch="*")
            except ClientError as error:
                assert error.response["ResponseMetadata"]["HTTPStatusCode"] == 412
            else:
                raise AssertionError("S3 conditional creation overwrote an existing object")
            assert base64.b64decode(self.object()) == b"first"
        for name, overrides in (
            ("unapproved PCR0", {"SWAP_KMS_E2E_PCR0": "cc" * 48}),
            ("restore PCR0 cannot generate", {"SWAP_KMS_E2E_PCR0": RESTORE}),
            ("encryption context mismatch", {"BITCOIN_NETWORK": "bitcoin"}),
            ("untrusted TLS certificate", {"SWAP_KMS_E2E_CA_PEM": None}),
            ("wrong TLS hostname", {"SWAP_KMS_REGION": "eu-central-1",
                "SWAP_KMS_KEY_ARN": f["key_arn"].replace("eu-west-1", "eu-central-1")}),
            ("plaintext HTTP endpoint", {"SWAP_KMS_E2E_PORT": str(self.args.aws_port)}),
        ):
            self.fixture_reset(name.replace(" ", "-"))
            broker = self.broker()
            with self.case(name + " fails closed"):
                enclave, address = self.signer(**overrides)
                failure = self.failed_init(address)
                assert self.object() is None
                if name in {"untrusted TLS certificate", "wrong TLS hostname", "plaintext HTTP endpoint"}:
                    # A later IAM/ARN denial must not mask a TLS validation bug.
                    assert "KMS HTTPS request failed" in failure["error"]["message"]
                    assert not [event for event in self.audit() if event["service"] == "kms"]
                self.stop(enclave)
            self.stop(broker)

    def write_report(self):
        def binary_hash(path):
            if not path.is_file():
                return None
            with path.open("rb") as binary:
                return hashlib.file_digest(binary, "sha256").hexdigest()

        report = {
            "branch": "kms-testing", "completed_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)),
            "enclave_binary_sha256": binary_hash(self.enclave),
            "parent_binary_sha256": binary_hash(self.parent),
            "suite": "real enclave, broker and parent processes with local Moto KMS/IAM/STS/S3",
            "boundary": "Nitro Recipient uses mock CBOR and local TLS CA; AWS hardware trust chain is not exercised.",
            "results": self.results,
        }
        (self.artifacts / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(self):
        if not self.args.skip_build:
            subprocess.run(["cargo", "build", "--locked", "--no-default-features",
                "--features", "local-kms-e2e", "--bin", "utexo-bridge-enclave", "--bin", "kms-e2e-client"],
                cwd=ROOT, env=git_env(), check=True)
            env = git_env()
            env["CARGO_TARGET_DIR"] = str(self.parent.parent.parent)
            subprocess.run(["cargo", "build", "--locked", "--features", "local-kms-e2e",
                "--bin", "utexo-bridge-parent", "--bin", "kms-e2e-grpc-client"],
                cwd=ROOT / "parent", env=env, check=True)
        assert self.enclave.is_file() and self.client.is_file(), "Build test binaries first"
        self.start("emulator", [sys.executable, HERE / "emulator.py",
            "--aws-port", self.args.aws_port, "--control-port", self.args.control_port,
            "--kms-port", self.args.kms_port, "--cert", self.certs["server.pem"],
            "--key", self.certs["server-key.pem"], "--node", self.args.node],
            port=self.args.control_port)
        self.api("/health")
        self.lifecycle()
        self.concurrent_bootstrap()
        self.failures()
        self.policy_checks()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--artifacts", type=Path, default=ROOT / ".artifacts/kms-e2e")
    parser.add_argument("--node", default=shutil.which("node") or "node")
    parser.add_argument("--aws-port", type=int, default=15000)
    parser.add_argument("--control-port", type=int, default=15001)
    parser.add_argument("--kms-port", type=int, default=3445)
    parser.add_argument("--broker-port", type=int, default=3446)
    args = parser.parse_args()
    for port in (args.aws_port, args.control_port, args.kms_port, args.broker_port):
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))  # fail before starting anything on occupied ports
    suite = Suite(args)
    try:
        suite.run()
    finally:
        suite.cleanup()
        suite.write_report()
    print(f"Passed {len(suite.results)} scenarios. Report: {suite.artifacts / 'report.json'}")


if __name__ == "__main__":
    main()
