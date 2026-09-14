#!/usr/bin/env python3
"""Local testing only: Moto AWS APIs, mock Nitro Recipient CMS, independent IAM.

Moto owns IAM users/roles/STS sessions, signature validation, random generation,
KMS AES-GCM ciphertext, encryption-context authentication, and S3 objects. The
adapter adds only missing Recipient wrapping and delegates the production policy
templates to iam-simulate. Mock CBOR is deliberately NOT AWS attestation evidence.
Never install or run this program as part of a production deployment.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from urllib.parse import urlparse

import boto3
from botocore.config import Config
import cbor2
from asn1crypto import algos, cms
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, jsonify, request
from moto import settings
from moto.core.authorization import ActionAuthenticatorMixin
from moto.core.exceptions import SignatureDoesNotMatchError
from moto.iam.access_control import IAMPolicy, IAMRequest, PermissionResult, S3IAMRequest
from moto.kms.exceptions import AccessDeniedException, ValidationException
from moto.kms.responses import KmsResponse
from moto.kms.models import kms_backends
from moto.moto_api._internal.models import moto_api_backend
from moto.s3.models import FakeBucket, s3_backends
from moto.s3.responses import S3Response
from moto.server import DomainDispatcherApplication, create_backend_app
from werkzeug.serving import make_server

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
REGION = "eu-west-1"
ACCOUNT = "123456789012"
BOOTSTRAP_PCR0 = "aa" * 48
RESTORE_PCR0 = "bb" * 48
FAULTS = {
    "s3_read_denied", "s3_write_denied", "kms_denied", "kms_plaintext",
    "kms_wrong_key", "kms_invalid_cms", "kms_short_seed", "kms_http_error",
    "bootstrap_barrier",
    "kms_wrong_algorithm",
}


def json_policy(policy):
    return IAMPolicy(policy)._policy_json


class PolicySimulator:
    """A separate, maintained OSS policy engine, with a serialized JSON pipe."""

    def __init__(self, node):
        self.lock = threading.Lock()
        self.process = subprocess.Popen(
            [node, str(HERE / "policy-simulator.mjs")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            bufsize=1,
        )

    def evaluate(self, principal, action, resource, identity, resource_policy, context):
        simulation = {
            "request": {
                "principal": principal,
                "action": action,
                "resource": {"resource": resource, "accountId": ACCOUNT},
                "contextVariables": context,
            },
            "identityPolicies": [
                {"name": f"identity-{i}", "policy": json_policy(p)}
                for i, p in enumerate(identity)
            ],
            "resourcePolicy": resource_policy,
            "serviceControlPolicies": [],
            "resourceControlPolicies": [],
        }
        with self.lock:
            self.process.stdin.write(json.dumps(simulation) + "\n")
            self.process.stdin.flush()
            line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("independent IAM simulator stopped")
        result = json.loads(line)
        if result.get("resultType") == "error":
            raise RuntimeError(f"independent IAM simulator rejected input: {result.get('errors')}")
        return result


class State:
    def __init__(self, args):
        self.args = args
        self.simulator = PolicySimulator(args.node)
        self.enabled = False
        self.fixture = None
        self.faults = {}
        self.events = []
        self.lock = threading.RLock()
        self.admin = None
        self.key_policy = None
        self.bucket_policy = None
        self.bootstrap_barrier = None

    def event(self, service, action):
        event = {"service": service, "action": action, "allowed": False}
        with self.lock:
            self.events.append(event)
        return event


def iam_request(response, request_class):
    parsed = urlparse(response.uri)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    return request_class(
        account_id=response.current_account, method=response.method, path=path,
        data=response.data, body=response.raw_body, headers=response.headers,
        action=response._get_action(),
    )


def mock_recipient(parameters):
    """Parse the repository's explicitly mocked CBOR; no COSE/NSM claim."""
    recipient = parameters.get("Recipient")
    if recipient is None:
        return None, None
    try:
        if recipient["KeyEncryptionAlgorithm"] != "RSAES_OAEP_SHA_256":
            raise ValueError("algorithm")
        document = cbor2.loads(base64.b64decode(recipient["AttestationDocument"], validate=True))
        if document["module_id"] != "mock" or document["digest"] != "SHA384":
            raise ValueError("mock document marker")
        pcr = bytes(document["pcrs"][0])
        nonce = bytes(document["nonce"])
        if len(pcr) != 48 or len(nonce) != 32:
            raise ValueError("PCR or nonce size")
        key = serialization.load_der_public_key(bytes(document["public_key"]))
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
            raise ValueError("RSA-2048 recipient key required")
        return key, pcr.hex()
    except Exception as error:
        raise ValidationException("Invalid local mock Recipient document") from error


def recipient_cms(public_key, plaintext):
    """AWS-compatible CMS algorithms and subjectKeyIdentifier recipient shape."""
    cek, iv = os.urandom(32), os.urandom(16)
    wrapped_key = public_key.encrypt(
        cek,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    oaep = algos.RSAESOAEPParams({
        "hash_algorithm": {"algorithm": "sha256"},
        "mask_gen_algorithm": {"algorithm": "mgf1", "parameters": {"algorithm": "sha256"}},
        "p_source_algorithm": {"algorithm": "p_specified", "parameters": b""},
    })
    envelope = cms.EnvelopedData({
        "version": "v2",
        "recipient_infos": [cms.RecipientInfo(name="ktri", value={
            "version": "v2",
            "rid": cms.RecipientIdentifier(name="subject_key_identifier", value=os.urandom(20)),
            "key_encryption_algorithm": {"algorithm": "rsaes_oaep", "parameters": oaep},
            "encrypted_key": wrapped_key,
        })],
        "encrypted_content_info": {
            "content_type": "data",
            "content_encryption_algorithm": {"algorithm": "aes256_cbc", "parameters": iv},
            "encrypted_content": encrypted,
        },
    })
    return cms.ContentInfo({"content_type": "enveloped_data", "content": envelope}).dump()


def install_adapters(state):
    original_kms_auth = KmsResponse._authenticate_and_authorize_normal_action
    original_s3_auth = S3Response._authenticate_and_authorize_s3_action
    original_bucket_permission = FakeBucket.get_permission
    original_generate = KmsResponse.generate_data_key
    original_decrypt = KmsResponse.decrypt

    def kms_resource(self):
        parameters = json.loads(self.body or "{}")
        return parameters.get("KeyId", "*")

    def kms_auth(self, resource="*"):
        if not state.enabled:
            return original_kms_auth(self, resource)
        event = state.event("kms", self._get_action())
        self._local_event = event
        try:
            # Moto recomputes SigV4 with botocore, which treats an explicit
            # X-Amz-Content-SHA256 as authoritative. Independently bind that
            # signed header to the received bytes before its native verifier.
            # Without the header, botocore already hashes the raw body itself.
            payload_hash = self.headers.get("X-Amz-Content-SHA256")
            if payload_hash is not None:
                if payload_hash != hashlib.sha256(self.raw_body or b"").hexdigest():
                    raise SignatureDoesNotMatchError()
                event["payload_hash_validated"] = True
            # Preserve Moto's native signature validation and IAM explicit deny.
            original_kms_auth(self, resource)
            auth = iam_request(self, IAMRequest)
            parameters = json.loads(self.body or "{}")
            key_id = parameters.get("KeyId")
            if key_id != state.fixture["key_arn"]:
                event["allowed"] = True
                return
            key, pcr = mock_recipient(parameters)
            context = {"aws:SecureTransport": str(urlparse(self.uri).scheme == "https").lower()}
            encryption_context = parameters.get("EncryptionContext", {})
            context.update({f"kms:EncryptionContext:{k}": v for k, v in encryption_context.items()})
            if "EncryptionContext" in parameters:
                context["kms:EncryptionContextKeys"] = list(encryption_context)
            if pcr is not None:
                context["kms:RecipientAttestation:PCR0"] = pcr
                event["pcr0"] = pcr
            result = state.simulator.evaluate(
                auth._access_key.arn, f"kms:{self._get_action()}", key_id,
                auth._access_key.collect_policies(), state.key_policy, context,
            )
            event["policy"] = result
            if result["result"] != "Allowed":
                raise AccessDeniedException("Denied by independent local KMS key-policy simulation")
            self._local_recipient_key = key
            event["allowed"] = True
        except Exception as error:
            event["error"] = type(error).__name__
            raise

    def s3_auth(self, bucket_name=None, key_name=None):
        if not state.enabled:
            return original_s3_auth(self, bucket_name, key_name)
        event = state.event("s3", self._get_action())
        try:
            original_s3_auth(self, bucket_name, key_name)
            if bucket_name != state.fixture["bucket"]:
                event["allowed"] = True
                return
            auth = iam_request(self, S3IAMRequest)
            resource = f"arn:aws:s3:::{bucket_name}"
            if key_name is not None:
                resource += "/" + key_name
            context = {"aws:SecureTransport": str(urlparse(self.uri).scheme == "https").lower()}
            if self.headers.get("If-None-Match") is not None:
                context["s3:if-none-match"] = self.headers["If-None-Match"]
            result = state.simulator.evaluate(
                auth._access_key.arn, f"s3:{self._get_action()}", resource,
                auth._access_key.collect_policies(), state.bucket_policy, context,
            )
            event["policy"] = result
            if result["result"] != "Allowed":
                auth._raise_access_denied()
            event["allowed"] = True
        except Exception as error:
            event["error"] = type(error).__name__
            raise

    def bucket_permission(self, action, resource):
        # Moto's built-in resource evaluator omits condition context. For the
        # fixture bucket its full replacement runs in s3_auth above, after IAM.
        if state.enabled and self.name == state.fixture["bucket"]:
            return PermissionResult.NEUTRAL
        return original_bucket_permission(self, action, resource)

    def recipient_response(original):
        def wrapped(self):
            if state.enabled and state.faults.get("kms_http_error"):
                return json.dumps({"__type": "KMSInternalException", "message": "Injected local service failure"}), {"status": 500}
            response = json.loads(original(self))
            if not state.enabled:
                return json.dumps(response)
            if original is original_decrypt:
                # AWS returns this required field; Moto 5.2.3 omits it. Keep
                # production's fail-closed response validation intact.
                response.setdefault("EncryptionAlgorithm", "SYMMETRIC_DEFAULT")
                if state.faults.get("kms_wrong_algorithm"):
                    response["EncryptionAlgorithm"] = "RSAES_OAEP_SHA_256"
            parameters = json.loads(self.body or "{}")
            key, _ = mock_recipient(parameters)
            if key is not None:
                plaintext = base64.b64decode(response.pop("Plaintext"))
                if state.faults.get("kms_short_seed"):
                    plaintext = plaintext[:-1]
                envelope = recipient_cms(key, plaintext)
                if state.faults.get("kms_invalid_cms"):
                    envelope = b"injected-invalid-cms"
                response["CiphertextForRecipient"] = base64.b64encode(envelope).decode()
                if state.faults.get("kms_plaintext"):
                    response["Plaintext"] = base64.b64encode(plaintext).decode()
            if state.faults.get("kms_wrong_key"):
                response["KeyId"] = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/ffffffff-ffff-ffff-ffff-ffffffffffff"
            event = getattr(self, "_local_event", None)
            if event is not None:
                event["response_fields"] = sorted(response)
            if original is original_generate and state.bootstrap_barrier is not None:
                state.bootstrap_barrier.wait(timeout=15)
            return json.dumps(response)
        return wrapped

    KmsResponse._determine_resource = kms_resource
    KmsResponse._authenticate_and_authorize_normal_action = kms_auth
    S3Response._authenticate_and_authorize_s3_action = s3_auth
    FakeBucket.get_permission = bucket_permission
    KmsResponse.generate_data_key = recipient_response(original_generate)
    KmsResponse.decrypt = recipient_response(original_decrypt)


def client(state, service, credentials=None, secure=False):
    credentials = credentials or {"access_key_id": "local-bootstrap", "secret_access_key": "local-bootstrap"}
    return boto3.client(
        service, region_name=REGION,
        endpoint_url=f"{'https' if secure else 'http'}://127.0.0.1:{state.args.kms_port if secure else state.args.aws_port}",
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        aws_session_token=credentials.get("session_token") or None,
        verify=state.args.cert if secure else True,
        config=Config(retries={"max_attempts": 0}, s3={"addressing_style": "path"}, proxies={}),
    )


def policy_template(name, substitutions):
    raw = (REPO / "deploy" / name).read_text()
    for old, new in substitutions.items():
        raw = raw.replace(old, new)
    policy = json.loads(raw)
    if "REPLACE_" in raw:
        raise ValueError(f"unresolved policy template placeholder in {name}")
    return policy


def setup_fixture(state, values):
    with state.lock:
        state.enabled = False
        settings.INITIAL_NO_AUTH_ACTION_COUNT = float("inf")
        moto_api_backend.reset()
        state.events.clear()
        state.faults.clear()
        state.bootstrap_barrier = None
        seed_id = values.get("seed_id", "local-rgb-swap")
        bucket = values.get("bucket", "local-rgb-swap-seeds")
        object_key = values.get("object_key", "swap/seed.kms")
        iam = client(state, "iam")
        iam.create_user(UserName="local-e2e-admin")
        iam.put_user_policy(UserName="local-e2e-admin", PolicyName="Admin", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }))
        admin_key = iam.create_access_key(UserName="local-e2e-admin")["AccessKey"]
        admin = {"access_key_id": admin_key["AccessKeyId"], "secret_access_key": admin_key["SecretAccessKey"], "session_token": ""}
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/local-e2e-admin"}, "Action": "sts:AssumeRole",
        }]}
        role_arn = iam.create_role(RoleName="local-e2e-signer", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
        kms = client(state, "kms", admin)
        key_arn = kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")["KeyMetadata"]["Arn"]
        substitutions = {
            "REPLACE_ACCOUNT_ID": ACCOUNT,
            "REPLACE_KEY_ADMIN_ROLE": "local-e2e-key-admin",
            "REPLACE_SIGNER_ROLE": "local-e2e-signer",
            "REPLACE_BOOTSTRAP_PCR0": BOOTSTRAP_PCR0,
            "REPLACE_RESTORE_PCR0": RESTORE_PCR0,
            "REPLACE_SEED_ID": seed_id,
            "REPLACE_BITCOIN_NETWORK": values.get("bitcoin_network", "regtest"),
            "REPLACE_SEED_BUCKET": bucket,
            "REPLACE_SEED_OBJECT_KEY": object_key,
        }
        state.key_policy = policy_template("swap-kms-key-policy.json", substitutions)
        state.bucket_policy = policy_template("swap-seed-bucket-policy.json", substitutions)
        kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=json.dumps(state.key_policy))
        s3 = client(state, "s3", admin)
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(state.bucket_policy))
        # Broad identity actions make the *actual production resource policies*
        # decisive, while resource ARNs still prevent cross-key/object access.
        identity_policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "kms:*", "Resource": key_arn},
            {"Effect": "Allow", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/{object_key}"]},
        ]}
        iam.put_role_policy(RoleName="local-e2e-signer", PolicyName="FixtureIdentity", PolicyDocument=json.dumps(identity_policy))
        session = client(state, "sts", admin).assume_role(RoleArn=role_arn, RoleSessionName="local-e2e")["Credentials"]
        signer = {"access_key_id": session["AccessKeyId"], "secret_access_key": session["SecretAccessKey"], "session_token": session["SessionToken"]}
        state.admin = admin
        state.fixture = {
            "key_arn": key_arn, "region": REGION, "seed_id": seed_id,
            "bucket": bucket, "object_key": object_key, "role_arn": role_arn,
            "credentials": signer, "admin_credentials": admin,
            "aws_endpoint": f"http://127.0.0.1:{state.args.aws_port}",
            "aws_tls_endpoint": f"https://127.0.0.1:{state.args.kms_port}",
            "bootstrap_pcr0": BOOTSTRAP_PCR0, "restore_pcr0": RESTORE_PCR0,
            "identity_policy": identity_policy, "key_policy": state.key_policy,
            "bucket_policy": state.bucket_policy,
            "bitcoin_network": values.get("bitcoin_network", "regtest"),
        }
        ActionAuthenticatorMixin.request_count = 0
        settings.INITIAL_NO_AUTH_ACTION_COUNT = 0
        state.enabled = True
        return state.fixture


def update_fault(state, name, value):
    if name not in FAULTS or type(value) is not bool:
        raise ValueError("unknown fault name or non-boolean value")
    state.faults[name] = value
    if name == "bootstrap_barrier":
        state.bootstrap_barrier = threading.Barrier(2) if value else None
    actions = []
    for fault, action in (("s3_read_denied", "s3:GetObject"), ("s3_write_denied", "s3:PutObject"), ("kms_denied", "kms:*")):
        if state.faults.get(fault):
            actions.append(action)
    iam = client(state, "iam", state.admin)
    if actions:
        iam.put_role_policy(RoleName="local-e2e-signer", PolicyName="InjectedExplicitDeny", PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": actions, "Resource": "*"}],
        }))
    else:
        try:
            iam.delete_role_policy(RoleName="local-e2e-signer", PolicyName="InjectedExplicitDeny")
        except iam.exceptions.NoSuchEntityException:
            pass


def control_app(state):
    app = Flask("local-kms-e2e-control")

    @app.get("/health")
    def health():
        return jsonify({"ready": True, "configured": state.enabled, "moto": "5.2.3", "faults": sorted(FAULTS)})

    @app.post("/setup")
    def setup():
        return jsonify(setup_fixture(state, request.get_json(force=True)))

    @app.post("/fault")
    def fault():
        data = request.get_json(force=True)
        with state.lock:
            update_fault(state, data["name"], data.get("value", True))
            return jsonify({"faults": state.faults})

    @app.get("/audit")
    def audit():
        with state.lock:
            return jsonify(list(state.events))

    @app.post("/audit/reset")
    def audit_reset():
        with state.lock:
            state.events.clear()
        return jsonify({"ok": True})

    @app.route("/object", methods=["GET", "POST"])
    def fixture_object():
        """Out-of-band corruption/replacement fixture; intentionally bypass IAM."""
        with state.lock:
            fixture = state.fixture
            backend = s3_backends[ACCOUNT]["aws"]
            bucket, key = fixture["bucket"], fixture["object_key"]
            if request.method == "POST":
                data = request.get_json(force=True)
                if data.get("replacement") is True:
                    context = {
                        "application": "utexo-enclave-signer", "flow": "rgb-swap",
                        "seed_id": fixture["seed_id"], "bitcoin_network": fixture["bitcoin_network"],
                    }
                    _, blob, _ = kms_backends[ACCOUNT][REGION].generate_data_key(
                        key_id=fixture["key_arn"], encryption_context=context,
                        number_of_bytes=64, key_spec=None,
                    )
                    backend.put_object(bucket, key, blob)
                elif data.get("ciphertext") is None:
                    backend.delete_object(bucket, key, bypass=True)
                else:
                    blob = base64.b64decode(data["ciphertext"], validate=True)
                    backend.put_object(bucket, key, blob)
            obj = backend.get_object(bucket, key)
            return jsonify({"ciphertext": base64.b64encode(obj.value).decode() if obj else None})

    @app.post("/simulate")
    def simulate():
        """Independent policy verdicts for negative cases, without API mutation."""
        data = request.get_json(force=True)
        service = data["action"].split(":", 1)[0]
        policy = state.key_policy if service == "kms" else state.bucket_policy
        resource = data.get("resource", state.fixture["key_arn"] if service == "kms" else f"arn:aws:s3:::{state.fixture['bucket']}/{state.fixture['object_key']}")
        result = state.simulator.evaluate(
            data.get("principal", state.fixture["role_arn"]), data["action"], resource,
            [json.dumps(p) for p in data.get("identity_policies", [state.fixture["identity_policy"]])],
            policy, data.get("context", {}),
        )
        return jsonify(result)

    @app.errorhandler(Exception)
    def control_error(error):
        # Diagnostics never include request credentials, plaintext, or bodies.
        logging.error("Local control error: %s", error)
        return jsonify({"error": type(error).__name__, "detail": str(error)}), 500

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aws-port", type=int, default=15000)
    parser.add_argument("--control-port", type=int, default=15001)
    parser.add_argument("--kms-port", type=int, default=3445)
    parser.add_argument("--cert", "--tls-cert", required=True)
    parser.add_argument("--key", "--tls-key", required=True)
    parser.add_argument("--node", default=os.environ.get("LOCAL_KMS_NODE") or shutil.which("node"))
    args = parser.parse_args()
    if not args.node:
        parser.error("Node.js is required; use --node or LOCAL_KMS_NODE")
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    state = State(args)
    install_adapters(state)
    aws_app = DomainDispatcherApplication(create_backend_app)
    servers = [
        make_server("127.0.0.1", args.aws_port, aws_app, threaded=True),
        make_server("127.0.0.1", args.kms_port, aws_app, threaded=True, ssl_context=(args.cert, args.key)),
        make_server("127.0.0.1", args.control_port, control_app(state), threaded=True),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"ready": True, "aws_port": args.aws_port, "control_port": args.control_port, "kms_port": args.kms_port}), flush=True)
    try:
        while True:
            time.sleep(1)
    finally:
        for server in servers:
            server.shutdown()
        state.simulator.process.terminate()


if __name__ == "__main__":
    main()
