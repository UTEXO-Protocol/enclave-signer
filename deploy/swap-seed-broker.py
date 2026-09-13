#!/usr/bin/env python3
"""RGB swaps only: broker temporary AWS credentials and immutable KMS ciphertext.

The enclave calls KMS with recipient attestation itself. This host process never
receives plaintext seed material. S3 contains one raw KMS CiphertextBlob at the
configured bucket/key; callers cannot choose a different storage location.

Wire format: one request and response per connection, each a big-endian u32
length followed by UTF-8 JSON (at most 64 KiB). Production uses AF_VSOCK on the
parent (CID 3), with an explicit enclave CID allowlist. --tcp is localhost-only
and intended for development. Prefer an EC2 instance role through IMDSv2 over
static AWS credentials; boto3 refreshes role credentials when needed.
"""

import argparse
import base64
import binascii
import json
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

import boto3
from botocore.config import Config as AwsConfig
from botocore.exceptions import BotoCoreError, ClientError


MAX_FRAME_BYTES = 65536
MAX_CIPHERTEXT_BYTES = 6144
CREATE_ATTEMPTS = 4
REQUEST_TIMEOUT_SECONDS = 10
MAX_CONNECTIONS = 16
LOGGER = logging.getLogger("swap-seed-broker")


class BrokerError(Exception):
    """Only constant, non-sensitive codes may be exposed across the socket."""


@dataclass(frozen=True)
class Config:
    seed_id: str
    bucket: str
    key: str
    region: str
    allowed_cids: frozenset
    port: int = 8004

    @classmethod
    def from_environment(cls, tcp=False):
        def required(name):
            value = os.environ.get(name, "")
            if not value or value != value.strip():
                raise BrokerError("invalid_configuration")
            return value

        try:
            cid_text = os.environ.get("SWAP_KMS_ALLOWED_CIDS", "")
            cids = frozenset(int(value.strip()) for value in cid_text.split(",") if value.strip())
            port = int(os.environ.get("SWAP_KMS_BROKER_PORT", "8004"))
        except ValueError:
            raise BrokerError("invalid_configuration") from None
        if (not tcp and not cids) or any(cid <= 3 or cid >= 0xFFFFFFFF for cid in cids):
            raise BrokerError("invalid_configuration")
        if not 1 <= port <= 0xFFFFFFFF:
            raise BrokerError("invalid_configuration")
        config = cls(
            seed_id=required("SWAP_KMS_SEED_ID"),
            bucket=required("SWAP_KMS_S3_BUCKET"),
            key=required("SWAP_KMS_S3_KEY"),
            region=required("AWS_REGION"),
            allowed_cids=cids,
            port=port,
        )
        if len(config.seed_id.encode("utf-8")) > 256:
            raise BrokerError("invalid_configuration")
        return config


def encode_ciphertext(ciphertext):
    return base64.b64encode(ciphertext).decode("ascii")


def decode_ciphertext(value):
    if not isinstance(value, str) or len(value) > 4 * ((MAX_CIPHERTEXT_BYTES + 2) // 3):
        raise BrokerError("invalid_ciphertext")
    try:
        blob = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        raise BrokerError("invalid_ciphertext") from None
    if not 0 < len(blob) <= MAX_CIPHERTEXT_BYTES or encode_ciphertext(blob) != value:
        raise BrokerError("invalid_ciphertext")
    return blob


def is_missing_object(error):
    # AccessDenied, timeouts, and missing buckets must never trigger generation.
    return (
        error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404
        and error.response.get("Error", {}).get("Code") in ("NoSuchKey", "NotFound", "404")
    )


class SeedBroker:
    def __init__(self, config, session=None, s3=None):
        self.config = config
        self.session = session if session is not None else boto3.Session()
        # Credential resolution may initialize a provider on first use. Resolve
        # under a lock, and freeze again on every request to refresh expiring roles.
        self.credentials_lock = threading.Lock()
        self.s3 = s3 if s3 is not None else self.session.client(
            "s3",
            region_name=config.region,
            config=AwsConfig(
                connect_timeout=2,
                read_timeout=5,
                retries={"mode": "standard", "total_max_attempts": 2},
                max_pool_connections=MAX_CONNECTIONS,
            ),
        )

    def credentials(self):
        with self.credentials_lock:
            credentials = self.session.get_credentials()
            if credentials is None:
                raise BrokerError("credentials_unavailable")
            frozen = credentials.get_frozen_credentials()
        if not frozen.access_key or not frozen.secret_key:
            raise BrokerError("credentials_unavailable")
        return {
            "access_key_id": frozen.access_key,
            "secret_access_key": frozen.secret_key,
            "session_token": frozen.token or "",
        }

    def load(self) -> Optional[bytes]:
        try:
            response = self.s3.get_object(Bucket=self.config.bucket, Key=self.config.key)
        except ClientError as error:
            if is_missing_object(error):
                return None
            raise BrokerError("storage_unavailable") from None
        body = response["Body"]
        try:
            size = response.get("ContentLength")
            if size is not None and (type(size) is not int or not 0 < size <= MAX_CIPHERTEXT_BYTES):
                raise BrokerError("invalid_stored_ciphertext")
            blob = body.read(MAX_CIPHERTEXT_BYTES + 1)
            if (
                not isinstance(blob, bytes)
                or not 0 < len(blob) <= MAX_CIPHERTEXT_BYTES
                or (size is not None and len(blob) != size)
            ):
                raise BrokerError("invalid_stored_ciphertext")
            return blob
        finally:
            body.close()

    def create(self, ciphertext):
        # Even the winner must return a successful GET of the committed object,
        # never its uncommitted proposal. Losing enclaves decrypt this same blob.
        for attempt in range(CREATE_ATTEMPTS):
            try:
                self.s3.put_object(
                    Bucket=self.config.bucket,
                    Key=self.config.key,
                    Body=ciphertext,
                    ContentType="application/octet-stream",
                    IfNoneMatch="*",
                )
            except ClientError as error:
                status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                code = error.response.get("Error", {}).get("Code")
                if (status, code) not in (
                    (412, "PreconditionFailed"),
                    (409, "ConditionalRequestConflict"),
                ):
                    raise BrokerError("storage_unavailable") from None
            committed = self.load()
            if committed is not None:
                return committed
            # A concurrent delete can produce a 409 or erase a newly committed
            # key. IAM/bucket policy should prohibit deletion; retry is bounded.
            if attempt + 1 < CREATE_ATTEMPTS:
                time.sleep(0.05 * (2 ** attempt))
        raise BrokerError("storage_conflict")

    def dispatch(self, request):
        if not isinstance(request, dict):
            raise BrokerError("invalid_request")
        operation = request.get("op")
        if operation == "credentials" and set(request) == {"op"}:
            return self.credentials()
        expected = {"op", "seed_id", "ciphertext"} if operation == "create" else {"op", "seed_id"}
        if operation not in ("load", "create") or set(request) != expected:
            raise BrokerError("invalid_request")
        if request["seed_id"] != self.config.seed_id:
            raise BrokerError("seed_id_not_allowed")
        if operation == "load":
            ciphertext = self.load()
            return {"ciphertext": None if ciphertext is None else encode_ciphertext(ciphertext)}
        return {"ciphertext": encode_ciphertext(self.create(decode_ciphertext(request["ciphertext"])))}

    def response(self, request):
        try:
            return self.dispatch(request)
        except BrokerError as error:
            return {"error": str(error)}
        except (BotoCoreError, ClientError):
            return {"error": "aws_unavailable"}
        except Exception:
            # Never serialize AWS errors, SDK tracebacks, request data, or creds.
            return {"error": "internal_error"}


def read_exact(connection, size, deadline):
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerError("request_timeout")
        connection.settimeout(remaining)
        data = connection.recv(size - len(chunks))
        if not data:
            raise BrokerError("invalid_frame")
        chunks.extend(data)
    return bytes(chunks)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BrokerError("invalid_request")
        result[key] = value
    return result


def read_request(connection):
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    size = struct.unpack(">I", read_exact(connection, 4, deadline))[0]
    if not 0 < size <= MAX_FRAME_BYTES:
        raise BrokerError("invalid_frame")
    try:
        return json.loads(read_exact(connection, size, deadline).decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, RecursionError):
        raise BrokerError("invalid_request") from None


def handle_connection(connection, broker):
    with connection:
        try:
            response = broker.response(read_request(connection))
        except BrokerError as error:
            response = {"error": str(error)}
        except (OSError, ValueError):
            response = {"error": "invalid_frame"}
        payload = json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(payload) > MAX_FRAME_BYTES:
            payload = b'{"error":"response_too_large"}'
        try:
            connection.settimeout(2)
            connection.sendall(struct.pack(">I", len(payload)) + payload)
        except OSError:
            pass


def peer_allowed(peer, config, tcp=False):
    return peer[0] == "127.0.0.1" if tcp else peer[0] in config.allowed_cids


def serve(listener, broker, tcp=False):
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def worker(connection):
        try:
            handle_connection(connection, broker)
        finally:
            slots.release()

    while True:
        connection, peer = listener.accept()
        # Reject unknown enclave CIDs before reading any request or returning
        # credentials. TCP mode is an explicit development-only opt-in.
        if not peer_allowed(peer, broker.config, tcp) or not slots.acquire(blocking=False):
            connection.close()
            continue
        try:
            threading.Thread(target=worker, args=(connection,), daemon=True).start()
        except Exception:
            connection.close()
            slots.release()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tcp", metavar="127.0.0.1:PORT", help="development only: listen on loopback TCP")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    # SDK diagnostics can include signed requests. Only this broker emits logs.
    logging.getLogger("boto3").setLevel(logging.CRITICAL)
    logging.getLogger("botocore").setLevel(logging.CRITICAL)
    try:
        config = Config.from_environment(tcp=bool(args.tcp))
        if args.tcp:
            host, port_text = args.tcp.rsplit(":", 1)
            port = int(port_text)
            if host != "127.0.0.1" or not 1 <= port <= 65535:
                raise BrokerError("invalid_tcp_address")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            address = (host, port)
        else:
            listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            address = (socket.VMADDR_CID_ANY, config.port)
        with listener:
            listener.bind(address)
            listener.listen(MAX_CONNECTIONS)
            broker = SeedBroker(config)
            LOGGER.info("ready (%s)", "development TCP" if args.tcp else "vsock")
            serve(listener, broker, tcp=bool(args.tcp))
    except KeyboardInterrupt:
        return 0
    except Exception:
        LOGGER.error("startup or listener failed; verify broker configuration and AWS connectivity")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
