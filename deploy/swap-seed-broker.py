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
import errno
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

import boto3
from botocore.config import Config as AwsConfig
from botocore.exceptions import (BotoCoreError, ClientError, ConfigParseError, InvalidConfigError,
    NoCredentialsError, NoRegionError, ParamValidationError, PartialCredentialsError, ProfileNotFound)


MAX_FRAME_BYTES = 65536
MAX_CIPHERTEXT_BYTES = 6144
REQUEST_TIMEOUT_SECONDS = 10
# Fits inside the enclave's eight-second broker exchange deadline. SDK socket
# timeouts alone cannot bound DNS, credential-provider refresh, or body trickle.
OPERATION_TIMEOUT_SECONDS = 7
MAX_CONNECTIONS = 16
MAX_CONNECTIONS_PER_CID = 4
MAX_OPERATIONS_PER_CID = 2
OPERATIONS_PER_SECOND = 4
OPERATION_BURST = 8
LOGGER = logging.getLogger("swap-seed-broker")


ERROR_CODES = frozenset({
    "configuration_error", "access_denied", "aws_unavailable", "invalid_ciphertext",
    "broker_busy", "operation_timeout", "request_timeout", "invalid_frame",
    "invalid_request", "seed_id_not_allowed", "response_too_large", "internal_error",
})


class BrokerError(Exception):
    """Only fixed codes can cross the socket or enter logs, even by accident."""
    def __init__(self, code):
        super().__init__(code if isinstance(code, str) and code in ERROR_CODES else "internal_error")


def aws_failure_code(error):
    if isinstance(error, (ConfigParseError, InvalidConfigError, NoCredentialsError,
            NoRegionError, ParamValidationError, PartialCredentialsError, ProfileNotFound)):
        return "configuration_error"
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                "InvalidAccessKeyId", "InvalidClientTokenId", "SignatureDoesNotMatch"}:
            return "access_denied"
        if code in {"NoSuchBucket", "PermanentRedirect", "AuthorizationHeaderMalformed",
                "IllegalLocationConstraintException", "InvalidRegion"}:
            return "configuration_error"
    return "aws_unavailable"


class Admission:
    """Nonblocking global and per-peer quotas; no queue or caller-chosen IDs."""
    def __init__(self, total, per_peer):
        self.total_limit, self.peer_limit = total, per_peer
        self.lock = threading.Lock()
        self.total, self.peers = 0, {}

    def acquire(self, peer):
        with self.lock:
            count = self.peers.get(peer, 0)
            if self.total >= self.total_limit or count >= self.peer_limit:
                return False
            self.total += 1
            self.peers[peer] = count + 1
            return True

    def release(self, peer):
        with self.lock:
            self.total -= 1
            count = self.peers[peer] - 1
            if count:
                self.peers[peer] = count
            else:
                del self.peers[peer]


class RateLimit:
    """Per-CID token bucket; requests are rejected immediately, never queued."""
    def __init__(self, rate, burst, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.lock, self.buckets = threading.Lock(), {}

    def take(self, peer):
        with self.lock:
            now = self.clock()
            tokens, previous = self.buckets.get(peer, (self.burst, now))
            tokens = min(self.burst, tokens + max(0, now - previous) * self.rate)
            accepted = tokens >= 1
            self.buckets[peer] = (tokens - 1 if accepted else tokens, now)
            return accepted


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
                raise BrokerError("configuration_error")
            return value

        try:
            cid_text = os.environ.get("SWAP_KMS_ALLOWED_CIDS", "")
            if len(cid_text) > 4096:
                raise BrokerError("configuration_error")
            cids = frozenset(int(value.strip()) for value in cid_text.split(",")) if cid_text else frozenset()
            port = int(os.environ.get("SWAP_KMS_BROKER_PORT", "8004"))
        except ValueError:
            raise BrokerError("configuration_error") from None
        if (not tcp and not cids) or len(cids) > 64 or any(cid <= 3 or cid >= 0xFFFFFFFF for cid in cids):
            raise BrokerError("configuration_error")
        # The measured enclave forwards to this fixed port. Reject an old
        # override rather than silently listening somewhere unreachable.
        if port != 8004:
            raise BrokerError("configuration_error")
        config = cls(
            seed_id=required("SWAP_KMS_SEED_ID"),
            bucket=required("SWAP_KMS_S3_BUCKET"),
            key=required("SWAP_KMS_S3_KEY"),
            region=required("AWS_REGION"),
            allowed_cids=cids,
            port=port,
        )
        if len(config.seed_id.encode("utf-8")) > 256:
            raise BrokerError("configuration_error")
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
        # Timed-out AWS calls cannot be cancelled safely by Python. Retain their
        # slots until they really finish, bounding stalled workers across retries.
        self.operation_slots = Admission(MAX_CONNECTIONS, MAX_OPERATIONS_PER_CID)
        self.operation_rate = RateLimit(OPERATIONS_PER_SECOND, OPERATION_BURST)
        self.s3 = s3 if s3 is not None else self.session.client(
            "s3",
            region_name=config.region,
            config=AwsConfig(
                connect_timeout=1,
                read_timeout=2,
                retries={"mode": "standard", "total_max_attempts": 1},
                max_pool_connections=MAX_CONNECTIONS,
            ),
        )

    def credentials(self):
        # CID authorization grants the FULL instance role, not just this broker's
        # S3 operations. CID reuse is not an image identity; IAM must be dedicated
        # and least privilege. KMS independently verifies recipient attestation.
        with self.credentials_lock:
            credentials = self.session.get_credentials()
            if credentials is None:
                raise BrokerError("configuration_error")
            frozen = credentials.get_frozen_credentials()
        if not frozen.access_key or not frozen.secret_key:
            raise BrokerError("configuration_error")
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
            raise BrokerError(aws_failure_code(error)) from None
        body = response["Body"]
        try:
            size = response.get("ContentLength")
            if size is not None and (type(size) is not int or not 0 < size <= MAX_CIPHERTEXT_BYTES):
                raise BrokerError("invalid_ciphertext")
            blob = body.read(MAX_CIPHERTEXT_BYTES + 1)
            if (
                not isinstance(blob, bytes)
                or not 0 < len(blob) <= MAX_CIPHERTEXT_BYTES
                or (size is not None and len(blob) != size)
            ):
                raise BrokerError("invalid_ciphertext")
            return blob
        finally:
            body.close()

    def create(self, ciphertext):
        # Even the winner must return a successful GET of the committed object,
        # never its uncommitted proposal. Losing enclaves decrypt this same blob.
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
                raise BrokerError(aws_failure_code(error)) from None
        committed = self.load()
        if committed is not None:
            return committed
        # No internal retry loop: a new InitializeKey starts by loading the
        # durable winner, including any PUT committed after an earlier timeout.
        raise BrokerError("aws_unavailable")

    def validate_request(self, request):
        if not isinstance(request, dict):
            raise BrokerError("invalid_request")
        operation = request.get("op")
        if operation == "credentials" and set(request) == {"op"}:
            return
        expected = {"op", "seed_id", "ciphertext"} if operation == "create" else {"op", "seed_id"}
        if operation not in ("load", "create") or set(request) != expected:
            raise BrokerError("invalid_request")
        if request["seed_id"] != self.config.seed_id:
            raise BrokerError("seed_id_not_allowed")
        if operation == "create":
            decode_ciphertext(request["ciphertext"])

    def dispatch(self, request):
        self.validate_request(request)
        operation = request["op"]
        if operation == "credentials":
            return self.credentials()
        if operation == "load":
            ciphertext = self.load()
            return {"ciphertext": None if ciphertext is None else encode_ciphertext(ciphertext)}
        return {"ciphertext": encode_ciphertext(self.create(decode_ciphertext(request["ciphertext"])))}

    def _response(self, request):
        try:
            return self.dispatch(request)
        except BrokerError as error:
            return {"error": str(error)}
        except (BotoCoreError, ClientError) as error:
            return {"error": aws_failure_code(error)}
        except Exception:
            # Never serialize AWS errors, SDK tracebacks, request data, or creds.
            return {"error": "internal_error"}

    def response(self, request, peer=0):
        try:
            self.validate_request(request)
        except BrokerError as error:
            return {"error": str(error)}
        if not self.operation_slots.acquire(peer):
            LOGGER.warning("operation_capacity_exhausted")
            return {"error": "broker_busy"}
        if not self.operation_rate.take(peer):
            self.operation_slots.release(peer)
            LOGGER.warning("operation_rate_exhausted")
            return {"error": "broker_busy"}
        result = queue.Queue(maxsize=1)

        def execute():
            try:
                result.put(self._response(request))
            finally:
                self.operation_slots.release(peer)

        try:
            threading.Thread(target=execute, daemon=True).start()
        except Exception:
            self.operation_slots.release(peer)
            return {"error": "internal_error"}
        try:
            return result.get(timeout=OPERATION_TIMEOUT_SECONDS)
        except queue.Empty:
            # An in-flight conditional PUT can still commit. Never return its
            # proposal as persisted, cancel/rewrite it, or retry it here.
            LOGGER.warning("operation_timeout")
            return {"error": "operation_timeout"}


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


def handle_connection(connection, broker, peer=0):
    with connection:
        try:
            response = broker.response(read_request(connection), peer=peer)
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
    slots = Admission(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_CID)

    def worker(connection, peer):
        try:
            handle_connection(connection, broker, peer=peer)
        finally:
            slots.release(peer)

    while True:
        try:
            connection, peer = listener.accept()
        except OSError as error:
            if error.errno in (errno.EBADF, errno.ENOTSOCK, errno.EINVAL):
                # A closed/broken listener needs systemd to restart the service.
                raise
            # No OS/SDK exception text: it can contain request/configuration
            # data. Back off to avoid a tight loop on descriptor exhaustion.
            LOGGER.warning("accept_failed")
            time.sleep(0.1)
            continue
        # Reject unknown enclave CIDs before reading any request or returning
        # credentials. TCP mode is an explicit development-only opt-in.
        if not peer_allowed(peer, broker.config, tcp):
            connection.close()
            continue
        peer = peer[0]
        if not slots.acquire(peer):
            LOGGER.warning("connection_capacity_exhausted")
            connection.close()
            continue
        try:
            threading.Thread(target=worker, args=(connection, peer), daemon=True).start()
        except Exception:
            connection.close()
            slots.release(peer)
            LOGGER.warning("connection_worker_failed")
            time.sleep(0.1)
            continue


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
                raise BrokerError("configuration_error")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Permit immediate development-process restart while accepted TCP
            # connections are in TIME_WAIT. The production vsock path is unchanged.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
    except BrokerError as error:
        # BrokerError messages are exclusively constant, non-sensitive codes.
        LOGGER.error("%s", error)
        return 1
    except Exception:
        LOGGER.error("startup or listener failed; verify broker configuration and AWS connectivity")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
