"""No AWS calls: run python -m unittest discover -s deploy/tests -v."""

import base64
import concurrent.futures
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError, EndpointConnectionError, ParamValidationError


SPEC = importlib.util.spec_from_file_location(
    "swap_seed_broker", Path(__file__).resolve().parents[1] / "swap-seed-broker.py"
)
broker_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = broker_module
SPEC.loader.exec_module(broker_module)


def aws_error(code, status):
    return ClientError(
        {
            "Error": {"Code": code, "Message": "sensitive AWS diagnostic"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "S3Operation",
    )


class MemoryS3:
    """Model S3's atomic create-if-absent and read-after-write consistency."""

    def __init__(self, value=None):
        self.value = value
        self.lock = threading.Lock()
        self.puts = []
        self.gets = []

    def get_object(self, **kwargs):
        with self.lock:
            self.gets.append(kwargs)
            if self.value is None:
                raise aws_error("NoSuchKey", 404)
            return {"Body": io.BytesIO(self.value), "ContentLength": len(self.value)}

    def put_object(self, **kwargs):
        with self.lock:
            self.puts.append(kwargs)
            if self.value is not None:
                raise aws_error("PreconditionFailed", 412)
            if kwargs["IfNoneMatch"] != "*":
                raise AssertionError("unconditional write is forbidden")
            self.value = kwargs["Body"]
            return {"ETag": "committed"}


class SeedBrokerTests(unittest.TestCase):
    def setUp(self):
        self.config = broker_module.Config(
            seed_id="swaps-prod", bucket="seed-bucket", key="swaps/seed.kms",
            region="eu-central-1", allowed_cids=frozenset({16, 18}),
        )
        self.s3 = MemoryS3()
        self.session = Mock()
        self.broker = broker_module.SeedBroker(self.config, self.session, self.s3)

    def request(self, operation, peer=16, **fields):
        return self.broker.response({"op": operation, "seed_id": "swaps-prod", **fields}, peer=peer)

    def create(self, blob, peer=16):
        return self.request("create", peer=peer, ciphertext=base64.b64encode(blob).decode("ascii"))

    def test_missing_then_create_then_restart_load_preserves_exact_ciphertext(self):
        self.assertEqual(self.request("load"), {"ciphertext": None})
        blob = b"opaque KMS ciphertext\x00\xff"
        expected = {"ciphertext": base64.b64encode(blob).decode("ascii")}
        self.assertEqual(self.create(blob), expected)
        restarted = broker_module.SeedBroker(self.config, self.session, self.s3)
        self.assertEqual(restarted.response({"op": "load", "seed_id": "swaps-prod"}), expected)
        self.assertEqual(self.s3.value, blob)
        self.assertEqual(len(self.s3.puts), 1)
        self.assertEqual(self.s3.puts[0]["IfNoneMatch"], "*")
        self.assertEqual(self.s3.gets[-1], {"Bucket": "seed-bucket", "Key": "swaps/seed.kms"})

    def test_concurrent_creators_all_return_the_single_committed_winner(self):
        count = 16
        barrier = threading.Barrier(count)

        def submit(index):
            barrier.wait(timeout=5)
            return self.create(f"candidate-{index}".encode("ascii"), peer=16+index)

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            results = list(pool.map(submit, range(count)))
        expected = {"ciphertext": base64.b64encode(self.s3.value).decode("ascii")}
        self.assertEqual(results, [expected] * count)
        self.assertEqual(len(self.s3.puts), count)
        self.assertTrue(all(put["IfNoneMatch"] == "*" for put in self.s3.puts))

    def test_existing_object_is_never_overwritten(self):
        self.s3.value = b"existing winner"
        self.assertEqual(self.create(b"loser"), {"ciphertext": "ZXhpc3Rpbmcgd2lubmVy"})
        self.assertEqual(self.s3.value, b"existing winner")

    def test_conflict_without_winner_fails_without_multiplying_aws_timeouts(self):
        self.s3.put_object = Mock(side_effect=aws_error("ConditionalRequestConflict", 409))
        self.assertEqual(self.create(b"candidate"), {"error": "aws_unavailable"})
        self.s3.put_object.assert_called_once()
        self.assertEqual(len(self.s3.gets), 1)

    def test_conflict_409_with_winner_reads_winner_without_new_write(self):
        self.s3.value = b"winner"
        self.s3.put_object = Mock(side_effect=aws_error("ConditionalRequestConflict", 409))
        self.assertEqual(self.create(b"loser"), {"ciphertext": "d2lubmVy"})
        self.s3.put_object.assert_called_once()

    def test_conflicts_are_bounded(self):
        self.s3.put_object = Mock(side_effect=aws_error("ConditionalRequestConflict", 409))
        with patch.object(broker_module.time, "sleep"):
            self.assertEqual(self.create(b"candidate"), {"error": "aws_unavailable"})
        self.assertEqual(self.s3.put_object.call_count, 1)

    def test_timeout_returns_before_slow_put_and_retry_recovers_late_commit(self):
        entered, finish, done = threading.Event(), threading.Event(), threading.Event()
        original_put = self.s3.put_object

        def slow_put(**kwargs):
            entered.set()
            finish.wait(timeout=3)
            original_put(**kwargs)
            done.set()

        self.s3.put_object = slow_put
        try:
            start = time.monotonic()
            with patch.object(broker_module, "OPERATION_TIMEOUT_SECONDS", 0.03):
                self.assertEqual(self.create(b"late committed"), {"error": "operation_timeout"})
            self.assertLess(time.monotonic() - start, 0.5)
            self.assertTrue(entered.is_set())
            self.assertIsNone(self.s3.value)
            finish.set()
            self.assertTrue(done.wait(timeout=1))
            self.assertEqual(self.request("load"), {"ciphertext": "bGF0ZSBjb21taXR0ZWQ="})
        finally:
            finish.set()

    def test_timed_out_workers_keep_capacity_until_aws_actually_finishes(self):
        finish, done = threading.Event(), threading.Event()

        def stalled(_request):
            try:
                finish.wait(timeout=3)
                return {"ciphertext": None}
            finally:
                done.set()

        self.broker.operation_slots = broker_module.Admission(1, 1)
        self.broker._response = Mock(side_effect=stalled)
        try:
            with patch.object(broker_module, "OPERATION_TIMEOUT_SECONDS", 0.03):
                self.assertEqual(self.request("load"), {"error": "operation_timeout"})
                self.assertEqual(self.request("load"), {"error": "broker_busy"})
            self.broker._response.assert_called_once()
        finally:
            finish.set()
            self.assertTrue(done.wait(timeout=1))

    def test_timed_out_cid_cannot_exhaust_another_cids_operation_capacity(self):
        finish = threading.Event()
        original = self.broker._response

        def dispatch(request):
            if request["op"] == "credentials":
                finish.wait(timeout=3)
                return {"error": "aws_unavailable"}
            return original(request)

        self.broker._response = Mock(side_effect=dispatch)
        try:
            with patch.object(broker_module, "OPERATION_TIMEOUT_SECONDS", 0.03):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    responses = list(pool.map(lambda _: self.broker.response({"op": "credentials"}, peer=16), range(2)))
                self.assertEqual(responses, [{"error": "operation_timeout"}] * 2)
                self.assertEqual(self.broker.response({"op": "credentials"}, peer=16), {"error": "broker_busy"})
                self.assertEqual(self.request("load", peer=18), {"ciphertext": None})
                self.assertEqual(self.broker._response.call_count, 3)
                self.assertEqual(self.broker.operation_slots.peers.get(16), 2)
        finally:
            finish.set()

    def test_operation_thread_failure_returns_its_global_and_cid_slots(self):
        with patch.object(broker_module.threading,"Thread") as thread:
            thread.return_value.start.side_effect=RuntimeError("sensitive system diagnostic")
            self.assertEqual(self.request("load"),{"error":"internal_error"})
        self.assertEqual(self.broker.operation_slots.total,0)
        self.assertEqual(self.broker.operation_slots.peers,{})
        self.assertEqual(self.request("load"),{"ciphertext":None})

    def test_fast_cid_rate_limit_rejects_before_sdk_and_other_cid_can_progress(self):
        now = [100.0]
        self.broker.operation_rate = broker_module.RateLimit(4, 8, clock=lambda: now[0])
        for _ in range(8):
            self.assertEqual(self.request("load",peer=16), {"ciphertext":None})
        self.assertEqual(len(self.s3.gets),8)
        self.assertEqual(self.request("load",peer=16), {"error":"broker_busy"})
        self.assertEqual(len(self.s3.gets),8)
        self.assertEqual(self.request("load",peer=18), {"ciphertext":None})
        now[0] += .25
        self.assertEqual(self.request("load",peer=16), {"ciphertext":None})
        self.assertEqual(self.request("load",peer=16), {"error":"broker_busy"})
        now[0] += 100
        self.assertTrue(all(self.broker.operation_rate.take(16) for _ in range(8)))
        self.assertFalse(self.broker.operation_rate.take(16))

    def test_provider_errors_have_fixed_categories_without_diagnostics(self):
        errors = ((aws_error("AccessDenied", 403), "access_denied"),
            (aws_error("SignatureDoesNotMatch", 403), "access_denied"),
            (aws_error("NoSuchBucket", 404), "configuration_error"),
            (aws_error("AuthorizationHeaderMalformed", 400), "configuration_error"),
            (aws_error("ExpiredToken", 400), "aws_unavailable"),
            (aws_error("InternalError", 500), "aws_unavailable"),
            (ParamValidationError(report="sensitive credential value"), "configuration_error"))
        for error, expected in errors:
            with self.subTest(expected=expected):
                self.s3.get_object = Mock(side_effect=error)
                self.assertEqual(self.request("load"), {"error": expected})
                self.assertFalse(self.s3.puts)
        self.broker.dispatch = Mock(side_effect=broker_module.BrokerError("sensitive credential value"))
        self.assertEqual(self.request("load"), {"error": "internal_error"})

    def test_sdk_has_no_automatic_retries(self):
        session = Mock()
        broker_module.SeedBroker(self.config, session=session)
        config = session.client.call_args.kwargs["config"]
        self.assertEqual(config.retries["total_max_attempts"], 1)
        self.assertEqual((config.connect_timeout, config.read_timeout), (1, 2))

    def test_successful_put_is_not_accepted_when_readback_fails(self):
        self.s3.get_object = Mock(side_effect=aws_error("AccessDenied", 403))
        self.assertEqual(self.create(b"candidate"), {"error": "access_denied"})
        self.assertEqual(self.s3.value, b"candidate")
        self.assertEqual(len(self.s3.puts), 1)

    def test_failed_or_uncertain_put_never_returns_uncommitted_proposal(self):
        for error in (
            aws_error("AccessDenied", 403), aws_error("InternalError", 500),
            EndpointConnectionError(endpoint_url="https://example.invalid"),
        ):
            with self.subTest(error=type(error).__name__):
                self.s3.put_object = Mock(side_effect=error)
                self.assertIn("error", self.create(b"candidate"))
                self.assertIsNone(self.s3.value)
                self.assertEqual(self.s3.gets, [])

    def test_only_real_missing_object_404_is_missing(self):
        for error in (
            aws_error("AccessDenied", 403), aws_error("NoSuchKey", 403),
            aws_error("NoSuchBucket", 404), aws_error("InternalError", 500),
        ):
            with self.subTest(error=error.response["Error"]["Code"]):
                self.s3.get_object = Mock(side_effect=error)
                self.assertEqual(self.request("load"), {"error": broker_module.aws_failure_code(error)})
                self.assertEqual(self.s3.puts, [])

    def test_corrupt_stored_object_fails_closed_and_closes_stream(self):
        for blob, size in ((b"", 0), (b"a" * 6145, 6145), (b"short", 100), (b"a" * 6145, None)):
            with self.subTest(size=size):
                stream = io.BytesIO(blob)
                response = {"Body": stream}
                if size is not None:
                    response["ContentLength"] = size
                self.s3.get_object = Mock(return_value=response)
                self.assertEqual(self.request("load"), {"error": "invalid_ciphertext"})
                self.assertTrue(stream.closed)
                self.assertEqual(self.s3.puts, [])

    def test_corrupt_kms_payload_is_opaque_and_left_for_enclave_to_authenticate(self):
        self.s3.value = b"not a valid KMS envelope"
        self.assertEqual(self.request("load"), {"ciphertext": base64.b64encode(self.s3.value).decode("ascii")})
        self.assertEqual(self.s3.puts, [])

    def test_create_rejects_invalid_base64_or_size_without_storage_access(self):
        for value in (None, {}, 1, "", "====", "☃", "YQ==\n", "YR==", base64.b64encode(b"a" * 6145).decode("ascii")):
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(self.request("create", ciphertext=value), {"error": "invalid_ciphertext"})
        self.assertEqual(self.s3.puts, [])
        self.assertEqual(self.s3.gets, [])

    def test_only_fixed_seed_and_exact_request_fields_are_accepted(self):
        for request in (
            {"op": "load", "seed_id": "another-seed"},
            {"op": "load", "seed_id": "swaps-prod", "key": "another-key"},
            {"op": "credentials", "seed_id": "swaps-prod"},
            {"op": "delete", "seed_id": "swaps-prod"},
            {"op": "create", "seed_id": "swaps-prod"},
            [], "credentials", None,
        ):
            with self.subTest(request=request):
                self.assertIn("error", self.broker.response(request))
        self.assertEqual(self.s3.puts, [])
        self.assertEqual(self.s3.gets, [])
        self.session.get_credentials.assert_not_called()

    def test_credentials_are_frozen_afresh_for_each_request(self):
        credentials = Mock()
        credentials.get_frozen_credentials.side_effect = [
            SimpleNamespace(access_key="first", secret_key="secret-one", token="token-one"),
            SimpleNamespace(access_key="second", secret_key="secret-two", token="token-two"),
        ]
        self.session.get_credentials.return_value = credentials
        first = self.broker.response({"op": "credentials"})
        second = self.broker.response({"op": "credentials"})
        self.assertEqual(first, {"access_key_id": "first", "secret_access_key": "secret-one", "session_token": "token-one"})
        self.assertEqual(second, {"access_key_id": "second", "secret_access_key": "secret-two", "session_token": "token-two"})
        self.assertEqual(credentials.get_frozen_credentials.call_count, 2)
        self.assertEqual(self.session.get_credentials.call_count, 2)

    def test_credentials_failures_are_sanitized(self):
        self.session.get_credentials.return_value = None
        self.assertEqual(self.broker.response({"op": "credentials"}), {"error": "configuration_error"})
        self.session.get_credentials.side_effect = RuntimeError("SECRET_ACCESS_KEY must not leak")
        self.assertEqual(self.broker.response({"op": "credentials"}), {"error": "internal_error"})


class ProtocolTests(unittest.TestCase):
    def exchange(self, body, size=None):
        client, server = socket.socketpair()
        broker = Mock()
        broker.response.return_value = {"ciphertext": None}
        worker = threading.Thread(target=broker_module.handle_connection, args=(server, broker))
        worker.start()
        try:
            client.settimeout(3)
            client.sendall(struct.pack(">I", len(body) if size is None else size) + body)
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError as error:
                # macOS may observe the one-shot server's close immediately
                # after a complete frame; the response remains readable.
                if error.errno != errno.ENOTCONN:
                    raise
            header = client.recv(4)
            length = struct.unpack(">I", header)[0]
            response = bytearray()
            while len(response) < length:
                response.extend(client.recv(length - len(response)))
            self.assertEqual(client.recv(1), b"")
            return json.loads(response), broker
        finally:
            client.close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())

    def test_valid_request_uses_big_endian_framing_and_closes_connection(self):
        response, broker = self.exchange(b'{"op":"load","seed_id":"swaps-prod"}')
        self.assertEqual(response, {"ciphertext": None})
        broker.response.assert_called_once_with({"op": "load", "seed_id": "swaps-prod"}, peer=0)

    def test_oversized_zero_and_truncated_frames_are_rejected(self):
        for body, size in ((b"", 65537), (b"", 0), (b"x", 20)):
            with self.subTest(size=size):
                response, broker = self.exchange(body, size)
                self.assertEqual(response, {"error": "invalid_frame"})
                broker.response.assert_not_called()

    def test_invalid_json_duplicate_keys_and_invalid_utf8_are_rejected(self):
        for body in (b"garbage", b'{"op":"load","op":"credentials"}', b"\xff"):
            with self.subTest(body=body):
                response, broker = self.exchange(body)
                self.assertEqual(response, {"error": "invalid_request"})
                broker.response.assert_not_called()

    def test_peer_allowlist(self):
        config = SimpleNamespace(allowed_cids=frozenset({16, 18}))
        self.assertTrue(broker_module.peer_allowed((16, 1234), config))
        self.assertFalse(broker_module.peer_allowed((20, 1234), config))
        self.assertFalse(broker_module.peer_allowed((3, 1234), config))
        self.assertTrue(broker_module.peer_allowed(("127.0.0.1", 1234), config, tcp=True))
        self.assertFalse(broker_module.peer_allowed(("0.0.0.0", 1234), config, tcp=True))

    def test_disallowed_cid_connection_is_closed_without_reading_request(self):
        connection = Mock()
        listener = Mock()
        listener.accept.side_effect = [(connection, (20, 1234)), KeyboardInterrupt]
        broker = Mock(config=SimpleNamespace(allowed_cids=frozenset({16})))
        with self.assertRaises(KeyboardInterrupt):
            broker_module.serve(listener, broker)
        connection.close.assert_called_once()
        connection.recv.assert_not_called()
        broker.response.assert_not_called()

    def test_transient_accept_failure_is_sanitized_and_does_not_stop_listener(self):
        connection = Mock()
        listener = Mock()
        listener.accept.side_effect = [OSError("secret must not be logged"), (connection, (20, 1234)), KeyboardInterrupt]
        broker = Mock(config=SimpleNamespace(allowed_cids=frozenset({16})))
        with self.assertLogs(broker_module.LOGGER, level="WARNING") as logs:
            with patch.object(broker_module.time, "sleep") as sleep:
                with self.assertRaises(KeyboardInterrupt):
                    broker_module.serve(listener, broker)
        connection.close.assert_called_once()
        sleep.assert_called_once_with(0.1)
        self.assertNotIn("secret", "".join(logs.output))

    def test_connection_thread_start_failure_releases_slot_and_accepts_next_peer(self):
        first, second = Mock(), Mock()
        listener = Mock()
        listener.accept.side_effect = [(first,(16,1)),(second,(16,2)),KeyboardInterrupt]
        broker = Mock(config=SimpleNamespace(allowed_cids=frozenset({16})))
        failed_thread, working_thread = Mock(), Mock()
        failed_thread.start.side_effect = RuntimeError("sensitive system diagnostic")
        with patch.object(broker_module,"MAX_CONNECTIONS_PER_CID",1), patch.object(broker_module.threading,"Thread",side_effect=[failed_thread,working_thread]), patch.object(broker_module.time,"sleep") as delay, self.assertLogs(broker_module.LOGGER,level="WARNING") as logs:
            with self.assertRaises(KeyboardInterrupt):
                broker_module.serve(listener,broker)
        first.close.assert_called_once()
        second.close.assert_not_called()
        working_thread.start.assert_called_once()
        delay.assert_called_once_with(.1)
        self.assertNotIn("sensitive", "".join(logs.output))

    def test_broken_listener_exits_for_supervisor_restart(self):
        listener = Mock()
        listener.accept.side_effect = OSError(errno.EBADF, "bad descriptor")
        with self.assertRaises(OSError):
            broker_module.serve(listener, Mock())
        listener.accept.assert_called_once()

    def test_total_request_deadline_prevents_slow_stream_from_extending_timeout(self):
        connection = Mock()
        connection.recv.return_value = b"x"
        with patch.object(broker_module.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaisesRegex(broker_module.BrokerError, "request_timeout"):
                broker_module.read_exact(connection, 4, deadline=1)
        connection.recv.assert_called_once()

    def test_one_cid_cannot_exhaust_connections_for_another_allowed_cid(self):
        connections = [Mock() for _ in range(4)]
        listener = Mock()
        listener.accept.side_effect = [(connections[0], (16, 1)), (connections[1], (16, 2)),
            (connections[2], (16, 3)), (connections[3], (18, 4)), KeyboardInterrupt]
        broker = Mock(config=SimpleNamespace(allowed_cids=frozenset({16, 18})))
        with patch.object(broker_module, "MAX_CONNECTIONS_PER_CID", 2):
            with patch.object(broker_module.threading, "Thread") as thread:
                with self.assertRaises(KeyboardInterrupt):
                    broker_module.serve(listener, broker)
        self.assertEqual(thread.call_count, 3)
        self.assertEqual([call.kwargs["args"][1] for call in thread.call_args_list], [16, 16, 18])
        connections[2].close.assert_called_once()
        connections[2].recv.assert_not_called()
        connections[3].close.assert_not_called()

    def test_admission_returns_capacity_to_each_cid_after_release(self):
        admission = broker_module.Admission(3, 2)
        self.assertTrue(admission.acquire(16))
        self.assertTrue(admission.acquire(16))
        self.assertFalse(admission.acquire(16))
        self.assertTrue(admission.acquire(18))
        self.assertFalse(admission.acquire(20))
        admission.release(16)
        self.assertTrue(admission.acquire(20))
        admission.release(16)
        self.assertNotIn(16, admission.peers)
        admission.release(18)
        admission.release(20)
        self.assertEqual(admission.total, 0)
        self.assertEqual(admission.peers, {})

    def test_active_connection_count_is_bounded(self):
        first, excess = Mock(), Mock()
        listener = Mock()
        listener.accept.side_effect = [(first, (16, 1234)), (excess, (16, 1235)), KeyboardInterrupt]
        broker = Mock(config=SimpleNamespace(allowed_cids=frozenset({16})))
        with patch.object(broker_module, "MAX_CONNECTIONS", 1):
            # Keep the first worker pending to exhaust the available slot.
            with patch.object(broker_module.threading, "Thread") as thread:
                with self.assertRaises(KeyboardInterrupt):
                    broker_module.serve(listener, broker)
        thread.assert_called_once()
        first.close.assert_not_called()
        excess.close.assert_called_once()
        excess.recv.assert_not_called()


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "SWAP_KMS_SEED_ID": "swaps-prod", "SWAP_KMS_S3_BUCKET": "seed-bucket",
            "SWAP_KMS_S3_KEY": "swaps/seed.kms", "AWS_REGION": "eu-central-1",
            "SWAP_KMS_ALLOWED_CIDS": "16,18,20",
        }

    def test_loads_fixed_storage_location_and_cid_allowlist(self):
        with patch.dict(os.environ, self.environment, clear=True):
            config = broker_module.Config.from_environment()
        self.assertEqual(config.port, 8004)
        self.assertEqual(config.allowed_cids, frozenset({16, 18, 20}))
        self.assertEqual(config.key, "swaps/seed.kms")

    def test_vsock_cid_allowlist_is_required(self):
        for value in ("", "3", "2", "-1", "4294967295", "invalid", "16,,18", ",".join(str(cid) for cid in range(16,81))):
            with self.subTest(value=value):
                environment = dict(self.environment, SWAP_KMS_ALLOWED_CIDS=value)
                with patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(broker_module.BrokerError, "configuration_error"):
                        broker_module.Config.from_environment()

    def test_port_cannot_diverge_from_measured_enclave_forwarder(self):
        with patch.dict(os.environ, dict(self.environment, SWAP_KMS_BROKER_PORT="9000"), clear=True):
            with self.assertRaisesRegex(broker_module.BrokerError, "configuration_error"):
                broker_module.Config.from_environment()


if __name__ == "__main__":
    unittest.main()
