#!/usr/bin/env python3
"""Authorize a socket-activated VSOCK peer before exec of a blind TLS relay.

systemd owns admission, per-CID quotas and the hard connection lifetime. socat
only copies bytes; TLS and AWS authentication remain inside the enclave.
"""
import os
import re
import socket
import stat
import subprocess
import sys

CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}
MIN_SYSTEMD = 252


class Rejected(Exception):
    pass


def configuration(environment):
    region = environment.get("AWS_REGION", "")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]+", region) or region.startswith(("cn-", "us-gov-", "us-iso")):
        raise Rejected("relay_configuration_error")
    raw = environment.get("SWAP_KMS_ALLOWED_CIDS", "")
    if not raw or len(raw) > 4096:
        raise Rejected("relay_configuration_error")
    try:
        cids = frozenset(int(value.strip()) for value in raw.split(","))
    except ValueError:
        raise Rejected("relay_configuration_error") from None
    if not cids or len(cids) > 64 or any(cid <= 3 or cid >= 0xFFFFFFFF for cid in cids):
        raise Rejected("relay_configuration_error")
    return region, cids


def check_systemd():
    if sys.platform != "linux" or not hasattr(socket, "AF_VSOCK"):
        raise Rejected("relay_unsupported_host")
    result = subprocess.run(["/usr/bin/systemctl", "--system", "show", "--property=Version", "--value"], env=CLEAN_ENV,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=True)
    match = re.match(rb"([0-9]+)(?:[. -]|\n|$)", result.stdout[:256])
    if match is None or int(match[1]) < MIN_SYSTEMD:
        raise Rejected("relay_unsupported_host")


def authorize(connection, cids):
    # socket.socket(fileno=...) autodetects the real family; do not assign a
    # caller-supplied family with fromfd(), which could disguise another socket.
    if connection.family != getattr(socket, "AF_VSOCK", None):
        raise Rejected("relay_socket_contract_error")
    if connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise Rejected("relay_socket_contract_error")
    if connection.getsockname() != (3, 8003):
        raise Rejected("relay_socket_contract_error")
    peer = connection.getpeername()
    if len(peer) != 2 or peer[0] not in cids:
        raise Rejected("relay_peer_denied")


def main():
    try:
        region, cids = configuration(os.environ)
        incoming, outgoing = os.fstat(0), os.fstat(1)
        if not stat.S_ISSOCK(incoming.st_mode) or not stat.S_ISSOCK(outgoing.st_mode) or (
                incoming.st_dev, incoming.st_ino) != (outgoing.st_dev, outgoing.st_ino):
            raise Rejected("relay_socket_contract_error")
        with socket.socket(fileno=os.dup(0)) as connection:
            authorize(connection, cids)
        check_systemd()
        # Only a validated literal regional hostname enters this address. No
        # caller bytes, AWS variables, proxy variables or profiles reach socat.
        os.execve("/usr/bin/socat", ["socat", "-t", "1", "-T", "12", "STDIO",
            f"TCP:kms.{region}.amazonaws.com:443,connect-timeout=3"], CLEAN_ENV)
    except Rejected as error:
        print(str(error), file=sys.stderr)
    except Exception:
        # OS/provider/configuration diagnostics may contain secrets. Never log
        # raw exceptions or write diagnostics into the TLS stream on stdout.
        print("relay_start_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
