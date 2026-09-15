"""CID guard regression tests; no AWS endpoint or Nitro hardware required."""
import importlib.util
import io
import os
from pathlib import Path
import socket
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("swap_kms_relay", Path(__file__).resolve().parents[1] / "swap-kms-relay-guard.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class RelayGuardTests(unittest.TestCase):
    def setUp(self):
        self.environment = {"AWS_REGION":"eu-central-1", "SWAP_KMS_ALLOWED_CIDS":"16,18"}
        self.vsock = getattr(socket, "AF_VSOCK", 40)
        self.connection = Mock(family=self.vsock)
        self.connection.getsockopt.return_value = socket.SOCK_STREAM
        self.connection.getsockname.return_value = (3, 8003)
        self.connection.getpeername.return_value = (16, 12345)

    def test_configuration_has_one_literal_regional_destination(self):
        self.assertEqual(m.configuration(self.environment), ("eu-central-1", frozenset({16,18})))
        for field, value in (("AWS_REGION",""),("AWS_REGION","eu-west-1,exec=command"),
                ("AWS_REGION","cn-north-1"),("AWS_REGION","us-gov-west-1"),
                ("SWAP_KMS_ALLOWED_CIDS",""),("SWAP_KMS_ALLOWED_CIDS","3"),
                ("SWAP_KMS_ALLOWED_CIDS","16,,18"),("SWAP_KMS_ALLOWED_CIDS","4294967295")):
            with self.subTest(field=field,value=value), self.assertRaises(m.Rejected):
                m.configuration(dict(self.environment, **{field:value}))

    def test_allowed_peer_comes_from_kernel_socket_address(self):
        with patch.object(m.socket,"AF_VSOCK",self.vsock,create=True):
            m.authorize(self.connection, frozenset({16,18}))
        self.connection.recv.assert_not_called()

    def test_wrong_family_type_local_port_or_peer_is_rejected_before_read(self):
        mutations = (("family",socket.AF_INET), ("getsockopt",socket.SOCK_DGRAM),
            ("getsockname",(3,8004)), ("getsockname",(2,8003)),
            ("getpeername",(20,12345)), ("getpeername",(3,12345)))
        for name,value in mutations:
            connection = Mock(family=self.vsock)
            connection.getsockopt.return_value=socket.SOCK_STREAM
            connection.getsockname.return_value=(3,8003)
            connection.getpeername.return_value=(16,12345)
            if name == "family": connection.family=value
            else: getattr(connection,name).return_value=value
            with self.subTest(name=name,value=value), patch.object(m.socket,"AF_VSOCK",self.vsock,create=True), self.assertRaises(m.Rejected):
                m.authorize(connection,frozenset({16,18}))
            connection.recv.assert_not_called()

    def test_actual_non_vsock_socket_cannot_be_disguised_by_constructor(self):
        first, second=socket.socketpair()
        try:
            with socket.socket(fileno=os.dup(first.fileno())) as autodetected:
                with self.assertRaises(m.Rejected):
                    m.authorize(autodetected,frozenset({16}))
        finally:
            first.close();second.close()

    def test_running_systemd_version_must_support_cid_admission(self):
        with patch.object(m.sys,"platform","linux"), patch.object(m.socket,"AF_VSOCK",self.vsock,create=True):
            for value in (b"219\n",b"251.9\n",b"unrecognized version\n"):
                with patch.object(m.subprocess,"run",return_value=SimpleNamespace(stdout=value)), self.assertRaises(m.Rejected):
                    m.check_systemd()
            with patch.object(m.subprocess,"run",return_value=SimpleNamespace(stdout=b"252.39-1\n")) as command:
                m.check_systemd()
            self.assertEqual(command.call_args.args[0], ["/usr/bin/systemctl","--system","show","--property=Version","--value"])
            self.assertEqual(command.call_args.kwargs["env"],m.CLEAN_ENV)
        with patch.object(m.sys,"platform","darwin"), self.assertRaises(m.Rejected):
            m.check_systemd()

    def test_socket_activation_contract_and_child_environment(self):
        descriptor=SimpleNamespace(st_mode=stat.S_IFSOCK,st_dev=1,st_ino=2)
        self.connection.__enter__=Mock(return_value=self.connection)
        self.connection.__exit__=Mock(return_value=False)
        class ExecCalled(BaseException): pass
        with patch.dict(m.os.environ,dict(self.environment,AWS_SECRET_ACCESS_KEY="secret",https_proxy="malicious"),clear=True), \
                patch.object(m,"check_systemd"), patch.object(m.os,"fstat",return_value=descriptor), \
                patch.object(m.os,"dup",return_value=9), patch.object(m.socket,"socket",return_value=self.connection), \
                patch.object(m.socket,"AF_VSOCK",self.vsock,create=True), \
                patch.object(m.os,"execve",side_effect=ExecCalled) as execute, self.assertRaises(ExecCalled):
            m.main()
        self.assertEqual(execute.call_args.args,("/usr/bin/socat",["socat","-t","1","-T","12","STDIO","TCP:kms.eu-central-1.amazonaws.com:443,connect-timeout=3"],m.CLEAN_ENV))

    def test_denied_peer_is_rejected_before_systemctl_or_socat(self):
        descriptor=SimpleNamespace(st_mode=stat.S_IFSOCK,st_dev=1,st_ino=2)
        self.connection.__enter__=Mock(return_value=self.connection)
        self.connection.__exit__=Mock(return_value=False)
        self.connection.getpeername.return_value=(20,12345)
        with patch.dict(m.os.environ,self.environment,clear=True), patch.object(m.os,"fstat",return_value=descriptor), \
                patch.object(m.os,"dup",return_value=9), patch.object(m.socket,"socket",return_value=self.connection), \
                patch.object(m.socket,"AF_VSOCK",self.vsock,create=True), patch.object(m,"check_systemd") as version, \
                patch.object(m.os,"execve") as execute, patch.object(m.sys,"stderr",new_callable=io.StringIO) as err:
            self.assertEqual(m.main(),1)
        version.assert_not_called()
        execute.assert_not_called()
        self.assertEqual(err.getvalue(),"relay_peer_denied\n")

    def test_wrong_stdio_contract_and_startup_errors_never_forward_or_leak(self):
        descriptor=SimpleNamespace(st_mode=stat.S_IFREG,st_dev=1,st_ino=2)
        with patch.dict(m.os.environ,self.environment,clear=True), patch.object(m,"check_systemd"), \
                patch.object(m.os,"fstat",return_value=descriptor), patch.object(m.os,"execve") as execute, \
                patch.object(m.sys,"stderr",new_callable=io.StringIO) as err, patch.object(m.sys,"stdout",new_callable=io.StringIO) as out:
            self.assertEqual(m.main(),1)
        execute.assert_not_called()
        self.assertEqual(err.getvalue(),"relay_socket_contract_error\n")
        self.assertEqual(out.getvalue(),"")
        with patch.dict(m.os.environ,self.environment,clear=True), patch.object(m.os,"fstat",side_effect=OSError("secret credential")), patch.object(m.sys,"stderr",new_callable=io.StringIO) as err:
            self.assertEqual(m.main(),1)
        self.assertEqual(err.getvalue(),"relay_start_failed\n")


if __name__ == "__main__":
    unittest.main()
