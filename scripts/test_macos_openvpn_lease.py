"""真实实验依赖的描述符边界；不创建隧道或发送业务。"""
from pathlib import Path
import socket
import subprocess
import unittest

from macos_pinned import validate_dependency

BINARY=Path(__file__).resolve().parents[1]/'validation-output/macos-deps/openvpn-2.6.23-lease-local/sbin/openvpn'


class DependencyTests(unittest.TestCase):
    def run_binary(self, descriptor, pass_fds=()):
        return subprocess.run([str(BINARY),'--dev','tun','--dev-node','utun-fd:'+descriptor,
                               '--proto','udp','--remote','127.0.0.1','9','--nobind',
                               '--ifconfig-noexec','--route-noexec','--verb','3'],
                              pass_fds=pass_fds,capture_output=True,text=True,timeout=3)

    def test_binary_matches_fixed_source_and_patch(self):
        self.assertTrue(validate_dependency(BINARY)['experimental_only'])

    def test_malformed_standard_and_overflow_descriptors_rejected(self):
        for value in ('','bad','0','1','2','-1','+3',' 3','3x','99999999999999999999999999'):
            with self.subTest(value=value):
                r=self.run_binary(value)
                self.assertNotEqual(r.returncode,0)
                self.assertIn('实验隧道描述符参数无效',r.stdout+r.stderr)
                self.assertNotIn('Opened utun device',r.stdout+r.stderr)

    def test_closed_descriptor_rejected_without_fallback(self):
        r=self.run_binary('99999')
        self.assertNotEqual(r.returncode,0)
        self.assertIn('实验隧道描述符无法复制',r.stdout+r.stderr)
        self.assertNotIn('Opened utun device',r.stdout+r.stderr)

    def test_unrelated_socket_rejected_and_parent_descriptor_survives(self):
        owner,peer=socket.socketpair()
        try:
            r=self.run_binary(str(owner.fileno()),(owner.fileno(),))
            self.assertNotEqual(r.returncode,0)
            self.assertIn('实验隧道描述符不是有效控制接口',r.stdout+r.stderr)
            self.assertNotIn('Opened utun device',r.stdout+r.stderr)
            owner.sendall(b'held')
            peer.settimeout(2)
            self.assertEqual(peer.recv(4),b'held')
        finally:
            owner.close()
            peer.close()

    def test_unrelated_datagram_socket_rejected(self):
        owner,peer=socket.socketpair(type=socket.SOCK_DGRAM)
        try:
            r=self.run_binary(str(owner.fileno()),(owner.fileno(),))
            self.assertNotEqual(r.returncode,0)
            self.assertIn('实验隧道描述符不是有效控制接口',r.stdout+r.stderr)
            self.assertNotIn('Opened utun device',r.stdout+r.stderr)
        finally:
            owner.close()
            peer.close()


if __name__=='__main__':unittest.main()
