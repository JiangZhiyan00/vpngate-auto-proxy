"""隧道解析探针：真实回环数据报、截断后的流式解析及错误远端。"""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import threading
import unittest
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("macos_dns", ROOT / "tests/fixtures/macos_dns.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
PROBE = ROOT / "target/debug/examples/macos_dns_probe"


class DNSProbeTests(unittest.TestCase):
    def test_failed_fixture_start_always_restores_response_handler(self):
        original = fixture.response
        with patch.object(fixture, 'servers', side_effect=OSError('受控端口冲突')):
            with self.assertRaises(OSError):
                self.execute('node-a', mutate=lambda reply: reply + b'changed')
        self.assertIs(fixture.response, original)

    def test_ephemeral_pair_retries_when_udp_port_is_occupied(self):
        original = fixture.socketserver.ThreadingTCPServer
        created = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            def server(address, handler):
                value = original(occupied.getsockname() if not created else address, handler)
                created.append(value)
                return value
            with patch.object(fixture.socketserver, 'ThreadingTCPServer', side_effect=server):
                udp, tcp = fixture.servers(('127.0.0.1', 0), 'node-a')
                with udp, tcp:
                    self.assertEqual(udp.server_address, tcp.server_address)
                    self.assertNotEqual(udp.server_address, occupied.getsockname())
            self.assertGreaterEqual(len(created), 2)
            self.assertEqual(created[0].socket.fileno(), -1)

    def execute(self, identity, interface=None, mutate=None):
        original = fixture.response
        if mutate:
            fixture.response = lambda *args, **kwargs: mutate(original(*args, **kwargs))
        try:
            udp, tcp = fixture.servers(("127.0.0.1", 0), "node-a")
            with udp, tcp:
                for server in (udp, tcp):
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    return subprocess.run(
                        [str(PROBE), str(interface or socket.if_nametoindex("lo0")), "127.0.0.1",
                         str(udp.server_address[1]), identity], capture_output=True, text=True, timeout=8,
                    )
                finally:
                    udp.shutdown()
                    tcp.shutdown()
        finally:
            fixture.response = original

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_udp_and_truncated_tcp_resolution(self):
        result = self.execute("node-a")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["dns_udp"] and value["dns_tcp_fallback"])
        self.assertEqual(value["resolved_ipv4"], "10.231.66.1")

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_wrong_remote_identity_rejected(self):
        result = self.execute("node-b")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_wrong_transaction_rejected(self):
        result = self.execute("node-a", mutate=lambda reply: bytes([reply[0] ^ 1]) + reply[1:])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_wrong_question_rejected(self):
        result = self.execute("node-a", mutate=lambda reply: reply[:13] + b"x" + reply[14:])
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_invalid_interface_has_no_default_fallback(self):
        result = self.execute("node-a", interface=4294967295)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_tcp_fallback_response_is_validated(self):
        def mutate(reply):
            if reply[2] == 0x81 and reply[12:22] == b"\x09truncated":
                return reply[:-1] + b"\x02"
            return reply
        result = self.execute("node-a", mutate=mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_truncated_response_question_is_validated_before_tcp(self):
        def mutate(reply):
            return reply[:13] + b"x" + reply[14:] if reply[2] == 0x83 else reply
        result = self.execute("node-a", mutate=mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
    def test_tcp_response_length_is_bounded(self):
        result = self.execute("node-a", mutate=lambda reply: reply + b"x" * 513 if reply[2] == 0x81 and reply[12:22] == b"\x09truncated" else reply)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
