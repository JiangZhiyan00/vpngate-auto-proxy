"""防漏探针的真实套接字正对照及无效接口拒绝。"""
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import threading
import unittest
import sys

PROBE = Path(__file__).resolve().parents[1] / "target/debug/examples/macos_guard_probe"


@unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生接口及探针")
class GuardTests(unittest.TestCase):
    def execute(self, index):
        received = []

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                received.append(("tcp", self.request.recv(128)))

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                received.append(("udp", self.request[0]))

        with socketserver.TCPServer(("127.0.0.1", 0), TCP) as tcp:
            with socketserver.UDPServer(tcp.server_address, UDP) as udp:
                for server in (tcp, udp):
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    result = subprocess.run([str(PROBE), str(index), "127.0.0.1",
                                             str(tcp.server_address[1]), "controlled-marker"],
                                            capture_output=True, text=True, timeout=8)
                finally:
                    tcp.shutdown()
                    udp.shutdown()
        return result, received

    def test_loopback_positive_control_sends_both_markers(self):
        result, received = self.execute(socket.if_nametoindex("lo0"))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["tcp_written"] and report["udp_sent"])
        self.assertCountEqual(received, [("tcp", b"controlled-marker-tcp"), ("udp", b"controlled-marker-udp")])

    def test_invalid_interface_reports_both_failures_without_fallback(self):
        result, received = self.execute(4294967295)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["tcp_connected"] or report["tcp_written"] or report["udp_sent"])
        self.assertEqual(received, [])


if __name__ == "__main__":
    unittest.main()
