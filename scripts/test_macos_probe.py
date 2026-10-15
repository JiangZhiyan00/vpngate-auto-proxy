"""原生探针的真实回环验证：远端身份、错误身份和长连接。"""
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import threading
import unittest

PROBE = Path(__file__).resolve().parents[1] / "target/debug/examples/macos_tunnel_probe"


class ProbeTests(unittest.TestCase):
    def execute(self, identity, rounds, udp_identity="node-a"):
        connections = []

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                connections.append(1)
                self.request.sendall(b"node-a:")
                while True:
                    data = self.request.recv(128)
                    if not data:
                        break
                    self.request.sendall(data)

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                sock.sendto(udp_identity.encode() + b":" + data, self.client_address)

        with socketserver.TCPServer(("127.0.0.1", 0), TCP) as tcp:
            with socketserver.UDPServer(tcp.server_address, UDP) as udp:
                for server in (tcp, udp):
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    result = subprocess.run(
                        [str(PROBE), str(socket.if_nametoindex("lo0")), "127.0.0.1",
                         str(tcp.server_address[1]), "payload", identity, str(rounds)],
                        capture_output=True, text=True, timeout=8,
                    )
                finally:
                    tcp.shutdown()
                    udp.shutdown()
        return result, len(connections)

    def test_expected_identity_and_one_continuous_connection(self):
        result, connections = self.execute("node-a", 4)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(records), 4)
        self.assertEqual(connections, 1)
        self.assertTrue(all(v["tcp"] and v["udp"] and v["identity"] == "node-a" for v in records))

    def test_wrong_identity_fails(self):
        result, _ = self.execute("node-b", 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_wrong_datagram_identity_fails(self):
        result, connections = self.execute("node-a", 1, udp_identity="node-b")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(connections, 1)


if __name__ == "__main__":
    unittest.main()
