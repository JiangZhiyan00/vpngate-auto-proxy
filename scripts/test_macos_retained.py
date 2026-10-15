"""保留套接字探针：故障前后使用同一组真实套接字。"""
from pathlib import Path
import os
import socket
import hashlib
import socketserver
import subprocess
import threading
import unittest

from macos_retained import read_record
from macos_lease import BorrowedWorker
PROBE = Path(__file__).resolve().parents[1] / "target/debug/examples/macos_tunnel_probe"


class RetainedTests(unittest.TestCase):
    def execute(self, close_connection, unexpected=False, custody=False):
        sockets, connections = [], []
        stopped = threading.Event()

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                connections.append(1)
                sockets.append(self.request)
                self.request.settimeout(8)
                try:
                    self.request.sendall(b"node-a:")
                    while True:
                        data = self.request.recv(128)
                        if not data:
                            break
                        self.request.sendall(b"x" if unexpected and data.endswith(b"-after-removal") else data)
                except OSError:
                    return

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                if not stopped.is_set():
                    data, sock = self.request
                    sock.sendto(b"x" if unexpected and data.endswith(b"-after-removal") else b"node-a:" + data, self.client_address)

        with socketserver.TCPServer(("127.0.0.1", 0), TCP) as tcp:
            with socketserver.UDPServer(tcp.server_address, UDP) as udp:
                for server in (tcp, udp):
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                owner, peer, holder = None, None, None
                if custody:
                    owner, peer = socket.socketpair()
                    holder = BorrowedWorker(owner, os.getuid(), os.getgid())
                    holder.ready()
                process = subprocess.Popen([str(PROBE), str(socket.if_nametoindex("lo0")),
                                            "127.0.0.1", str(tcp.server_address[1]), "payload", "node-a", "1", "retained"],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                           pass_fds=(owner.fileno(),) if custody else ())
                try:
                    ready = read_record(process)
                    self.assertTrue(ready["tcp"] and ready["udp"])
                    if custody:
                        owner.close()
                        holder.process.kill()
                        self.assertEqual(holder.process.wait(timeout=3), -9)
                        peer.settimeout(0.1)
                        with self.assertRaises(socket.timeout):
                            peer.recv(1)
                        self.assertIsNone(process.poll())
                    if close_connection:
                        stopped.set()
                        for peer in sockets:
                            peer.shutdown(socket.SHUT_RDWR)
                    process.stdin.write("c")
                    process.stdin.flush()
                    result = read_record(process)
                    self.assertEqual(process.wait(timeout=3), 0, process.stderr.read())
                    if custody:
                        peer.settimeout(2)
                        self.assertEqual(peer.recv(1), b'')
                    self.assertEqual(len(connections), 1)
                    return result
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=3)
                    for pipe in (process.stdin, process.stdout, process.stderr):
                        pipe.close()
                    if holder is not None:
                        holder.close()
                        owner.close()
                        peer.close()
                    tcp.shutdown()
                    udp.shutdown()

    def test_live_original_sockets_are_detected_as_still_forwarding(self):
        result = self.execute(False)
        self.assertTrue(result["retained_tcp_response"] and result["retained_udp_response"])
        self.assertEqual(result['retained_tcp_response_sha256'], hashlib.sha256(b'payload-after-removal').hexdigest())
        self.assertEqual(result['retained_udp_response_sha256'], hashlib.sha256(b'node-a:payload-after-removal').hexdigest())

    def test_closed_tcp_and_silent_udp_are_reported_independently(self):
        result = self.execute(True)
        self.assertFalse(result["retained_tcp_response"] or result["retained_udp_response"])
        self.assertIsNone(result['retained_tcp_response_sha256'])
        self.assertIsNone(result['retained_udp_response_sha256'])

    def test_unexpected_or_partial_response_is_not_treated_as_blocked(self):
        result = self.execute(False, unexpected=True)
        self.assertTrue(result["retained_tcp_response"] and result["retained_udp_response"])

    def test_actual_business_probe_holds_descriptor_after_other_holders_exit(self):
        result = self.execute(False, custody=True)
        self.assertTrue(result['retained_tcp_response'] and result['retained_udp_response'])


if __name__ == "__main__":
    unittest.main()
