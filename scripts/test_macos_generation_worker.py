"""真实子进程及回环套接字验证；不需要管理员权限。"""
import json
import array
from pathlib import Path
import select
import socket
import subprocess
import threading
import unittest
import uuid

REPO = Path(__file__).resolve().parents[1]


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tcp = socket.socket()
        self.tcp.bind(('127.0.0.1', 0))
        self.tcp.listen()
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', self.port))
        self.connections = []
        self.closed = threading.Event()
        self.stop = threading.Event()

        def stream():
            self.tcp.settimeout(0.1)
            while not self.stop.is_set():
                try:
                    peer, _ = self.tcp.accept()
                except socket.timeout:
                    continue
                self.connections.append(peer)
                peer.settimeout(0.1)
                peer.sendall(b'node-a:')
                while not self.stop.is_set():
                    try:
                        data = peer.recv(256)
                    except socket.timeout:
                        continue
                    if not data:
                        self.closed.set()
                        break
                    peer.sendall(data)
                peer.close()
        def datagram():
            self.udp.settimeout(0.1)
            while not self.stop.is_set():
                try:
                    data, address = self.udp.recvfrom(256)
                except socket.timeout:
                    continue
                self.udp.sendto(b'node-a:' + data, address)
        self.threads = [threading.Thread(target=f) for f in (stream, datagram)]
        for thread in self.threads:
            thread.start()
        self.worker = None
        self.addCleanup(self.cleanup)
        self.worker = subprocess.Popen(
            [str(REPO / 'target/debug/examples/macos_generation_worker'),
             str(socket.if_nametoindex('lo0')), '127.0.0.1', str(self.port), 'node-a'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self.ready = self.read()
        self.assertEqual(self.ready['event'], 'ready')

    def cleanup(self):
        if self.worker is not None:
            if self.worker.poll() is None:
                self.worker.kill()
            self.worker.communicate(timeout=3)
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=2)
        self.tcp.close()
        self.udp.close()

    def read(self):
        self.assertTrue(select.select([self.worker.stdout], [], [], 3)[0], '工作进程未按时输出')
        line = self.worker.stdout.readline(4097)
        self.assertTrue(line.endswith('\n'), '工作进程输出缺失')
        return json.loads(line)

    def send(self, op, generation=None, **extra):
        self.worker.stdin.write(json.dumps(dict(op=op, generation=generation or self.ready['generation'], **extra)) + '\n')
        self.worker.stdin.flush()

    def test_revoke_closes_real_connections_and_exits(self):
        self.send('probe')
        value = self.read()
        self.assertEqual(value['event'], 'verified')
        self.assertTrue(value['tcp'] and value['udp'])
        self.send('revoke')
        value = self.read()
        self.assertEqual(value['event'], 'retired')
        self.assertEqual(value['generation'], self.ready['generation'])
        self.assertEqual(self.worker.wait(timeout=3), 0)
        self.assertTrue(self.closed.wait(timeout=1), '回收完成后原连接未关闭')
        self.assertEqual(len(self.connections), 1)

    def test_stale_generation_rejected_but_current_still_works(self):
        self.send('probe', '00000000-0000-0000-0000-000000000000')
        self.assertEqual(self.read()['event'], 'rejected')
        self.assertEqual(len(self.connections), 0)
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.send('revoke')
        self.assertEqual(self.read()['event'], 'retired')
        self.assertEqual(self.worker.wait(timeout=3), 0)

    def test_retired_worker_id_is_rejected_by_real_replacement(self):
        old_id = self.ready['generation']
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.send('revoke')
        self.assertEqual(self.read()['event'], 'retired')
        self.assertEqual(self.worker.wait(timeout=3), 0)
        self.worker.communicate(timeout=3)
        self.worker = subprocess.Popen(
            [str(REPO / 'target/debug/examples/macos_generation_worker'),
             str(socket.if_nametoindex('lo0')), '127.0.0.1', str(self.port), 'node-a'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.ready = self.read()
        self.assertNotEqual(self.ready['generation'], old_id)
        self.send('probe', old_id)
        self.assertEqual(self.read()['event'], 'rejected')
        self.assertEqual(len(self.connections), 1)
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.assertEqual(len(self.connections), 2)
        self.send('revoke')
        self.assertEqual(self.read()['event'], 'retired')
        self.assertEqual(self.worker.wait(timeout=3), 0)

    def test_stale_revoke_does_not_stop_current_generation(self):
        self.send('revoke', '00000000-0000-0000-0000-000000000000')
        self.assertEqual(self.read()['event'], 'rejected')
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.send('revoke')
        self.assertEqual(self.read()['event'], 'retired')
        self.assertEqual(self.worker.wait(timeout=3), 0)

    def test_revoke_before_probe_opens_no_connection(self):
        self.send('revoke')
        self.assertEqual(self.read()['event'], 'retired')
        self.assertEqual(self.worker.wait(timeout=3), 0)
        self.assertEqual(len(self.connections), 0)

    def test_parent_pipe_eof_reaps_worker_and_socket(self):
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.worker.stdin.close()
        self.worker.stdin = None
        self.assertEqual(self.worker.wait(timeout=3), 0)
        self.assertTrue(self.closed.wait(timeout=1))

    def test_duplicate_operation_fails_and_releases_owned_socket(self):
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.send('probe')
        self.assertNotEqual(self.worker.wait(timeout=3), 0)
        self.assertTrue(self.closed.wait(timeout=1))
        self.assertEqual(len(self.connections), 1)

    def test_request_cannot_override_endpoint(self):
        self.send('probe', target='127.0.0.2')
        self.assertNotEqual(self.worker.wait(timeout=3), 0)
        self.assertEqual(len(self.connections), 0)

    def test_oversized_frame_is_rejected_without_network(self):
        self.worker.stdin.write('x' * 4097 + '\n')
        self.worker.stdin.flush()
        self.assertNotEqual(self.worker.wait(timeout=3), 0)
        self.assertEqual(len(self.connections), 0)

    def restart_with_custody(self, wrong_authorization=False, missing_descriptor=False, descriptor_count=1):
        self.worker.kill()
        self.worker.communicate(timeout=3)
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        owner, peer = socket.socketpair()
        extras = [socket.socketpair() for _ in range(descriptor_count - 1)]
        self.extra_custody_peers = [pair[1] for pair in extras]
        for extra_owner, extra_peer in extras:
            self.addCleanup(extra_owner.close)
            self.addCleanup(extra_peer.close)
        self.addCleanup(owner.close)
        self.addCleanup(peer.close)
        authorization = uuid.uuid4()
        index = socket.if_nametoindex('lo0')
        self.worker = subprocess.Popen(
            [str(REPO / 'target/debug/examples/macos_generation_worker'),
             str(index), '127.0.0.1', str(self.port), 'node-a',
             '--custody-stdin', str(authorization)],
            stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        child.close()
        token = uuid.uuid4() if wrong_authorization else authorization
        frame = b'VAP1' + token.bytes + index.to_bytes(4, 'big')
        ancillary = [] if missing_descriptor else [
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [owner.fileno()] + [pair[0].fileno() for pair in extras]))]
        self.assertEqual(parent.sendmsg([frame], ancillary), len(frame))
        owner.close()
        for extra_owner, _ in extras:
            extra_owner.close()
        self.worker.stdin = parent.makefile('w')
        parent.close()
        peer.settimeout(1)
        if not wrong_authorization and not missing_descriptor and descriptor_count == 1:
            self.ready = self.read()
            self.assertEqual(self.ready['event'], 'ready')
            peer.setblocking(False)
            with self.assertRaises(BlockingIOError):
                peer.recv(1)
            peer.settimeout(1)
        return peer

    def test_custody_retirement_closes_registered_connection_and_descriptor(self):
        peer = self.restart_with_custody()
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.send('revoke')
        self.assertEqual(self.read()['event'], 'retired')
        self.assertEqual(self.worker.wait(timeout=3), 0)
        self.assertTrue(self.closed.wait(timeout=1))
        self.assertEqual(peer.recv(1), b'')

    def test_custody_parent_eof_retires_worker_and_descriptor(self):
        peer = self.restart_with_custody()
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.worker.stdin.close()
        self.worker.stdin = None
        self.assertEqual(self.worker.wait(timeout=3), 0)
        self.assertTrue(self.closed.wait(timeout=1))
        self.assertEqual(peer.recv(1), b'')

    def test_custody_worker_kill_releases_descriptor(self):
        peer = self.restart_with_custody()
        self.send('probe')
        self.assertEqual(self.read()['event'], 'verified')
        self.worker.kill()
        self.assertEqual(self.worker.wait(timeout=3), -9)
        self.assertTrue(self.closed.wait(timeout=1))
        self.assertEqual(peer.recv(1), b'')

    def test_custody_wrong_authorization_rejected_before_network(self):
        peer = self.restart_with_custody(wrong_authorization=True)
        self.assertNotEqual(self.worker.wait(timeout=3), 0)
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(len(self.connections), 0)

    def test_custody_missing_descriptor_rejected_before_network(self):
        peer = self.restart_with_custody(missing_descriptor=True)
        self.assertNotEqual(self.worker.wait(timeout=3), 0)
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(len(self.connections), 0)

    def test_custody_truncated_transfer_exits_and_releases_all_kernel_descriptors(self):
        peer = self.restart_with_custody(descriptor_count=16)
        self.assertNotEqual(self.worker.wait(timeout=3), 0)
        self.assertEqual(peer.recv(1), b'')
        for extra_peer in self.extra_custody_peers:
            extra_peer.setblocking(False)
            self.assertEqual(extra_peer.recv(1), b'')
        self.assertEqual(len(self.connections), 0)

    def test_real_custody_rejects_unix_udp_and_file_without_ready_or_network(self):
        import tempfile
        for kind in ('unix', 'udp', 'file'):
            with self.subTest(kind=kind):
                self.worker.kill()
                self.worker.communicate(timeout=3)
                parent, child = socket.socketpair()
                peer = None
                if kind == 'unix':
                    owner, peer = socket.socketpair()
                elif kind == 'udp':
                    owner = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    owner.bind(('127.0.0.1', 0))
                else:
                    owner = tempfile.TemporaryFile()
                try:
                    authorization = uuid.uuid4()
                    index = socket.if_nametoindex('lo0')
                    self.worker = subprocess.Popen(
                        [str(REPO / 'target/debug/examples/macos_generation_worker'),
                         str(index), '127.0.0.1', str(self.port), 'node-a',
                         '--utun-custody-stdin', str(authorization)],
                        stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    child.close()
                    frame = b'VAP1' + authorization.bytes + index.to_bytes(4, 'big')
                    self.assertEqual(parent.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                        array.array('i', [owner.fileno()]))]), len(frame))
                    owner.close()
                    self.assertNotEqual(self.worker.wait(timeout=3), 0)
                    output, error = self.worker.communicate(timeout=3)
                    self.assertEqual(output, '', '真实隧道身份校验失败仍发布就绪')
                    self.assertTrue(error)
                    self.assertEqual(len(self.connections), 0)
                    if peer is not None:
                        peer.settimeout(1)
                        self.assertEqual(peer.recv(1), b'')
                finally:
                    owner.close()
                    parent.close()
                    child.close()
                    if peer is not None:
                        peer.close()


if __name__ == '__main__':
    unittest.main()
