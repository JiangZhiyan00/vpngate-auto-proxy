"""普通权限验证正式单文件工作进程拒绝伪造控制句柄。"""

import array
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/vap"


@unittest.skipUnless(sys.platform == "darwin" and BINARY.exists(), "需要已构建的苹果系统可执行文件")
class VerifiedWorkerProcessTests(unittest.TestCase):
    def test_counterfeit_descriptor_exits_without_publishing_listener(self):
        with tempfile.TemporaryDirectory(prefix="vap-worker-") as directory:
            listener = Path(directory) / "worker.sock"
            parent, child = socket.socketpair()
            fake, peer = socket.socketpair()
            authorization = uuid.uuid4()
            index = socket.if_nametoindex("lo0")
            try:
                process = subprocess.Popen(
                    [str(BINARY), "mac-worker", "--socket", str(listener),
                     "--max-connections", "1", "--interface-index", str(index),
                     "--authorization", str(authorization)],
                    stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                child.close()
                frame = b"VAP1" + authorization.bytes + index.to_bytes(4, "big")
                parent.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                          array.array("i", [fake.fileno()]))])
                try:
                    _, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
                    self.fail("伪造句柄未被及时拒绝")
                self.assertEqual(process.returncode, 1, stderr.decode(errors="replace"))
                self.assertFalse(listener.exists())
                self.assertIn("控制句柄", stderr.decode(errors="replace"))
                parent.settimeout(1)
                self.assertEqual(parent.recv(40), b"", "校验失败不得发布就绪确认")
            finally:
                parent.close()
                child.close()
                fake.close()
                peer.close()

    def test_control_eof_before_handoff_exits_without_listener(self):
        with tempfile.TemporaryDirectory(prefix="vap-worker-") as directory:
            listener = Path(directory) / "worker.sock"
            parent, child = socket.socketpair()
            try:
                process = subprocess.Popen(
                    [str(BINARY), "mac-worker", "--socket", str(listener),
                     "--max-connections", "1", "--interface-index",
                     str(socket.if_nametoindex("lo0")), "--authorization", str(uuid.uuid4())],
                    stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                child.close()
                parent.close()
                try:
                    _, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
                    self.fail("控制通道结束后工作进程未退出")
                self.assertEqual(process.returncode, 1, stderr.decode(errors="replace"))
                self.assertFalse(listener.exists())
            finally:
                parent.close()
                child.close()


if __name__ == "__main__":
    unittest.main()
