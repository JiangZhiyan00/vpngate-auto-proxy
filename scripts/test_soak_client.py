"""容量客户端的失败判定回归；不以这些局部测试替代真实隧道验收。"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest


class ClientFailureTests(unittest.TestCase):
    def exercise(self, response, rejection):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()

        def serve():
            with listener:
                connection, _ = listener.accept()
                with connection:
                    connection.recv(3)
                    if response:
                        connection.sendall(response)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("soak_client.py"))],
            input=json.dumps({"host": "127.0.0.1", "port": listener.getsockname()[1], "username": "secret-user",
                              "password": "secret-password", "connections": 10, "expect_rejection": rejection}) + "\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("secret-user", result.stdout + result.stderr)
        self.assertNotIn("secret-password", result.stdout + result.stderr)
        return result

    def test_closed_connection_counts_as_explicit_capacity_rejection(self):
        result = self.exercise(None, True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"rejected": True})

    def test_accepted_authentication_is_not_a_capacity_rejection(self):
        result = self.exercise(bytes([5, 2]), True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", json.loads(result.stdout))

    def test_invalid_authentication_response_fails_without_secret_output(self):
        result = self.exercise(bytes([5, 255]), False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
