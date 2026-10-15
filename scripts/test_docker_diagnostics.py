"""夹具失败诊断在清理前留存并隐藏秘密。"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import validate_docker


class FixtureDiagnosticsTests(unittest.TestCase):
    def test_state_and_logs_preserved_without_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.log"
            with patch.object(validate_docker, "run", side_effect=[
                subprocess.CompletedProcess([], 0, '{"ExitCode":1}', ""),
                subprocess.CompletedProcess([], 0, "启动失败 secret-value", ""),
            ]) as command:
                error = validate_docker.fixture_startup_failure("owned-fixture", output, ("secret-value",))
            self.assertIn('"ExitCode":1', output.read_text())
            self.assertIn("启动失败", str(error))
            self.assertNotIn("secret-value", output.read_text() + str(error))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(command.call_count, 2)
            self.assertNotIn("{{json .Config}}", str(command.call_args_list))

    def test_diagnostic_timeout_does_not_hide_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.log"
            with patch.object(validate_docker, "run", side_effect=subprocess.TimeoutExpired("docker", 10)):
                error = validate_docker.fixture_startup_failure("owned-fixture", output)
            self.assertIn("受控节点夹具未启动", str(error))
            self.assertIn("TimeoutExpired", output.read_text())


if __name__ == "__main__":
    unittest.main()
