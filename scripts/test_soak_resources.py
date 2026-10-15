"""资源采样竞争回归；不启动服务或容器。"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import validate_soak


class ProcessMemoryTests(unittest.TestCase):
    def test_sums_live_statuses_and_quotes_directory(self):
        with tempfile.TemporaryDirectory(prefix="采样 空格'") as directory:
            root = Path(directory)
            for identity, rss, peak in [(1, 2, 3), (2, 5, 7)]:
                (root / str(identity)).mkdir()
                (root / str(identity) / "status").write_text(f"Name: test\nVmRSS: {rss} kB\nVmHWM: {peak} kB\n")
            result = subprocess.run(["sh", "-c", validate_soak.process_memory_command(root)], capture_output=True, text=True, check=True)
            self.assertEqual([int(value) for value in result.stdout.split()], [7 * 1024, 10 * 1024])

    def sampling_failure(self, disappearing):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "1").mkdir()
            (root / "1/status").write_text("VmRSS: 2 kB\nVmHWM: 3 kB\n")
            fake = root / "bin"
            fake.mkdir()
            script = '#!/bin/sh\n'
            if disappearing:
                script += '/bin/rm "$1"\n'
            script += 'exit 1\n'
            (fake / "cat").write_text(script)
            (fake / "cat").chmod(0o755)
            return subprocess.run(["sh", "-c", validate_soak.process_memory_command(root)], capture_output=True, text=True,
                                  env={**os.environ, "PATH": str(fake) + ":" + os.environ["PATH"]})

    def test_disappearing_status_is_skipped(self):
        result = self.sampling_failure(True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "0 0")

    def test_existing_unreadable_status_fails(self):
        result = self.sampling_failure(False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
