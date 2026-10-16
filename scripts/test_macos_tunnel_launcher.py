"""单文件启动桥接的真实失败入口；普通用户不得启动特权隧道。"""
from pathlib import Path
import os
import subprocess
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'target/debug/vap'


@unittest.skipUnless(sys.platform == 'darwin' and BINARY.exists() and os.geteuid() != 0,
                     '需要普通用户及已构建的苹果程序')
class TunnelLauncherTests(unittest.TestCase):
    def test_unprivileged_launcher_refuses_before_opening_paths(self):
        process = subprocess.run([
            str(BINARY), 'mac-tunnel', '--dependency-manifest', '/missing/dependency.json',
            '--profile', '/missing/profile.conf', '--management', '/missing/manager.sock',
            '--remote', '8.8.8.8:443', '--transport', 'tcp', '--interface-index', '1',
            '--authorization', str(uuid.uuid4()),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(process.returncode, 1, process.stderr.decode(errors='replace'))
        self.assertIn('管理员身份', process.stderr.decode(errors='replace'))
        self.assertEqual(process.stdout, b'')

    def test_launcher_is_not_listed_in_public_help(self):
        process = subprocess.run([str(BINARY), '--help'], capture_output=True, timeout=5)
        self.assertEqual(process.returncode, 0)
        self.assertNotIn(b'mac-tunnel', process.stdout)


if __name__ == '__main__':
    unittest.main()
