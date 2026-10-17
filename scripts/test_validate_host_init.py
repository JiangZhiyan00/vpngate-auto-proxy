"""重启证据工具只读契约，不触及真实宿主。"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_host_init import HostFixture, load_installer
import validate_host_init


class EvidenceTests(unittest.TestCase):
    def test_actual_boot_change_required_without_initializing(self):
        module = load_installer()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in ('etc/apparmor.d', 'var/lib', 'run/lock', 'deploy/apparmor'):
                (root / relative).mkdir(parents=True, exist_ok=True)
            policy = b'profile vpngate-auto-proxy {}\n'
            (root / 'deploy/apparmor/vpngate-auto-proxy').write_bytes(policy)
            host = HostFixture(root)
            host.module = module
            host.safe_inventory = lambda: {'containers': [], 'other_profiles_sha256': 'e' * 64}
            release = module.Release('v1.2.3', 'a' * 40, policy, 'b' * 64)
            setup = module.HostSetup(release, host, root=root, owner=os.getuid())
            setup.run()
            calls = host.calls.count('load')
            with patch.object(validate_host_init, 'ROOT', root):
                before = validate_host_init.collect('before-reboot', module=module, host=host, files=setup.files)
                with self.assertRaises(module.Rejected):
                    validate_host_init.collect('after-reboot', before, module, host, setup.files)
                host.boot_id = 'different-test-boot'
                after = validate_host_init.collect('after-reboot', before, module, host, setup.files)
                self.assertTrue(after['reboot_validated'])
                host.mode = None
                with self.assertRaises(module.Rejected):
                    validate_host_init.collect('after-reboot', before, module, host, setup.files)
            self.assertEqual(calls, host.calls.count('load'))
            self.assertFalse(before['reboot_validated'])
            self.assertFalse(after['initialization_performed'])


if __name__ == '__main__':
    unittest.main()
