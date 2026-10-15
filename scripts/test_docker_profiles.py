"""安全策略在业务资源创建之前验证，失败保留明确诊断。"""
import subprocess
import unittest
from unittest.mock import patch

import docker_profiles


class ProfileTests(unittest.TestCase):
    def test_no_apparmor_requires_no_probe(self):
        with patch.object(docker_profiles.subprocess, 'run') as run:
            docker_profiles.require_profiles([], [('product:tag', 'vpngate-auto-proxy')])
            run.assert_not_called()

    def test_missing_profile_has_load_command_and_no_privileged_probe(self):
        failure = subprocess.CompletedProcess([], 127, '', 'label not found')
        with patch.object(docker_profiles.subprocess, 'run', return_value=failure) as run:
            with self.assertRaisesRegex(RuntimeError, 'apparmor_parser'):
                docker_profiles.require_profiles(['name=apparmor'], [('product:tag', 'vpngate-auto-proxy')])
            command = run.call_args_list[0].args[0]
            self.assertIn('none', command)
            self.assertIn('ALL', command)
            self.assertNotIn('--privileged', command)
            self.assertNotIn('--device', command)

    def test_cleanup_removes_only_matching_label(self):
        import json
        for owned in (True, False):
            token = None
            calls = []
            def run(command, **kwargs):
                nonlocal token
                calls.append(command)
                if command[1] == 'run':
                    token = command[command.index('--label') + 1].split('=', 1)[1]
                    return subprocess.CompletedProcess(command, 0, '', '')
                if command[1:3] == ['container', 'inspect']:
                    value = token if owned else '另一实例'
                    return subprocess.CompletedProcess(command, 0, json.dumps([
                        {'Config': {'Labels': {'io.vpngate-auto-proxy.preflight': value}}}]), '')
                return subprocess.CompletedProcess(command, 0, '', '')
            with self.subTest(owned=owned), patch.object(docker_profiles.subprocess, 'run', side_effect=run):
                docker_profiles.require_profiles(['name=apparmor'], [('product:tag', 'vpngate-auto-proxy')])
            self.assertEqual(any(command[1] == 'rm' for command in calls), owned)


if __name__ == '__main__':
    unittest.main()
