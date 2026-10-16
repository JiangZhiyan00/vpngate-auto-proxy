"""离线部署的秘密保护、完整性和失败前置回归。"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import cloud_deploy


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def bundle(self):
        for name, value in {"bundle.json": '{}', "images.tar": '镜像', "config.json": '{}',
                            "compose.yaml": 'services: {}', "image.env": 'VAP_IMAGE=test:cloud',
                            "deploy/compose.apparmor.yaml": 'services: {}',
                            **{name: '受校验内容' for name in cloud_deploy.REQUIRED_FILES - {
                                'bundle.json', 'images.tar', 'compose.yaml', 'image.env', 'deploy/compose.apparmor.yaml'}}}.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        self.sums()

    def sums(self):
        (self.root / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(self.root).as_posix()}\n'
            for p in sorted(self.root.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'))

    def test_editable_config_does_not_disable_immutable_checks(self):
        self.bundle()
        (self.root / 'config.json').write_text('{"health_interval_seconds":5}')
        cloud_deploy.verify_files(self.root)
        (self.root / 'compose.yaml').write_text('篡改')
        with self.assertRaisesRegex(RuntimeError, 'compose.yaml'):
            cloud_deploy.verify_files(self.root)

    def test_checksum_traversal_and_missing_required_entries_rejected(self):
        self.bundle()
        with (self.root / 'SHA256SUMS').open('a') as stream:
            stream.write('0' * 64 + '  ../outside\n')
        with self.assertRaises(RuntimeError):
            cloud_deploy.verify_files(self.root)
        (self.root / 'SHA256SUMS').write_text('')
        with self.assertRaises(RuntimeError):
            cloud_deploy.verify_files(self.root)

    def test_init_preserves_existing_credentials_and_never_prints_password(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cloud_deploy.initialize(self.root)
        path = self.root / 'credentials.local.json'
        original = path.read_bytes()
        credentials = json.loads(original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(len(credentials['password']), 32)
        with contextlib.redirect_stdout(output):
            cloud_deploy.initialize(self.root)
        self.assertEqual(path.read_bytes(), original)
        self.assertNotIn(credentials['password'], output.getvalue())

    def test_symlink_and_shared_credentials_rejected(self):
        outside = self.root / 'outside.json'
        outside.write_text('{"username":"test","password":"secret"}')
        outside.chmod(0o600)
        target = self.root / 'credentials.local.json'
        target.symlink_to(outside)
        with self.assertRaises(RuntimeError):
            cloud_deploy.initialize(self.root)
        target.unlink()
        os.link(outside, target)
        with self.assertRaises(RuntimeError):
            cloud_deploy.initialize(self.root)

    def test_group_readable_credentials_rejected(self):
        cloud_deploy.initialize(self.root)
        (self.root / 'credentials.local.json').chmod(0o640)
        with self.assertRaises(RuntimeError):
            cloud_deploy.read_credentials(self.root)

    def test_compose_uses_stable_project_and_explicit_policy(self):
        base = cloud_deploy.compose_command(self.root, True)
        self.assertIn('vpngate-auto-proxy', base)
        self.assertIn(str(self.root / 'deploy/compose.apparmor.yaml'), base)
        self.assertNotIn(str(self.root / 'deploy/compose.apparmor.yaml'), cloud_deploy.compose_command(self.root, False))

    def test_up_does_not_run_compose_when_check_fails(self):
        with patch.object(cloud_deploy, 'check', side_effect=RuntimeError('策略缺失')), \
             patch.object(cloud_deploy, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, '策略缺失'):
                cloud_deploy.manage(self.root, 'up')
            execute.assert_not_called()

    def test_ready_exit_code_is_preserved(self):
        self.bundle()
        with patch.object(cloud_deploy, 'security_options', return_value=[]), \
             patch.object(cloud_deploy, 'execute', return_value=subprocess.CompletedProcess([], 3)) as execute:
            self.assertEqual(cloud_deploy.manage(self.root, 'ready'), 3)
            command = execute.call_args.args[0]
            self.assertIn('--check-ready', command)
            self.assertEqual(command[command.index('proxy') + 1], 'vap')

    def test_stop_preserves_volume_and_has_fifteen_second_timeout(self):
        self.bundle()
        with patch.object(cloud_deploy, 'security_options', return_value=[]), \
             patch.object(cloud_deploy, 'execute', return_value=subprocess.CompletedProcess([], 0)) as execute:
            self.assertEqual(cloud_deploy.manage(self.root, 'stop'), 0)
            self.assertEqual(execute.call_args.args[0][-4:], ['stop', '--timeout', '15', 'proxy'])

    def test_compose_environment_cannot_override_image_or_files(self):
        with patch.dict(os.environ, {'COMPOSE_FILE': '/other.yaml', 'VAP_IMAGE': 'wrong:tag',
                                     'DOCKER_DEFAULT_PLATFORM': 'linux/arm64'}), \
             patch.object(cloud_deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            cloud_deploy.execute(['docker', 'compose', 'config'], self.root)
            environment = run.call_args.kwargs['env']
            self.assertNotIn('COMPOSE_FILE', environment)
            self.assertNotIn('VAP_IMAGE', environment)
            self.assertNotIn('DOCKER_DEFAULT_PLATFORM', environment)

    def test_ready_and_stop_do_not_require_available_image_archive(self):
        self.bundle()
        (self.root / 'images.tar').unlink()
        with patch.object(cloud_deploy, 'security_options', return_value=[]), \
             patch.object(cloud_deploy, 'execute', return_value=subprocess.CompletedProcess([], 0)):
            self.assertEqual(cloud_deploy.manage(self.root, 'stop'), 0)

    def test_failed_check_invalidates_old_success_report(self):
        output = self.root / 'validation-output'
        output.mkdir()
        report = output / 'deployment-check.json'
        report.write_text('{"status":"passed"}')
        with patch.object(cloud_deploy, '_check', side_effect=RuntimeError('策略缺失')):
            with self.assertRaises(RuntimeError):
                cloud_deploy.check(self.root)
        self.assertEqual(json.loads(report.read_text())['status'], 'failed')

    def test_legacy_crypto_opt_in_is_explicit_boolean(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps({'listen': '0.0.0.0:1080',
                                      'credentials_file': '/run/secrets/proxy_credentials',
                                      'data_dir': '/var/lib/vap', 'runtime_dir': '/run/vap',
                                      'allow_legacy_vpngate_crypto': True}))
        self.assertTrue(cloud_deploy.validate_config(self.root))
        config.write_text(config.read_text().replace('true', '"true"'))
        with self.assertRaisesRegex(RuntimeError, '布尔值'):
            cloud_deploy.validate_config(self.root)

    def test_rendered_compose_rejects_device_or_secret_redirection(self):
        proxy = {'image': 'test:cloud', 'pull_policy': 'never', 'read_only': True,
                 'cap_drop': ['ALL'], 'cap_add': sorted(cloud_deploy.CAPS),
                 'security_opt': ['no-new-privileges:true'],
                 'ports': [{'host_ip': '127.0.0.1', 'target': 1080, 'published': '1080'}],
                 'devices': [{'source': '/dev/net/tun', 'target': '/dev/net/tun'}],
                 'sysctls': {'net.ipv4.ip_forward': '1'},
                 'volumes': [{'type': 'bind', 'source': str(self.root / 'config.json'),
                              'target': '/etc/vap/config.json', 'read_only': True},
                             {'type': 'volume', 'source': 'proxy-data', 'target': '/var/lib/vap'}],
                 'secrets': [{'source': 'proxy_credentials', 'target': '/run/secrets/proxy_credentials'}],
                 'stop_grace_period': '15s'}
        rendered = {'services': {'proxy': proxy},
                    'secrets': {'proxy_credentials': {'file': str(self.root / 'credentials.local.json')}},
                    'volumes': {'proxy-data': {'name': 'vpngate-auto-proxy_proxy-data'}}}
        cloud_deploy.validate_compose(rendered, 'test:cloud', False, self.root)
        for field in ('device', 'secret', 'config_read_only'):
            with self.subTest(field=field):
                copy = json.loads(json.dumps(rendered))
                changed_proxy = copy['services']['proxy']
                if field == 'device':
                    changed_proxy['devices'][0]['target'] = '/dev/null'
                elif field == 'secret':
                    copy['secrets']['proxy_credentials']['file'] = '/tmp/stolen'
                else:
                    changed_proxy['volumes'][0]['read_only'] = False
                with self.assertRaisesRegex(RuntimeError, '容器配置'):
                    cloud_deploy.validate_compose(copy, 'test:cloud', False, self.root)


if __name__ == '__main__':
    unittest.main()
