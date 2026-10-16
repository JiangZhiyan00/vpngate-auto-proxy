"""依赖准备与普通权限入口回归；真实候选由显式环境变量提供。"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'target/debug/vap'
spec = importlib.util.spec_from_file_location('dependency_builder', ROOT / 'scripts/prepare-macos-dependency.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuilderTests(unittest.TestCase):
    def test_root_build_refused_before_reading_or_running_tools(self):
        with mock.patch.object(builder.platform, 'system', return_value='Darwin'), \
             mock.patch.object(builder.platform, 'machine', return_value='arm64'), \
             mock.patch.object(builder.os, 'getuid', return_value=0), \
             mock.patch.object(builder.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, '普通用户'):
                builder.build(Path('/missing/output'), Path('/missing/crypto'), APP)
            run.assert_not_called()

    def test_existing_output_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            output.write_bytes(b'keep')
            with mock.patch.object(builder.platform, 'system', return_value='Darwin'), \
                 mock.patch.object(builder.platform, 'machine', return_value='arm64'), \
                 mock.patch.object(builder.os, 'getuid', return_value=501), \
                 mock.patch.object(builder.os, 'geteuid', return_value=501), \
                 mock.patch.object(builder.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, '拒绝覆盖'):
                    builder.build(output, Path('/missing/crypto'), APP)
                run.assert_not_called()
            self.assertEqual(output.read_bytes(), b'keep')

    def test_changed_source_refused_before_compile(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(builder.platform, 'system', return_value='Darwin'), \
             mock.patch.object(builder.platform, 'machine', return_value='arm64'), \
             mock.patch.object(builder.os, 'getuid', return_value=501), \
             mock.patch.object(builder.os, 'geteuid', return_value=501), \
             mock.patch.object(builder, 'digest', return_value='0' * 64), \
             mock.patch.object(builder.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, '摘要不符'):
                builder.build(Path(directory) / 'output', Path('/missing/crypto'), APP)
            run.assert_not_called()


@unittest.skipUnless(sys.platform == 'darwin' and APP.exists() and os.geteuid() != 0, '需要普通用户及已构建的苹果程序')
class EntryTests(unittest.TestCase):
    def test_install_requires_root_before_reading_bundle(self):
        result = subprocess.run([str(APP), 'mac-dependency', '--install', '--bundle', '/missing/bundle'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn('管理员身份', result.stderr.decode())
        self.assertEqual(result.stdout, b'')

    def test_internal_entry_hidden_from_public_help(self):
        result = subprocess.run([str(APP), '--help'], capture_output=True, timeout=5, check=True)
        self.assertNotIn(b'mac-dependency', result.stdout)


BUNDLE = os.environ.get('VAP_TEST_DEPENDENCY_BUNDLE')


@unittest.skipUnless(sys.platform == 'darwin' and BUNDLE and APP.exists() and os.geteuid() != 0, '需要显式提供真实普通权限候选')
class ActualBundleTests(unittest.TestCase):
    def run_candidate(self, descriptor, pass_fds=()):
        path = Path(BUNDLE)
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'OPENSSL_CONF': '/dev/null',
               'OPENSSL_MODULES': str(path), 'OPENSSL_ENGINES': str(path)}
        return subprocess.run([str(path / 'openvpn'), '--dev', 'tun', '--dev-node', 'utun-fd:' + descriptor,
                               '--proto', 'udp', '--remote', '127.0.0.1', '9', '--nobind',
                               '--ifconfig-noexec', '--route-noexec', '--verb', '3'],
                              pass_fds=pass_fds, capture_output=True, text=True, env=env, timeout=3)

    def test_static_crypto_default_provider_is_available(self):
        path = Path(BUNDLE)
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'OPENSSL_CONF': '/dev/null',
               'OPENSSL_MODULES': str(path), 'OPENSSL_ENGINES': str(path)}
        result = subprocess.run([str(path / 'openvpn'), '--show-ciphers'], env=env, capture_output=True, text=True, timeout=5, check=True)
        self.assertIn('AES-256-GCM', result.stdout)

    def test_actual_bundle_pins_and_only_system_libraries(self):
        result = subprocess.run([str(APP), 'mac-dependency', '--bundle', BUNDLE], capture_output=True, text=True, timeout=10, check=True)
        record = json.loads(result.stdout)
        self.assertEqual(record['version'], '2.6.23')
        self.assertFalse(record['native_tunnel_validated'])
        self.assertEqual(set(record['system_libraries']), {'/usr/lib/libresolv.9.dylib', '/usr/lib/libSystem.B.dylib'})

    def test_invalid_standard_overflow_and_closed_descriptors_never_fall_back(self):
        for value in ('', 'bad', '0', '1', '2', '-1', '+3', '3x', '99999999999999999999999', '99999'):
            with self.subTest(value=value):
                result = self.run_candidate(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('实验隧道描述符', result.stdout + result.stderr)
                self.assertNotIn('Opened utun device', result.stdout + result.stderr)

    def test_unrelated_socket_rejected_and_parent_handle_survives(self):
        owner, peer = socket.socketpair()
        try:
            result = self.run_candidate(str(owner.fileno()), (owner.fileno(),))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('不是有效控制接口', result.stdout + result.stderr)
            owner.sendall(b'held')
            self.assertEqual(peer.recv(4), b'held')
        finally:
            owner.close()
            peer.close()


if __name__ == '__main__':
    unittest.main()
