"""独立监督通道所有者退出的边界，不等同于正式服务崩溃验收。"""
from pathlib import Path
import json
import array
import os
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
import sys
from unittest.mock import Mock, patch

from macos_parallel import Tunnel
from macos_supervision import ManagementOwner, exercise_supervision, transfer_worker_control
from macos_tunnel import REPO
from macos_retained import read_record


class ManagementArgumentsTests(unittest.TestCase):
    def test_local_lifeline_is_generated_as_client_and_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path = folder / 'lifeline.sock'
            with patch('macos_parallel.client_config', return_value='受控配置'), \
                 patch('macos_parallel.subprocess.Popen') as spawn:
                Tunnel(SimpleNamespace(openvpn='/openvpn'), folder, folder, 0,
                       {'port': 12345}, set(), management_path=path)
            command = spawn.call_args.args[0]
            self.assertIn('--management-client', command)
            self.assertIn('--management-hold', command)
            self.assertEqual(command[command.index('--management')+1:command.index('--management')+3],
                             [str(path), 'unix'])

    def test_management_path_must_stay_in_private_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            with patch('macos_parallel.client_config', return_value='受控配置'), \
                 patch('macos_parallel.subprocess.Popen') as spawn:
                with self.assertRaisesRegex(RuntimeError, '私有'):
                    Tunnel(SimpleNamespace(openvpn='/openvpn'), folder, folder, 0,
                           {'port': 12345}, set(), management_path=Path('/tmp/unowned.sock'))
            spawn.assert_not_called()


class OwnerProcessTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.runtime = Path(self.folder.name)
        self.owner = ManagementOwner(self.runtime, hold=True)
        self.addCleanup(self.owner.close)
        self.owner.ready()

    def test_private_socket_and_forced_owner_exit_close_both_channels(self):
        self.assertEqual(self.owner.path.stat().st_mode & 0o777, 0o600)
        manager = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(manager.close)
        manager.settimeout(2)
        manager.connect(str(self.owner.path))
        self.owner.connected()
        business, peer = socket.socketpair()
        self.addCleanup(business.close)
        self.addCleanup(peer.close)
        peer.settimeout(2)
        self.owner.adopt(business.fileno())
        business.close()
        with self.assertRaises(socket.timeout):
            peer.recv(1)
        self.owner.process.kill()
        self.assertEqual(self.owner.process.wait(timeout=3), -9)
        self.assertEqual(manager.recv(1), b'')
        self.assertEqual(peer.recv(1), b'')

    def test_observer_eof_closes_both_channels_without_signal(self):
        manager = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(manager.close)
        manager.settimeout(2)
        manager.connect(str(self.owner.path))
        self.owner.connected()
        business, peer = socket.socketpair()
        self.addCleanup(business.close)
        self.addCleanup(peer.close)
        peer.settimeout(2)
        self.owner.adopt(business.fileno())
        business.close()
        self.owner.channel.close()
        self.assertEqual(self.owner.process.wait(timeout=3), 0)
        self.assertEqual(manager.recv(1), b'')
        self.assertEqual(peer.recv(1), b'')
        self.assertFalse(self.owner.path.exists())

    def test_second_adoption_fails_and_releases_all_received_endpoints(self):
        peers = []
        for attempt in range(2):
            business, peer = socket.socketpair()
            self.addCleanup(business.close)
            self.addCleanup(peer.close)
            peer.settimeout(2)
            peers.append(peer)
            if attempt == 0:
                self.owner.adopt(business.fileno())
            else:
                with self.assertRaises(RuntimeError):
                    self.owner.adopt(business.fileno())
            business.close()
        self.assertNotEqual(self.owner.process.wait(timeout=3), 0)
        for peer in peers:
            self.assertEqual(peer.recv(1), b'')

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生工作进程或实验依赖")
    def test_fixed_external_program_stops_when_owner_is_killed_during_hold(self):
        binary = REPO/'validation-output/macos-deps/openvpn-2.6.23-lease-local/sbin/openvpn'
        # 明确要求固定依赖存在；缺少工具不能计作通过。
        self.assertTrue(binary.is_file(), '缺少固定实验依赖')
        log_path = self.runtime/'external.log'
        with log_path.open('w') as log:
            external = subprocess.Popen([str(binary), '--dev', 'null', '--proto', 'udp4',
                '--remote', '127.0.0.1', '9', '--route-noexec', '--ifconfig-noexec', '--script-security', '1',
                '--management', str(self.owner.path), 'unix', '--management-client', '--management-hold', '--verb', '3'],
                stdout=log, stderr=log)
        def cleanup():
            if external.poll() is None:
                external.kill()
            external.wait(timeout=3)
        self.addCleanup(cleanup)
        self.owner.connected()
        self.assertEqual(self.owner.read_event()['event'], 'management_hold')
        self.assertIsNone(external.poll(), log_path.read_text())
        self.owner.process.kill()
        self.assertEqual(self.owner.process.wait(timeout=3), -9)
        self.assertEqual(external.wait(timeout=3), 0, log_path.read_text())
        self.assertIn('MANAGEMENT: Triggering management exit', log_path.read_text())
        self.assertIn('Signal received from management interface, exiting', log_path.read_text())

    @unittest.skipUnless(sys.platform == "darwin", "需要苹果系统的原生工作进程或实验依赖")
    def test_forced_owner_exit_retires_real_worker_and_registered_connections(self):
        import test_macos_generation_worker as worker_fixture
        case = worker_fixture.WorkerTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        custody_peer = case.restart_with_custody()
        case.send('probe')
        self.assertEqual(case.read()['event'], 'verified')
        transfer_worker_control(SimpleNamespace(process=case.worker), self.owner)
        self.assertIsNone(case.worker.stdin)
        self.owner.process.kill()
        self.assertEqual(self.owner.process.wait(timeout=3), -9)
        self.assertEqual(case.worker.wait(timeout=3), 0)
        ack = case.read()
        self.assertEqual(ack['event'], 'retired')
        self.assertEqual(ack['generation'], case.ready['generation'])
        self.assertTrue(case.closed.wait(timeout=1))
        self.assertEqual(custody_peer.recv(1), b'')

    def test_file_control_endpoint_is_rejected_before_adoption(self):
        with tempfile.TemporaryFile() as file:
            with self.assertRaises(RuntimeError):
                self.owner.adopt(file.fileno())
        self.assertNotEqual(self.owner.process.wait(timeout=3), 0)

    def test_truncated_control_transfer_exits_and_releases_all_endpoints(self):
        pairs = [socket.socketpair() for _ in range(32)]
        for business, peer in pairs:
            self.addCleanup(business.close)
            self.addCleanup(peer.close)
            peer.settimeout(2)
        self.owner.channel.sendmsg([b'A'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [business.fileno() for business, _ in pairs]))])
        for business, _ in pairs:
            business.close()
        self.assertNotEqual(self.owner.process.wait(timeout=3), 0)
        for _, peer in pairs:
            self.assertEqual(peer.recv(1), b'')


class OwnerFrameTests(unittest.TestCase):
    def test_coalesced_events_are_not_lost_to_text_prefetch(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        stream = os.fdopen(read_fd, 'rb', buffering=0)
        self.addCleanup(stream.close)
        owner = ManagementOwner.__new__(ManagementOwner)
        owner.process = SimpleNamespace(stdout=stream)
        owner.buffer = b''
        os.write(write_fd, b'{"event":"management_connected"}\n{"event":"management_hold"}\n')
        self.assertEqual(owner.read_event()['event'], 'management_connected')
        with patch('macos_supervision.select.select', side_effect=AssertionError('余帧已经在缓冲区')):
            self.assertEqual(owner.read_event()['event'], 'management_hold')


class SupervisionStageTests(unittest.TestCase):
    def exercise(self, supervisor_code=-9, worker_code=0, tunnel_code=0,
                 foreign_reason=False, early_worker=False, bad_candidate=False, stalled_tunnel=False):
        order = []
        nodes = [SimpleNamespace(close=Mock(), index=str(34+i), interface=f'utun{6+i}') for i in range(3)]
        owner = Mock()
        owner.path = Path('/runtime/supervisor.sock')
        owner.process.poll.return_value = None
        owner.process.wait.return_value = supervisor_code
        owner.process.kill.side_effect = lambda: order.append('supervisor-kill')
        worker = Mock()
        worker.generation = 'generation'
        worker.process.poll.return_value = 0 if early_worker else None
        worker.process.wait.side_effect = lambda **kwargs: order.append('worker-exit') or worker_code
        managed = SimpleNamespace(index='36', interface='utun8', ready=Mock(), process=Mock(),
                                  control_handle=Mock(), log=Mock())
        managed.process.poll.return_value = None
        if stalled_tunnel:
            managed.process.wait.side_effect = subprocess.TimeoutExpired('owned-tunnel', 6)
        else:
            managed.process.wait.side_effect = lambda **kwargs: order.append('tunnel-exit') or tunnel_code
        managed.control_handle.identity_present.return_value = True
        managed.log.read_text.return_value = 'other-reason' if foreign_reason else 'SIGTERM[soft,management-exit]'
        workers, evidence = [], {}
        def construct_worker(*args):
            self.assertIn(owner, workers)
            return worker
        def transfer(actual, controller):
            self.assertIn(actual, workers)
            self.assertIs(controller, owner)
            order.append('transfer-control')
        def released(actual):
            self.assertIs(actual, managed)
            order.append('release-parent-utun')
        def removed(actual):
            self.assertIs(actual, managed)
            self.assertEqual(order[-2:], ['worker-exit', 'tunnel-exit'])
            order.append('interface-release')
        candidate = Mock(side_effect=RuntimeError('候选归属错误') if bad_candidate else None)
        error = None
        with patch('macos_supervision.ManagementOwner', return_value=owner), \
             patch('macos_supervision.PinnedTunnel', return_value=managed), \
             patch('macos_supervision.CustodyGenerationWorker', side_effect=construct_worker), \
             patch('macos_supervision.transfer_worker_control', side_effect=transfer), \
             patch('macos_supervision.release_parent', side_effect=released), \
             patch('macos_supervision.verify_candidate', candidate), \
             patch('macos_supervision.require_removed', side_effect=removed), \
             patch('macos_supervision.read_record', return_value={'event': 'retired', 'generation': 'generation'}), \
             patch('macos_tunnel.interfaces', return_value={}):
            try:
                exercise_supervision(SimpleNamespace(), Path('/bundle'), nodes, Path('/runtime'),
                                     [{}, {}, {}], 501, 20, evidence, workers)
            except (RuntimeError, subprocess.TimeoutExpired) as caught:
                error = caught
        worker.process.kill.assert_not_called()
        managed.process.kill.assert_not_called()
        return error, order, evidence, candidate

    def test_observer_does_not_signal_consumers_to_manufacture_success(self):
        error, order, evidence, candidate = self.exercise()
        self.assertIsNone(error)
        self.assertTrue(all(evidence['checks'].values()))
        self.assertEqual(order, ['transfer-control', 'release-parent-utun', 'supervisor-kill',
                                 'worker-exit', 'tunnel-exit', 'interface-release'])
        self.assertEqual(candidate.call_count, 2)

    def test_unexpected_supervisor_exit_stops_before_consumer_checks(self):
        error, order, evidence, _ = self.exercise(supervisor_code=0)
        self.assertIn('强制退出', str(error))
        self.assertNotIn('worker-exit', order)

    def test_consumer_errors_prevent_interface_release(self):
        for worker_code, tunnel_code in [(1, 0), (0, 1)]:
            with self.subTest(worker_code=worker_code, tunnel_code=tunnel_code):
                error, order, evidence, _ = self.exercise(worker_code=worker_code, tunnel_code=tunnel_code)
                self.assertIn('自动停止', str(error))
                self.assertNotIn('interface-release', order)

    def test_unrelated_tunnel_exit_reason_is_not_supervision_evidence(self):
        error, order, evidence, _ = self.exercise(foreign_reason=True)
        self.assertIn('退出原因', str(error))
        self.assertNotIn('interface-release', order)

    def test_early_worker_exit_prevents_supervisor_fault_injection(self):
        error, order, evidence, _ = self.exercise(early_worker=True)
        self.assertIn('故障前', str(error))
        self.assertNotIn('supervisor-kill', order)

    def test_failed_positive_candidate_stops_before_fault(self):
        error, order, evidence, _ = self.exercise(bad_candidate=True)
        self.assertIn('候选', str(error))
        self.assertNotIn('supervisor-kill', order)

    def test_stalled_tunnel_is_failure_without_observer_signal(self):
        error, order, evidence, _ = self.exercise(stalled_tunnel=True)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertNotIn('interface-release', order)


if __name__ == '__main__':
    unittest.main()
