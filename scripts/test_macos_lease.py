"""借用进程异常退出、精确单元占用与资源回收门槛。"""
import errno
import os
import signal
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from macos_lease import BorrowedWorker, CONTROL_ADDRESS, CONTROL_INFO, UtunHandle, borrowed, exercise_lease, open_control


class DescriptorTests(unittest.TestCase):
    def test_killed_borrower_does_not_close_supervisor_descriptor(self):
        owner, peer = socket.socketpair()
        peer.settimeout(2)
        worker = BorrowedWorker(owner, os.getuid(), os.getgid())
        try:
            worker.ready()
            worker.process.kill()
            self.assertEqual(worker.process.wait(timeout=3), -signal.SIGKILL)
            owner.sendall(b'lease')
            self.assertEqual(peer.recv(5), b'lease')
            owner.close()
            self.assertEqual(peer.recv(1), b'')
        finally:
            worker.close()
            owner.close()
            peer.close()

    def test_borrowed_descriptor_does_not_trigger_socket_address_inference(self):
        owner, peer = socket.socketpair()
        fd = os.dup(owner.fileno())
        try:
            with patch('macos_lease.socket.socket', side_effect=OSError(102, '不支持')), patch('macos_lease.sys.stdin'), patch('builtins.print'):
                borrowed(fd)
            with self.assertRaises(OSError):
                os.fstat(fd)
            owner.sendall(b'x')
            self.assertEqual(peer.recv(1), b'x')
        finally:
            owner.close()
            peer.close()

    def test_target_abi_sizes(self):
        self.assertEqual(CONTROL_INFO.size, 100)
        self.assertEqual(CONTROL_ADDRESS.size, 32)


class ControlTests(unittest.TestCase):
    def test_explicit_unit_avoids_unsupported_address_query(self):
        handle = Mock()
        handle.getsockopt.return_value = b'utun42\0'
        libc = Mock()
        libc.connect.return_value = 0
        with patch('macos_lease.socket.socket', return_value=handle), patch('macos_lease.fcntl.ioctl'), patch('macos_lease.ctypes.CDLL', return_value=libc), patch('macos_lease.socket.if_nametoindex', return_value=142):
            actual, name, index = open_control(17)
        self.assertIs(actual, handle)
        self.assertEqual((name, index), ('utun42', 142))
        handle.getsockname.assert_not_called()
        libc.getsockname.assert_not_called()
        address = CONTROL_ADDRESS.unpack(libc.connect.call_args[0][1].raw[:32])
        self.assertEqual(address[4],17)
        handle.close.assert_not_called()

    def test_failed_native_call_reports_stage_and_closes_handle(self):
        handle = Mock()
        with patch('macos_lease.socket.socket', return_value=handle), patch('macos_lease.fcntl.ioctl', side_effect=OSError(102, '不支持')):
            with self.assertRaises(OSError) as caught:
                open_control(17)
        self.assertEqual(caught.exception.stage, 'lookup_control')
        handle.close.assert_called_once()

    def test_busy_connect_tries_next_explicit_unit(self):
        error = OSError(errno.EBUSY, '占用')
        error.stage = 'connect_control'
        with patch('macos_lease.open_control', side_effect=[error,(Mock(),'utun42',142)]) as opened:
            handle = UtunHandle()
        self.assertEqual(handle.unit, 2)
        self.assertEqual([c.args[0] for c in opened.call_args_list], [1,2])

    def test_busy_lookup_is_not_treated_as_unit_collision(self):
        error = OSError(errno.EBUSY, '查询失败')
        error.stage = 'lookup_control'
        with patch('macos_lease.open_control', side_effect=error) as opened:
            with self.assertRaises(OSError):
                UtunHandle()
        opened.assert_called_once_with(1)


class LifecycleTests(unittest.TestCase):
    def execute(self, collision=None, borrower_stuck=False):
        handles = []
        snapshot = dict(interfaces={}, routes=[], resolver='', firewall='')
        worker = Mock()
        worker.process.poll.return_value = None
        worker.process.wait.side_effect = lambda **kw: setattr(worker.process.poll, 'return_value', -9) or -9
        if borrower_stuck:
            worker.close.side_effect = RuntimeError('借用进程无法回收')
            worker.process.wait.side_effect = RuntimeError('等待退出失败')
        def handle(unit=0):
            if unit and collision is not None:
                error = OSError(collision, '受控占用错误')
                error.stage = 'connect_control'
                raise error
            obj = SimpleNamespace(name='utun42' if not handles else 'utun43', index=142+len(handles), unit=43+len(handles), close=Mock())
            obj.identity_present = lambda: not obj.close.called
            handles.append(obj)
            return obj
        def names():
            return {h.name: [] for h in handles if not h.close.called}
        with patch('macos_lease.UtunHandle', side_effect=handle), patch('macos_lease.BorrowedWorker', return_value=worker), patch('macos_lease.baseline', return_value=snapshot), patch('macos_lease.interfaces', side_effect=names):
            result = exercise_lease(501,20)
        return result, handles, worker

    def test_borrower_killed_but_owned_interface_stays_reserved(self):
        r, handles, worker = self.execute(collision=errno.EBUSY)
        self.assertEqual(r['status'], 'passed')
        self.assertTrue(r['interface_lifetime_validated'])
        self.assertTrue(all(r['checks'].values()))
        self.assertEqual(len(handles), 2)
        self.assertTrue(all(h.close.called for h in handles))

    def test_successful_same_unit_allocation_is_failure_and_is_reaped(self):
        r, handles, worker = self.execute()
        self.assertEqual(r['status'], 'failed')
        self.assertIn('占用', r['error'])
        self.assertTrue(all(h.close.called for h in handles))

    def test_unrelated_permission_error_does_not_prove_reservation(self):
        r, handles, worker = self.execute(collision=errno.EPERM)
        self.assertEqual(r['status'], 'failed')
        self.assertFalse(r['checks'].get('same_unit_reserved', False))

    def test_unreaped_borrower_prevents_supervisor_release(self):
        r, handles, worker = self.execute(collision=errno.EBUSY, borrower_stuck=True)
        self.assertEqual(r['status'], 'failed')
        self.assertTrue(r['cleanup_errors'])
        self.assertTrue(all(not h.close.called for h in handles))


if __name__ == '__main__':
    unittest.main()
