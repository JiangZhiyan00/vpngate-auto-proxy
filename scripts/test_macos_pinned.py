"""保留接口句柄的故障阶段与旧套接字响应拒绝。"""
import json
import errno
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from macos_parallel import Tunnel
from macos_abrupt import RetainedProbe
from macos_pinned import PinnedTunnel, exercise_pinned


class PinnedTests(unittest.TestCase):
    def execute(self, response=False, wrong_index=False, early_probe=False, custody=False,
                local_closed=True, holder_exit=-9, lost_interface=False, probe_exit=0):
        order=[]
        handles=[Mock() for _ in range(3)]
        for h in handles:
            h.identity_present.return_value=not lost_interface
            h.fileno.return_value=17
        handles[2].close.side_effect=lambda:order.append('local-close')
        holder=Mock()
        holder.process.poll.return_value=None
        holder.process.wait.side_effect=lambda **kw:setattr(holder.process.poll,'return_value',holder_exit) or holder_exit
        holder.process.kill.side_effect=lambda:order.append('holder-kill')
        nodes=[SimpleNamespace(index=str(34+i),interface=f'utun{6+i}',control_handle=handles[i],process=Mock(),close=Mock()) for i in range(3)]
        nodes[2].process.poll.return_value=None
        nodes[2].process.wait.return_value=-9
        nodes[2].process.kill.side_effect=lambda:order.append('kill')
        worker=Mock()
        worker.process.poll.return_value=None
        worker.process.wait.side_effect=lambda **kw: setattr(worker.process.poll,'return_value',probe_exit) or order.append('probe-exit') or probe_exit
        nodes[2].close.side_effect=lambda:order.append('release')
        activity=Mock()
        activity.poll.return_value=None
        activity.wait.side_effect=lambda **kw:setattr(activity.poll,'return_value',-15)
        replacement=SimpleNamespace(index='36' if wrong_index else '34',interface='utun6',ready=Mock())
        positive=dict(interface_index=36,identity='old',tcp=True,udp=True)
        observed=dict(interface_index=36,identity='old',retained_tcp_write_succeeded=True,retained_udp_send_succeeded=True,
                      retained_tcp_response=False,retained_tcp_response_sha256=None,
                      retained_udp_response=response,retained_udp_response_sha256='a'*64 if response else None)
        evidence,workers={},[]
        def construct(*args,**kwargs):
            self.assertEqual(order,['local-close','holder-kill','kill'] if custody else ['kill'])
            self.assertEqual(workers,[holder,worker] if custody else [worker])
            nodes[2].close.assert_not_called()
            if early_probe:worker.process.poll.return_value=0
            return replacement
        def run(command,**kwargs):
            value=(dict(interface_index=int(command[1]),identity=command[5],tcp=True,udp=True) if command[0]=='/probe' else
                   dict(interface_index=int(command[1]),identity=command[4],dns_udp=True,dns_tcp_fallback=True,resolved_ipv4='10.231.66.1'))
            return SimpleNamespace(stdout=json.dumps(value))
        error=None
        with patch('macos_pinned.RetainedProbe',return_value=worker),patch('macos_pinned.read_record',side_effect=[positive,observed]),patch('macos_pinned.PinnedTunnel',side_effect=construct),patch('macos_pinned.interfaces',return_value={}),patch('macos_pinned.run',side_effect=run),patch('macos_pinned.BorrowedWorker',return_value=holder),patch('macos_pinned.os.fstat',side_effect=OSError(errno.EBADF,'已关闭') if local_closed else None),patch('macos_pinned.reconcile_removed_route') as reconcile:
            try:
                exercise_pinned(SimpleNamespace(probe='/probe',dns_probe='/dns'),Path('/bundle'),nodes,activity,Path('/runtime'),
                                [{'identity':v} for v in ('new','candidate','old')],501,20,evidence,workers,custody=custody)
            except RuntimeError as caught:error=caught
            if custody and error is None:reconcile.assert_called_once_with(nodes[2])
        return error,evidence,order,worker,nodes,workers

    def test_old_probe_exits_before_owned_handle_release(self):
        error,evidence,order,worker,nodes,workers=self.execute()
        self.assertIsNone(error)
        self.assertTrue(all(evidence['checks'].values()))
        self.assertEqual(order,['kill','probe-exit','release'])
        self.assertEqual(len(nodes),4)

    def test_any_old_socket_response_is_failure(self):
        error,evidence,order,worker,nodes,workers=self.execute(response=True)
        self.assertIn('响应',str(error))
        self.assertNotIn('release',order)
        self.assertEqual(workers,[worker])

    def test_replacement_cannot_take_pinned_old_index(self):
        error,evidence,order,worker,nodes,workers=self.execute(wrong_index=True)
        self.assertIn('身份',str(error))
        worker.process.stdin.write.assert_not_called()
        self.assertEqual(len(nodes),4)

    def test_probe_exit_before_challenge_is_failure(self):
        error,evidence,order,worker,nodes,workers=self.execute(early_probe=True)
        self.assertIn('探针',str(error))
        worker.process.stdin.write.assert_not_called()

    def test_business_custody_survives_both_owned_process_deaths(self):
        error,evidence,order,worker,nodes,workers=self.execute(custody=True)
        self.assertIsNone(error)
        self.assertTrue(all(evidence['checks'].values()))
        self.assertEqual(order,['local-close','holder-kill','kill','probe-exit','release'])
        self.assertEqual(evidence['holder_exit_code'],-9)

    def test_unclosed_local_descriptor_cannot_count_as_business_custody(self):
        error,evidence,order,worker,nodes,workers=self.execute(custody=True,local_closed=False)
        self.assertIn('句柄',str(error))
        self.assertNotIn('holder-kill',order)
        self.assertEqual(len(workers),2)

    def test_unexpected_holder_exit_prevents_tunnel_fault(self):
        error,evidence,order,worker,nodes,workers=self.execute(custody=True,holder_exit=1)
        self.assertIn('持有进程',str(error))
        self.assertNotIn('kill',order)

    def test_interface_loss_with_business_probe_alive_is_failure(self):
        error,evidence,order,worker,nodes,workers=self.execute(custody=True,lost_interface=True)
        self.assertIn('接口',str(error))
        worker.process.stdin.write.assert_not_called()

    def test_custody_response_is_not_treated_as_blocked(self):
        error,evidence,order,worker,nodes,workers=self.execute(custody=True,response=True)
        self.assertIn('响应',str(error))
        self.assertNotIn('release',order)

    def test_abnormal_business_exit_is_failure_even_without_responses(self):
        error,evidence,order,worker,nodes,workers=self.execute(custody=True,probe_exit=1)
        self.assertIn('正常退出',str(error))
        self.assertNotIn('release',order)


class HandleOwnershipTests(unittest.TestCase):
    def test_custody_failure_cleanup_reconciles_only_removed_owned_route(self):
        with tempfile.TemporaryDirectory() as directory:
            node=Tunnel.__new__(Tunnel)
            node.closed=False
            node.route_added=True
            node.interface='utun42'
            node.configuration=Path(directory)/'client.conf'
            node.process=Mock()
            node.process.poll.return_value=-9
            node.control_handle=Mock()
            node.control_handle_transferred=True
            def reconcile(actual):
                self.assertIs(actual,node)
                actual.route_added=False
            with patch('macos_parallel.interfaces',return_value={}),patch('macos_abrupt.reconcile_removed_route',side_effect=reconcile) as checked,patch('macos_parallel.run') as run:
                node.close()
            checked.assert_called_once_with(node)
            run.assert_not_called()
            self.assertTrue(node.closed)

    def test_business_probe_inherits_only_requested_control_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            handle=Mock()
            handle.fileno.return_value=17
            with patch('macos_abrupt.subprocess.Popen') as spawn:
                RetainedProbe(SimpleNamespace(probe='/probe'),SimpleNamespace(index='36'),
                              'old','payload',Path(directory),501,20,control_handle=handle)
            self.assertEqual(spawn.call_args.kwargs['pass_fds'],(17,))
            self.assertEqual(spawn.call_args.kwargs['extra_groups'],[])

    def test_constructor_passes_only_owned_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            handle=Mock(name='句柄')
            handle.name='utun42'
            handle.fileno.return_value=17
            with patch('macos_pinned.UtunHandle',return_value=handle),patch('macos_parallel.client_config',return_value='受控配置'),patch('macos_parallel.subprocess.Popen') as spawn:
                PinnedTunnel(SimpleNamespace(openvpn='/experimental'),folder,folder,0,{'port':12345},set())
            command=spawn.call_args.args[0]
            self.assertEqual(command[command.index('--dev-node')+1],'utun-fd:17')
            self.assertEqual(spawn.call_args.kwargs['pass_fds'],(17,))
            handle.close.assert_not_called()

    def test_spawn_failure_releases_owned_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            handle=Mock()
            handle.name='utun42'
            with patch('macos_pinned.UtunHandle',return_value=handle),patch('macos_parallel.client_config',return_value='受控配置'),patch('macos_parallel.subprocess.Popen',side_effect=OSError('启动失败')):
                with self.assertRaises(OSError):
                    PinnedTunnel(SimpleNamespace(openvpn='/experimental'),folder,folder,0,{'port':12345},set())
            handle.close.assert_called_once()
            self.assertFalse((folder/'client-0.conf').exists())

    def test_tunnel_exit_precedes_control_handle_release(self):
        with tempfile.TemporaryDirectory() as directory:
            order=[]
            node=Tunnel.__new__(Tunnel)
            node.closed=False
            node.route_added=False
            node.interface='utun42'
            node.configuration=Path(directory)/'client.conf'
            node.process=Mock()
            node.process.poll.return_value=None
            node.process.wait.side_effect=lambda **kw:setattr(node.process.poll,'return_value',0) or order.append('tunnel-exit')
            node.control_handle=Mock()
            node.control_handle.close.side_effect=lambda:order.append('handle-release')
            with patch('macos_parallel.interfaces',return_value={}):node.close()
            self.assertEqual(order,['tunnel-exit','handle-release'])
            self.assertTrue(node.closed)

    def test_unreaped_tunnel_prevents_control_handle_close(self):
        with tempfile.TemporaryDirectory() as directory:
            node=Tunnel.__new__(Tunnel)
            node.closed=False
            node.route_added=False
            node.interface=None
            node.configuration=Path(directory)/'client.conf'
            node.process=Mock()
            node.process.poll.return_value=None
            node.process.wait.side_effect=RuntimeError('隧道无法回收')
            node.control_handle=Mock()
            with self.assertRaises(RuntimeError):node.close()
            node.control_handle.close.assert_not_called()
            self.assertFalse(node.closed)


if __name__=='__main__':unittest.main()
