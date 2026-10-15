"""交接阶段的错误拒绝、身份保持与释放顺序。"""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from macos_handoff import exercise_handoff, require_removed


class HandoffTests(unittest.TestCase):
    def exercise(self, rejection_failed=False, wrong_candidate=False,
                 lost_identity=False, exited_worker=False, failed_kill=False):
        order = []
        nodes = []
        for i in range(3):
            node = SimpleNamespace(index=str(34+i), interface=f'utun{6+i}',
                                   control_handle=Mock(), process=Mock(), close=Mock())
            node.control_handle.identity_present.return_value = not (lost_identity and i == 1)
            node.process.wait.return_value = -9
            node.process.kill.side_effect = lambda i=i: order.append(f'tunnel-{i}-kill')
            nodes.append(node)
        workers, evidence = [], {}
        made = []
        def create(options, node, endpoint, runtime, label, uid, gid, expected_index=None):
            worker = Mock()
            worker.process.poll.return_value = 0 if exited_worker and label == 'retire' else None
            worker.process.wait.return_value = 1 if failed_kill else -9
            worker.process.kill.side_effect = lambda: order.append('worker-kill')
            worker.probe.return_value = {'tcp': True, 'udp': True}
            worker.rejected.return_value = {'exit_code': 1, 'ready_published': False}
            if rejection_failed and label == 'wrong-index':
                worker.rejected.side_effect = RuntimeError('错误索引被接受')
            worker.retire.side_effect = lambda: order.append('retire') or {'event': 'retired'}
            worker.handoff.side_effect = lambda handle: self.assertIn(worker, workers)
            if label == 'wrong-index':
                self.assertEqual(expected_index, 34)
                self.assertIs(node, nodes[2])
            made.append(worker)
            return worker
        def release(node):
            order.append(f'parent-{node.index}-close')
        def removed(node):
            order.append(f'interface-{node.index}-release')
        def run(command, **kwargs):
            value = dict(interface_index=int(command[1]), identity='wrong' if wrong_candidate else 'node-'+command[1],
                         tcp=True, udp=True, dns_udp=True, dns_tcp_fallback=True, resolved_ipv4='10.231.66.1')
            return SimpleNamespace(stdout=json.dumps(value))
        error = None
        with patch('macos_handoff.CustodyGenerationWorker', side_effect=create), \
             patch('macos_handoff.release_parent', side_effect=release), \
             patch('macos_handoff.require_removed', side_effect=removed), \
             patch('macos_handoff.run', side_effect=run):
            try:
                exercise_handoff(SimpleNamespace(probe='/probe', dns_probe='/dns'), nodes, Path('/runtime'),
                                 [{'identity': 'node-'+node.index} for node in nodes], 501, 20, evidence, workers)
            except RuntimeError as caught:
                error = caught
        return error, evidence, order, made

    def test_real_transfer_registered_before_send_and_exit_before_release(self):
        error, evidence, order, workers = self.exercise()
        self.assertIsNone(error)
        self.assertTrue(all(evidence['checks'].values()))
        self.assertEqual(order, ['parent-36-close', 'tunnel-2-kill', 'retire', 'interface-36-release',
                                 'parent-35-close', 'tunnel-1-kill', 'worker-kill', 'interface-35-release'])
        self.assertEqual(len(workers), 3)

    def test_wrong_index_acceptance_stops_before_parent_release(self):
        error, evidence, order, workers = self.exercise(rejection_failed=True)
        self.assertIsNotNone(error)
        self.assertEqual(order, [])
        self.assertEqual(len(workers), 1)

    def test_wrong_candidate_response_prevents_retirement_and_release(self):
        error, evidence, order, _ = self.exercise(wrong_candidate=True)
        self.assertIn('归属', str(error))
        self.assertNotIn('retire', order)
        self.assertNotIn('interface-36-release', order)

    def test_lost_identity_prevents_worker_release(self):
        error, evidence, order, _ = self.exercise(lost_identity=True)
        self.assertIn('身份', str(error))
        self.assertNotIn('worker-kill', order)
        self.assertNotIn('interface-35-release', order)

    def test_early_worker_exit_is_not_lifetime_evidence(self):
        error, evidence, order, _ = self.exercise(exited_worker=True)
        self.assertIn('身份', str(error))
        self.assertNotIn('retire', order)

    def test_unexpected_worker_exit_code_prevents_release(self):
        error, evidence, order, _ = self.exercise(failed_kill=True)
        self.assertIn('强制退出', str(error))
        self.assertNotIn('interface-35-release', order)

    def test_remaining_interface_is_not_cleaned_as_success(self):
        node = SimpleNamespace(interface='utun42', close=Mock())
        with patch('macos_handoff.interfaces', return_value={'utun42': []}), \
             patch('macos_handoff.time.monotonic', side_effect=[0, 4]), \
             patch('macos_handoff.reconcile_removed_route') as reconcile:
            with self.assertRaisesRegex(RuntimeError, '仍存在'):
                require_removed(node)
        node.close.assert_not_called()
        reconcile.assert_not_called()


if __name__ == '__main__':
    unittest.main()
