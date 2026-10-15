"""异常退出实验的归属、阶段门槛及失败回收责任。"""
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from macos_abrupt import classify_response, exercise_abrupt, reconcile_removed_route


def observation(tcp=None, udp=None):
    return dict(interface_index=36, identity='old', retained_tcp_write_succeeded=True,
                retained_udp_send_succeeded=True, retained_tcp_response=tcp is not None,
                retained_udp_response=udp is not None, retained_tcp_response_sha256=tcp,
                retained_udp_response_sha256=udp)


class EvidenceTests(unittest.TestCase):
    def test_no_response_is_observation(self):
        self.assertEqual(classify_response(observation(), 36, 'old', 'new', 'p'), {'tcp': 'none', 'udp': 'none'})

    def test_replacement_response_is_detected_without_suppressing_risk(self):
        digest = hashlib.sha256(b'new:p-after-removal').hexdigest()
        self.assertEqual(classify_response(observation(udp=digest), 36, 'old', 'new', 'p')['udp'], 'replacement')

    def test_original_and_unexpected_response(self):
        digest = hashlib.sha256(b'old:p-after-removal').hexdigest()
        value = classify_response(observation('a'*64, digest), 36, 'old', 'new', 'p')
        self.assertEqual(value, {'tcp': 'other', 'udp': 'original'})

    def test_malformed_or_misattributed_observation_fails(self):
        for change in ({'identity':'new'}, {'interface_index':34}, {'retained_tcp_response':1},
                       {'retained_udp_response':True}, {'retained_tcp_response_sha256':'a'*64},
                       {'retained_udp_send_succeeded':1}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                classify_response({**observation(), **change}, 36, 'old', 'new', 'p')


class RouteTests(unittest.TestCase):
    def test_only_absent_owned_route_clears_cleanup_flag(self):
        node = SimpleNamespace(process=Mock(), interface='utun8', route_added=True)
        node.process.poll.return_value = -9
        for table, expected in (('10.231.66.1 link#36 UHIS utun8\n', True),
                                ('10.231.66.1 link#35 UHIS utun7\n', False)):
            node.route_added = True
            with patch('macos_abrupt.interfaces', return_value={}), patch('macos_abrupt.run', return_value=SimpleNamespace(stdout=table)):
                reconcile_removed_route(node)
            self.assertEqual(node.route_added, expected)

    def test_unreaped_process_or_existing_interface_refuses_reconciliation(self):
        for code, names in ((None, {}), (-9, {'utun8': []})):
            node = SimpleNamespace(process=Mock(), interface='utun8', route_added=True)
            node.process.poll.return_value = code
            with patch('macos_abrupt.interfaces', return_value=names), patch('macos_abrupt.run') as run:
                with self.assertRaises(RuntimeError):
                    reconcile_removed_route(node)
                self.assertTrue(node.route_added)
                run.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def execute(self, bad_positive=False, reuse_error=False, early_probe=False):
        nodes = [SimpleNamespace(index=str(34+i), interface=f'utun{6+i}', process=Mock()) for i in range(3)]
        nodes[2].process.poll.return_value = None
        nodes[2].process.wait.return_value = -9
        worker = Mock()
        worker.process.poll.return_value = None
        worker.process.wait.return_value = 0
        workers, evidence = [], {}
        positive = dict(interface_index=36, identity='old', tcp=True, udp=not bad_positive)
        def reuse(*args):
            self.assertEqual(workers, [worker])
            nodes[2].process.kill.assert_called_once()
            worker.process.stdin.write.assert_not_called()
            if reuse_error:
                raise RuntimeError('未复用目标索引')
            args[-1]['checks'] = {'cached_numeric_index_reaches_replacement': True}
            if early_probe:
                worker.process.poll.return_value = 0
        error = None
        with patch('macos_abrupt.RetainedProbe', return_value=worker), patch('macos_abrupt.read_record', side_effect=[positive, observation()]), patch('macos_abrupt.interfaces', return_value={}), patch('macos_abrupt.reconcile_removed_route'), patch('macos_abrupt.exercise_reuse', side_effect=reuse):
            try:
                exercise_abrupt(SimpleNamespace(), Path('/bundle'), nodes, Mock(), Path('/runtime'),
                                [{'identity':v} for v in ('new','candidate','old')], 501,20,evidence,workers)
            except RuntimeError as caught:
                error = caught
        return error, evidence, worker, nodes, workers

    def test_probe_registered_and_alive_across_kill_and_reuse(self):
        error, evidence, worker, nodes, workers = self.execute()
        self.assertIsNone(error)
        self.assertTrue(all(evidence['checks'].values()))
        worker.process.stdin.write.assert_called_once_with('c')
        self.assertEqual(evidence['response_classification'], {'tcp':'none', 'udp':'none'})

    def test_bad_positive_prevents_kill(self):
        error, evidence, worker, nodes, workers = self.execute(bad_positive=True)
        self.assertIn('正向对照失败', str(error))
        nodes[2].process.kill.assert_not_called()
        self.assertEqual(workers, [worker])

    def test_missing_reuse_prevents_challenge_and_keeps_worker_registered(self):
        error, evidence, worker, nodes, workers = self.execute(reuse_error=True)
        self.assertIn('未复用', str(error))
        worker.process.stdin.write.assert_not_called()
        self.assertEqual(workers, [worker])

    def test_probe_exit_during_rebuild_prevents_observation(self):
        error, evidence, worker, nodes, workers = self.execute(early_probe=True)
        self.assertIn('探针已退出', str(error))
        worker.process.stdin.write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
