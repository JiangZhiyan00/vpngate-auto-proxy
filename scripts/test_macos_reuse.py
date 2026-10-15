"""接口索引复用判定及已回收对象的资源归属回归。"""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import json
import unittest
from unittest.mock import Mock, patch

from macos_parallel import Tunnel
from macos_reuse import exercise_reuse, verify_observation


class ReuseTests(unittest.TestCase):
    def test_real_reuse_and_changed_identity_required(self):
        verify_observation(34, 34, 'old', 'new', {
            'interface_index': 34, 'identity': 'new', 'tcp': True, 'udp': True,
        })

    def test_different_index_does_not_prove_reuse(self):
        with self.assertRaisesRegex(RuntimeError, '未复用'):
            verify_observation(34, 37, 'old', 'new', {})

    def test_same_identity_does_not_prove_cross_generation(self):
        with self.assertRaisesRegex(RuntimeError, '远端身份必须不同'):
            verify_observation(34, 34, 'same', 'same', {})

    def test_wrong_identity_or_incomplete_response_rejected(self):
        for change in ({'identity': 'old'}, {'interface_index': 35}, {'udp': False}, {'tcp': 1}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                verify_observation(34, 34, 'old', 'new', {
                    **{'interface_index': 34, 'identity': 'new', 'tcp': True, 'udp': True}, **change,
                })

    def test_closed_object_does_not_touch_replacement_with_same_name(self):
        node = Tunnel.__new__(Tunnel)
        node.closed = True
        with patch('macos_parallel.run') as run, patch('macos_parallel.interfaces') as interfaces:
            node.close()
            run.assert_not_called()
            interfaces.assert_not_called()

    def test_failed_cleanup_can_be_retried(self):
        with tempfile.TemporaryDirectory() as folder:
            node = Tunnel.__new__(Tunnel)
            node.closed = False
            node.route_added = True
            node.interface = 'utun6'
            node.process = Mock()
            node.process.poll.return_value = 0
            node.configuration = Path(folder) / 'client.conf'
            node.configuration.write_text('受控配置')
            with patch('macos_parallel.run', return_value=SimpleNamespace(returncode=1)), patch('macos_parallel.interfaces', return_value={}):
                with self.assertRaises(RuntimeError):
                    node.close()
                self.assertFalse(node.closed)
            with patch('macos_parallel.run', return_value=SimpleNamespace(returncode=0)), patch('macos_parallel.interfaces', return_value={}):
                node.close()
                self.assertTrue(node.closed)


class ReuseLifecycleTests(unittest.TestCase):
    def execute(self, replacement_index='36', early_exit=False, ready_error=False):
        nodes = [SimpleNamespace(index=str(34+i), interface=f'utun{6+i}', close=Mock()) for i in range(3)]
        replacement = SimpleNamespace(index=replacement_index, interface='utun6', ready=Mock())
        if ready_error:
            replacement.ready.side_effect = RuntimeError('替代隧道未就绪')
        activity = Mock()
        activity.poll.return_value = 0 if early_exit else None
        activity.wait.side_effect = lambda **kwargs: setattr(activity.poll, 'return_value', -15)
        endpoints = [{'identity': v, 'port': 100+i} for i, v in enumerate(('new', 'candidate', 'old'))]
        options = SimpleNamespace(probe='/probe', dns_probe='/dns')
        evidence = {}
        def response(command, **kwargs):
            self.assertEqual(kwargs['user'], 501)
            self.assertEqual(kwargs['extra_groups'], [])
            if command[0] == '/probe':
                value = dict(interface_index=int(command[1]), identity=command[5], tcp=True, udp=True)
            else:
                value = dict(interface_index=int(command[1]), identity=command[4], dns_udp=True,
                             dns_tcp_fallback=True, resolved_ipv4='10.231.66.1')
            return SimpleNamespace(stdout=json.dumps(value))
        def construct(*args, **kwargs):
            nodes[0].close.assert_called_once()
            nodes[2].close.assert_called_once()
            nodes[1].close.assert_not_called()
            self.assertEqual(args[3], 0)
            self.assertEqual(args[4]['identity'], 'new')
            self.assertEqual(activity.poll(), -15)
            return replacement
        error = None
        with patch('macos_parallel.Tunnel', side_effect=construct), patch('macos_reuse.interfaces', return_value={}), patch('macos_reuse.run', side_effect=response) as run:
            try:
                exercise_reuse(options, Path('/bundle'), nodes, activity, Path('/runtime'), endpoints, 501, 20, evidence)
            except RuntimeError as caught:
                error = caught
        return nodes, evidence, error, run.call_count

    def test_reuse_observation_preserves_candidate_and_checks_dns(self):
        nodes, evidence, error, calls = self.execute()
        self.assertIsNone(error)
        self.assertEqual(len(nodes), 4)
        self.assertEqual(calls, 5)
        self.assertEqual(evidence['old_interface']['index'], 36)
        self.assertEqual(evidence['old_interface']['identity'], 'old')
        self.assertEqual(evidence['replacement_interface']['identity'], 'new')
        self.assertEqual(evidence['cached_numeric_index_observation']['identity'], 'new')
        self.assertTrue(all(evidence['checks'].values()))
        nodes[0].close.assert_called_once()
        nodes[2].close.assert_called_once()
        nodes[1].close.assert_not_called()

    def test_no_reuse_does_not_attempt_cached_index(self):
        nodes, evidence, error, calls = self.execute('34')
        self.assertIn('未复用', str(error))
        self.assertFalse(evidence['checks']['actual_index_reused'])
        self.assertEqual(calls, 0)
        self.assertEqual(len(nodes), 4)

    def test_failed_replacement_is_registered_for_outer_cleanup(self):
        nodes, evidence, error, calls = self.execute(ready_error=True)
        self.assertIn('未就绪', str(error))
        self.assertEqual(len(nodes), 4)
        self.assertEqual(calls, 0)
        self.assertIn('error', evidence)

    def test_activity_exit_prevents_interface_replacement(self):
        nodes, evidence, error, calls = self.execute(early_exit=True)
        self.assertIn('提前退出', str(error))
        self.assertEqual(len(nodes), 3)
        self.assertEqual(calls, 0)
        nodes[0].close.assert_not_called()


if __name__ == '__main__':
    unittest.main()
