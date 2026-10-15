"""受控代际实验顺序与失败阻断回归。"""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from macos_generation import exercise_generation
from macos_parallel import cleanup_after_workers


class GenerationLifecycleTests(unittest.TestCase):
    def execute(self, retirement_error=False, reuse_error=False, stale_accepted=False):
        nodes = [SimpleNamespace(index=str(34+i)) for i in range(3)]
        endpoints = [{'identity': v} for v in ('new', 'candidate', 'old')]
        old = Mock(generation='old-generation')
        old.process.poll.return_value = 0
        new = Mock(generation='new-generation')
        new.process.poll.return_value = 0
        old.probe.return_value = {'identity': 'old'}
        new.probe.return_value = {'identity': 'new'}
        old.retire.return_value = {'event': 'retired'}
        if retirement_error:
            old.retire.side_effect = RuntimeError('旧进程退出未确认')
        new.request.return_value = {'event': 'verified' if stale_accepted else 'rejected',
                                    'reason': 'stale_generation', 'generation': new.generation}
        workers, evidence = [], {}
        def reuse(*args):
            old.retire.assert_called_once()
            self.assertEqual(old.process.poll(), 0)
            if reuse_error:
                raise RuntimeError('未复用目标索引')
            args[-1]['checks'] = {'cached_numeric_index_reaches_replacement': True}
            nodes.append(SimpleNamespace(index='36'))
        error = None
        with patch('macos_generation.GenerationWorker', side_effect=[old, new]), patch('macos_generation.exercise_reuse', side_effect=reuse) as reused:
            try:
                exercise_generation(SimpleNamespace(), Path('/bundle'), nodes, Mock(), Path('/runtime'),
                                    endpoints, 501, 20, evidence, workers)
            except RuntimeError as caught:
                error = caught
        return workers, evidence, error, old, new, reused

    def test_worker_exit_precedes_reuse_and_old_id_is_rejected(self):
        workers, evidence, error, old, new, reused = self.execute()
        self.assertIsNone(error)
        self.assertEqual(workers, [old, new])
        self.assertTrue(all(evidence['checks'].values()))
        new.request.assert_called_once_with('probe', old.generation)
        new.probe.assert_called_once()
        new.retire.assert_called_once()

    def test_exit_failure_prevents_interface_release(self):
        workers, evidence, error, old, new, reused = self.execute(retirement_error=True)
        self.assertIn('退出未确认', str(error))
        reused.assert_not_called()
        self.assertEqual(workers, [old])
        new.probe.assert_not_called()

    def test_missing_actual_reuse_prevents_replacement_worker(self):
        workers, evidence, error, old, new, reused = self.execute(reuse_error=True)
        self.assertIn('未复用', str(error))
        self.assertEqual(workers, [old])
        new.ready.assert_not_called()

    def test_stale_id_accepted_is_failure_and_worker_remains_registered(self):
        workers, evidence, error, old, new, reused = self.execute(stale_accepted=True)
        self.assertIn('未拒绝旧代际', str(error))
        self.assertEqual(workers, [old, new])
        self.assertFalse(evidence['checks']['old_generation_rejected'])
        new.probe.assert_not_called()


class CleanupTests(unittest.TestCase):
    def test_unreaped_worker_prevents_all_interface_cleanup(self):
        worker, node = Mock(), Mock()
        worker.process.poll.return_value = None
        worker.close.side_effect = RuntimeError('进程无法回收')
        errors = []
        self.assertFalse(cleanup_after_workers([node], [worker], True, errors))
        node.close.assert_not_called()
        self.assertTrue(errors)

    def test_unreaped_activity_prevents_all_interface_cleanup(self):
        node = Mock()
        errors = []
        cleanup_after_workers([node], [], False, errors)
        node.close.assert_not_called()
        self.assertTrue(errors)

    def test_worker_cleanup_precedes_reverse_interface_cleanup(self):
        order, errors = [], []
        workers = [Mock(), Mock()]
        nodes = [Mock(), Mock()]
        for i, worker in enumerate(workers):
            worker.process.poll.return_value = 0
            worker.close.side_effect = lambda i=i: order.append(('worker', i))
        for i, node in enumerate(nodes):
            node.close.side_effect = lambda i=i: order.append(('interface', i))
        self.assertTrue(cleanup_after_workers(nodes, workers, True, errors))
        self.assertEqual(order, [('worker', 1), ('worker', 0), ('interface', 1), ('interface', 0)])
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
