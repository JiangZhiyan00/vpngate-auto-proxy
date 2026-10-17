"""容器日志验收判定规则，避免无事件或错误频率被当作通过。"""
import unittest
from docker_logging import validate_level, validate_frequency


class LoggingEvidenceTests(unittest.TestCase):
    def test_exact_level_matrix_and_no_debug_noise(self):
        rows = [{'level': level, 'event_type': 'test'} for level in ('error', 'warn', 'info', 'debug')]
        for index, selected in enumerate(('error', 'warn', 'info', 'debug')):
            validate_level(rows[:index + 1], selected)
            if index < 3:
                with self.assertRaises(RuntimeError):
                    validate_level(rows, selected)
        with self.assertRaises(RuntimeError):
            validate_level([{'level': 'info', 'event_type': 'runtime_summary'}], 'info')

    def test_frequency_requires_positive_evidence(self):
        with self.assertRaises(RuntimeError):
            validate_frequency([], 60)
        rows = [{'event_type': 'runtime_summary', 'timestamp': value} for value in
                ('2026-10-16T09:00:00+08:00', '2026-10-16T09:01:00+08:00')]
        self.assertEqual(validate_frequency(rows, 60), 2)
        with self.assertRaises(RuntimeError):
            validate_frequency(rows, 300)


if __name__ == '__main__':
    unittest.main()
