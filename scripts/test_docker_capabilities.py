"""不能把业务成功等同于降权及边界能力已正确清空。"""
import unittest

from validate_docker import validate_child_capabilities


def process(uid, mask):
    name = 'openvpn' if uid == 10002 else 'vpngate-auto-pr'
    return (f'Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n' +
            ''.join(f'{field}:\t{mask:016x}\n' for field in
                    ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) +
            'NoNewPrivs:\t1\n')


class ChildCapabilitiesTests(unittest.TestCase):
    def test_exact_control_and_tunnel_capabilities(self):
        validate_child_capabilities(process(10001, 0) + '\n' + process(10002, 1 << 12))

    def test_retained_bounding_set_missing_evidence_and_new_privileges_rejected(self):
        valid = process(10001, 0) + '\n' + process(10002, 1 << 12)
        for value in (valid.replace('CapBnd:\t0000000000000000', 'CapBnd:\t0000000000000001'),
                      process(10001, 0), valid.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0')):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                validate_child_capabilities(value)


if __name__ == '__main__':
    unittest.main()
