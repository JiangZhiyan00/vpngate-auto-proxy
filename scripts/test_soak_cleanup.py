"""接口清理竞争与失败证据回归；不创建实际网络资源。"""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import validate_soak


def result(links=None, code=0, stderr=""):
    return SimpleNamespace(stdout=json.dumps(links or []), returncode=code, stderr=stderr)


class LinkCleanupTests(unittest.TestCase):
    def setUp(self):
        self.link={"ifname":"owned","ifindex":7,"ifalias":"token"}

    def test_absent_link_needs_no_delete(self):
        with mock.patch.object(validate_soak,"run",return_value=result()) as run:
            validate_soak.delete_owned_link("owned","token")
            self.assertEqual(run.call_count,1)

    def test_disappearing_link_after_failed_delete_is_verified_absent(self):
        with mock.patch.object(validate_soak,"run",side_effect=[result([self.link]),result(code=1,stderr="设备不存在"),result()]) as run:
            validate_soak.delete_owned_link("owned","token")
            self.assertEqual(run.call_count,3)

    def test_persisting_link_keeps_delete_failure_and_diagnostic(self):
        with mock.patch.object(validate_soak,"run",side_effect=[result([self.link]),result(code=1,stderr="受控删除失败"),result([self.link])]):
            with self.assertRaisesRegex(RuntimeError,"受控删除失败"):
                validate_soak.delete_owned_link("owned","token")

    def test_foreign_alias_is_never_deleted(self):
        with mock.patch.object(validate_soak,"run",return_value=result([{**self.link,"ifalias":"other"}])) as run:
            with self.assertRaises(RuntimeError): validate_soak.delete_owned_link("owned","token")
            self.assertEqual(run.call_count,1)

    def test_replacement_after_delete_is_not_removed_or_reported_clean(self):
        with mock.patch.object(validate_soak,"run",side_effect=[result([self.link]),result(),result([{**self.link,"ifindex":8,"ifalias":"other"}])]) as run:
            with self.assertRaises(RuntimeError): validate_soak.delete_owned_link("owned","token")
            self.assertEqual(run.call_count,3)

    def test_inventory_error_is_not_misreported_as_absence(self):
        with mock.patch.object(validate_soak,"run",side_effect=RuntimeError("查询失败")):
            with self.assertRaisesRegex(RuntimeError,"查询失败"): validate_soak.delete_owned_link("owned","token")

    def test_cleanup_failure_retains_observations_without_success_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"report.json"
            environment=SimpleNamespace(token="test",prepare=mock.Mock(),close=mock.Mock(side_effect=RuntimeError("受控清理失败")))
            with mock.patch.object(sys,"argv",["validate", "--deployment","native","--duration-seconds","15","--output",str(output)]), \
                 mock.patch.object(validate_soak,"Environment",return_value=environment), \
                 mock.patch.object(validate_soak,"trial",return_value={"status":"passed","full_duration_passed":True,"actual_elapsed_seconds":1800,"round_trips":50}):
                with self.assertRaisesRegex(RuntimeError,"受控清理失败"): validate_soak.main()
            report=json.loads(output.read_text())
            self.assertEqual(report["status"],"failed"); self.assertFalse(report["full_duration_passed"])
            self.assertEqual(report["trial_observations"]["round_trips"],50)
            self.assertNotIn("status",report["trial_observations"]);self.assertNotIn("full_duration_passed",report["trial_observations"])
            self.assertEqual(report["failure_reason"],"受控清理失败")


if __name__ == "__main__": unittest.main()
