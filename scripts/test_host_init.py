"""宿主准备隔离测试：从不访问真实策略或执行宿主命令。"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load_installer():
    spec = importlib.util.spec_from_file_location("host_init", Path(__file__).with_name("host-init.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostFixture:
    """所有命令和内核状态均由测试替身控制。"""
    def __init__(self, directory):
        self.root = Path(directory)
        self.calls = []
        self.mode = None
        self.loaded_policy = None
        self.active = False
        self.fail = None
        self.boot_id = "test-boot"
        self.uid = os.getuid()

    def preflight(self):
        self.calls.append("preflight")

    def kernel_mode(self):
        return self.mode

    def consumers(self):
        self.calls.append("consumers")
        if self.active:
            raise self.module.Rejected("策略仍有消费者")

    def parse(self, policy):
        self.calls.append("parse")
        if self.fail == "parse":
            raise self.module.Rejected("策略解析失败")

    def load(self, policy):
        self.calls.append("load")
        if self.fail == "load":
            raise self.module.Rejected("策略加载失败")
        self.mode = "enforce"
        self.loaded_policy = policy

    def unload(self, policy):
        self.calls.append("unload")
        self.mode = None
        self.loaded_policy = None


class HostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_installer()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = HostFixture(self.temp.name)
        self.host.module = self.module
        self.policy = b"profile vpngate-auto-proxy {}\n"
        self.release = self.module.Release("v1.2.3", "a" * 40, self.policy, "b" * 64)
        self.setup = self.module.HostSetup(self.release, self.host, root=self.host.root,
                                           owner=self.host.uid)
        for relative in ("etc/apparmor.d", "var/lib", "run/lock"):
            (self.host.root / relative).mkdir(parents=True, exist_ok=True)

    def test_clean_check_is_read_only_and_fails(self):
        before = sorted(str(p) for p in self.host.root.rglob("*"))
        with self.assertRaises(self.module.Rejected):
            self.setup.run("check")
        self.assertEqual(before, sorted(str(p) for p in self.host.root.rglob("*")))
        self.assertNotIn("load", self.host.calls)

    def test_initial_three_repeats_and_check_do_not_reload(self):
        result = self.setup.run()
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["changed"])
        for action in ("init", "init", "init", "check"):
            result = self.setup.run(action)
            self.assertFalse(result["changed"])
        self.assertEqual(self.host.calls.count("load"), 1)
        self.assertNotIn("reboot_validated", result)

    def test_adopt_requires_explicit_and_official_bytes(self):
        target = self.host.root / "etc/apparmor.d/vpngate-auto-proxy"
        target.write_bytes(self.policy)
        target.chmod(0o644)
        with self.assertRaises(self.module.Rejected):
            self.setup.run()
        self.assertEqual(self.setup.run("adopt")["status"], "ready")

    def test_adopt_reloads_existing_official_file_to_prove_kernel_material(self):
        target = self.host.root / 'etc/apparmor.d/vpngate-auto-proxy'
        target.write_bytes(self.policy)
        target.chmod(0o644)
        self.host.mode = 'enforce'
        self.assertEqual(self.setup.run('adopt')['status'], 'ready')
        self.assertEqual(self.host.calls.count('load'), 1)

    def test_adopt_failure_never_claims_unknown_old_kernel_was_restored(self):
        target = self.host.root / 'etc/apparmor.d/vpngate-auto-proxy'
        target.write_bytes(self.policy)
        target.chmod(0o644)
        self.host.mode, self.host.fail = 'enforce', 'load'
        with self.assertRaises(self.module.RecoveryRequired):
            self.setup.run('adopt')
        self.assertEqual(target.read_bytes(), self.policy)
        self.assertNotIn('unload', self.host.calls)

    def test_unknown_bytes_kernel_only_and_active_consumer_refused(self):
        target = self.host.root / "etc/apparmor.d/vpngate-auto-proxy"
        target.write_bytes(b"unknown")
        target.chmod(0o644)
        with self.assertRaises(self.module.Rejected):
            self.setup.run("adopt")
        self.assertEqual(target.read_bytes(), b"unknown")
        target.unlink()
        self.host.mode = "enforce"
        with self.assertRaises(self.module.Rejected):
            self.setup.run()
        self.host.mode = None
        self.host.active = True
        with self.assertRaises(self.module.Rejected):
            self.setup.run()
        self.assertFalse(target.exists())

    def test_symlink_hardlink_and_parent_permissions_refused(self):
        target = self.host.root / "etc/apparmor.d/vpngate-auto-proxy"
        other = self.host.root / "other"
        other.write_bytes(self.policy)
        other.chmod(0o644)
        target.symlink_to(other)
        with self.assertRaises(self.module.Rejected):
            self.setup.run("adopt")
        target.unlink()
        os.link(other, target)
        with self.assertRaises(self.module.Rejected):
            self.setup.run("adopt")
        target.unlink()
        target.parent.chmod(0o777)
        with self.assertRaises(self.module.Rejected):
            self.setup.run()

    def test_load_failure_rolls_back_and_retry_can_succeed(self):
        self.host.fail = "load"
        with self.assertRaises(self.module.Rejected):
            self.setup.run()
        self.assertFalse((self.host.root / "etc/apparmor.d/vpngate-auto-proxy").exists())
        self.host.fail = None
        self.assertEqual(self.setup.run()["status"], "ready")

    def test_parse_failure_has_no_policy_side_effect(self):
        self.host.fail = "parse"
        with self.assertRaises(self.module.Rejected):
            self.setup.run()
        self.assertNotIn("load", self.host.calls)

    def test_update_binds_previous_version_and_protects_drift(self):
        self.setup.run()
        new = self.module.Release("v1.2.4", "c" * 40, self.policy, "d" * 64)
        updated = self.module.HostSetup(new, self.host, root=self.host.root, owner=self.host.uid)
        with self.assertRaises(self.module.Rejected):
            updated.run()
        with self.assertRaises(self.module.Rejected):
            updated.run("update", "v0.0.1")
        self.assertEqual(updated.run("update", "v1.2.3")["status"], "ready")
        self.assertEqual(self.host.calls.count("load"), 1)
        target = self.host.root / "etc/apparmor.d/vpngate-auto-proxy"
        target.write_bytes(b"local modification")
        with self.assertRaises(self.module.Rejected):
            updated.run()


    def test_changed_policy_failure_restores_original_kernel_file_and_record(self):
        self.setup.run()
        new_policy = self.policy + b'# new policy bytes\n'
        release = self.module.Release('v1.2.4', 'c' * 40, new_policy, 'd' * 64)
        updated = self.module.HostSetup(release, self.host, root=self.host.root, owner=self.host.uid)
        advance = updated.advance
        def fail(transaction, stage):
            advance(transaction, stage)
            if stage == 'kernel_verified':
                raise self.module.Rejected('受控更新提交失败')
        with patch.object(updated, 'advance', side_effect=fail):
            with self.assertRaises(self.module.Rejected):
                updated.run('update', 'v1.2.3')
        self.assertEqual(self.host.loaded_policy, self.policy)
        self.assertEqual((self.host.root / 'etc/apparmor.d/vpngate-auto-proxy').read_bytes(), self.policy)
        self.assertEqual(self.setup.run()['status'], 'ready')
        self.assertEqual(updated.run('update', 'v1.2.3')['status'], 'ready')
        self.assertEqual(self.host.loaded_policy, new_policy)

    def test_recovery_can_resume_after_restoring_the_policy_node(self):
        self.setup.run()
        release = self.module.Release('v1.2.4', 'c' * 40, self.policy + b'# changed\n', 'd' * 64)
        updated = self.module.HostSetup(release, self.host, root=self.host.root, owner=self.host.uid)
        advance, save = updated.advance, updated.save_transaction
        class Interrupted(BaseException):
            pass
        def fail(transaction, stage):
            advance(transaction, stage)
            if stage == 'kernel_verified':
                raise self.module.Rejected('受控更新失败')
        def interrupt(transaction):
            save(transaction)
            if transaction['restored_policy_identity'] is not None and transaction['restored_record'] is None:
                raise Interrupted()
        with patch.object(updated, 'advance', side_effect=fail), patch.object(updated, 'save_transaction', side_effect=interrupt):
            with self.assertRaises(Interrupted):
                updated.run('update', 'v1.2.3')
        self.assertEqual(self.setup.run()['status'], 'ready')
        self.assertEqual(self.host.loaded_policy, self.policy)

    def test_corrupt_record_refused(self):
        self.setup.run()
        record = self.host.root / "var/lib/vap-host/record.json"
        record.write_text('{"schema_version":1}')
        with self.assertRaises(self.module.Rejected):
            self.setup.run()

    def test_unknown_pending_transaction_fails_closed(self):
        self.setup.run()
        transaction = self.host.root / "var/lib/vap-host/transaction.json"
        transaction.write_text('{"stage":"file_committed"}')
        transaction.chmod(0o600)
        with self.assertRaises(self.module.RecoveryRequired):
            self.setup.run()

    def test_versions_and_arguments_are_strict(self):
        for tag in ("latest", "v01.2.3", "v1.2.3;id", "v1.2.3\n"):
            with self.assertRaises(self.module.Rejected):
                self.module.Release(tag, "a" * 40, self.policy, "b" * 64)
        for args in (["--check", "--adopt"], ["--update-from", "latest"]):
            with self.assertRaises(SystemExit) as error:
                self.module.arguments(args)
            self.assertEqual(error.exception.code, 2)

    def test_project_lock_rejects_concurrent_writer(self):
        with self.setup.files.lock():
            with self.assertRaises(self.module.Rejected):
                self.setup.run()
        self.assertNotIn("load", self.host.calls)

    def test_each_commit_stage_failure_restores_known_state(self):
        for stage in ("file_committed", "kernel_verified", "record_committed", "complete"):
            with self.subTest(stage=stage):
                self.host.mode = None
                for target in ("etc/apparmor.d/vpngate-auto-proxy", "var/lib/vap-host/record.json",
                               "var/lib/vap-host/transaction.json"):
                    (self.host.root / target).unlink(missing_ok=True)
                advance = self.setup.advance
                def fail(transaction, reached):
                    advance(transaction, reached)
                    if reached == stage:
                        raise self.module.Rejected("受控事务阶段失败")
                with patch.object(self.setup, "advance", side_effect=fail):
                    with self.assertRaises(self.module.Rejected):
                        self.setup.run()
                self.assertIsNone(self.host.mode)
                self.assertFalse((self.host.root / "etc/apparmor.d/vpngate-auto-proxy").exists())
                self.assertFalse((self.host.root / "var/lib/vap-host/record.json").exists())

    def test_interrupted_transaction_is_recovered_before_next_write(self):
        class Interrupted(BaseException):
            pass
        advance = self.setup.advance
        def interrupt(transaction, stage):
            advance(transaction, stage)
            if stage == "kernel_verified":
                raise Interrupted()
        with patch.object(self.setup, "advance", side_effect=interrupt):
            with self.assertRaises(Interrupted):
                self.setup.run()
        self.assertEqual(self.host.mode, "enforce")
        self.assertEqual(self.setup.run()["status"], "ready")
        self.assertEqual(self.host.calls.count("unload"), 1)

    def test_recovery_refuses_changed_material_or_consumers(self):
        class Interrupted(BaseException):
            pass
        advance = self.setup.advance
        def interrupt(transaction, stage):
            advance(transaction, stage)
            if stage == "kernel_verified":
                raise Interrupted()
        with patch.object(self.setup, "advance", side_effect=interrupt):
            with self.assertRaises(Interrupted):
                self.setup.run()
        self.host.active = True
        with self.assertRaises(self.module.RecoveryRequired):
            self.setup.run()
        self.assertEqual(self.host.mode, "enforce")
        self.assertNotIn("unload", self.host.calls)

    def test_recovery_never_overwrites_same_bytes_with_an_unknown_inode(self):
        class Interrupted(BaseException):
            pass
        advance = self.setup.advance
        def interrupt(transaction, stage):
            advance(transaction, stage)
            if stage == 'kernel_verified':
                raise Interrupted()
        with patch.object(self.setup, 'advance', side_effect=interrupt):
            with self.assertRaises(Interrupted):
                self.setup.run()
        target = self.host.root / 'etc/apparmor.d/vpngate-auto-proxy'
        foreign = target.with_name('foreign')
        foreign.write_bytes(target.read_bytes())
        foreign.chmod(0o644)
        foreign.replace(target)
        inode = target.stat().st_ino
        with self.assertRaises(self.module.RecoveryRequired):
            self.setup.run()
        self.assertEqual(inode, target.stat().st_ino)
        self.assertNotIn('unload', self.host.calls)

    def test_check_does_not_touch_complete_files(self):
        self.setup.run()
        before = {str(p): (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes())
                  for p in self.host.root.rglob("*") if p.is_file()}
        self.setup.run("check")
        after = {str(p): (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes())
                 for p in self.host.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_preflight_failure_occurs_before_files_or_commands(self):
        for reason in ("无权限", "未支持宿主", "远端引擎", "无根引擎", "缺少工具", "设备缺失", "启动链缺失"):
            with self.subTest(reason=reason), patch.object(self.host, 'preflight', side_effect=self.module.Rejected(reason)):
                with self.assertRaises(self.module.Rejected):
                    self.setup.run()
                self.assertFalse((self.host.root / 'run/lock/vap-host-init.lock').exists())
                self.assertNotIn('load', self.host.calls)

    def test_native_preflight_rejects_wrong_platform_and_uid_before_tools(self):
        native = self.module.NativeHost()
        with patch.object(self.module.sys, 'platform', 'darwin'), patch.object(native, 'tool') as tool:
            with self.assertRaises(self.module.Rejected):
                native.preflight()
            tool.assert_not_called()
        with patch.object(self.module.sys, 'platform', 'linux'), \
                patch.object(self.module.sys, 'version_info', (3, 10)), \
                patch.object(self.module.platform, 'machine', return_value='x86_64'), \
                patch.object(self.module.os, 'getuid', return_value=1000), patch.object(native, 'tool') as tool:
            with self.assertRaises(self.module.Rejected):
                native.preflight()
            tool.assert_not_called()


if __name__ == "__main__":
    unittest.main()
