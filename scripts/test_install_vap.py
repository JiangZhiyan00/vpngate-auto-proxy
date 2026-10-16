"""生产安装测试：真实成功仅在独立 Linux 管理员环境执行。"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("install-vap.py")
spec = importlib.util.spec_from_file_location("install_vap", SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Components(unittest.TestCase):
    def test_privilege_and_platform_gate(self):
        for platform, uid, euid in [("darwin", 0, 0), ("linux", 1000, 0), ("linux", 0, 1000)]:
            with patch.object(installer.sys, "platform", platform), patch.object(installer.os, "getuid", return_value=uid), patch.object(installer.os, "geteuid", return_value=euid):
                with self.assertRaises(installer.Rejected):
                    installer.require_root()

    def test_absolute_path_and_digest(self):
        for value in ["relative", "/a/../b", "/a/./b", "/a//b", ""]:
            with self.assertRaises(installer.Rejected):
                installer.absolute(value)
        for value in ["A" * 64, "g" * 64, "a" * 63, ""]:
            with self.assertRaises(installer.Rejected):
                installer.digest_format(value)

    def test_nonpublic_retirement_paths_reject_before_reading_evidence(self):
        for entry in [
            "/opt/application/bin/backups/vpngate-auto-proxy",
            "/opt/application/bin/data/vpngate-auto-proxy",
            "/opt/application/bin/history/old/bin/vpngate-auto-proxy",
            "/opt/application/backups/bin/vpngate-auto-proxy",
            "/opt/backups/bin/vpngate-auto-proxy",
            "/opt/data/bin/vpngate-auto-proxy",
            "/opt/versions/bin/vpngate-auto-proxy",
        ]:
            with self.subTest(entry=entry), patch.object(installer, "require_root"), \
                    patch.object(installer, "load_evidence", side_effect=installer.Rejected("不应读取证据")) as load:
                with self.assertRaises(installer.Rejected):
                    installer.retire(entry, "/record", "/artifact", "/stopped")
                load.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and os.getuid() == os.geteuid() == 0,
                     "真实生产安装仅在独立 Linux 管理员环境执行")
class Production(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="vap-install-test-", dir="/opt"))
        self.root.chmod(0o755)
        self.addCleanup(shutil.rmtree, self.root)
        self.target = self.root / "bin"
        self.target.mkdir(mode=0o755)
        self.source = self.root / "source"
        self.source.write_bytes("受控程序快照\n".encode())
        self.source.chmod(0o644)
        self.sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.environment = {"PATH": str(self.target)}

    def install(self):
        with patch.dict(os.environ, self.environment, clear=True):
            return installer.install(str(self.source), self.sha, str(self.target))

    def test_install_snapshot_permissions_no_attributes_and_repeat(self):
        try:
            os.setxattr(self.source, "user.test", "不可继承".encode())
        except OSError:
            pass
        self.install()
        final = self.target / "vap"
        self.assertEqual(final.read_bytes(), self.source.read_bytes())
        info = final.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (0, 0, 0o755, 1))
        self.assertEqual(os.listxattr(final), [])
        with self.assertRaises(installer.Rejected):
            self.install()
        self.assertEqual(list(self.target.iterdir()), [final])

    def test_conflicting_nodes_are_preserved(self):
        final = self.target / "vap"
        for kind in ["file", "directory", "dangling", "link"]:
            with self.subTest(kind=kind):
                if kind == "file": final.write_bytes("保留".encode())
                elif kind == "directory": final.mkdir()
                else: final.symlink_to(self.source if kind == "link" else "不存在")
                before = final.lstat()
                with self.assertRaises(installer.Rejected): self.install()
                self.assertEqual(final.lstat().st_ino, before.st_ino)
                if kind == "directory": final.rmdir()
                else: final.unlink()

    def test_path_rejects_unsafe_or_conflicting_directories(self):
        other = self.root / "other"
        other.mkdir(mode=0o755)
        (other / "vap").write_bytes("不执行".encode())
        for path in ["", ":" + str(self.target), "relative", str(other), "/tmp"]:
            self.environment["PATH"] = path
            with self.subTest(path=path), self.assertRaises(installer.Rejected): self.install()
        (other / "vap").unlink()
        link = self.root / "path-link"
        link.symlink_to(other, target_is_directory=True)
        self.environment["PATH"] = str(link)
        self.install()

    def test_source_and_parent_constraints(self):
        for mode in [0o666, 0o4644, 0o2644, 0o1644]:
            self.source.chmod(mode)
            with self.assertRaises(installer.Rejected): self.install()
        self.source.chmod(0o644)
        for uid in [12345]:
            os.chown(self.source, uid, 0)
            with self.assertRaises(installer.Rejected): self.install()
            self.environment["SUDO_UID"] = str(uid)
            self.install()
            (self.target / "vap").unlink()
            del self.environment["SUDO_UID"]
        os.chown(self.source, 0, 0)
        hard = self.root / "hard"
        os.link(self.source, hard)
        with self.assertRaises(installer.Rejected): self.install()

        hard.unlink()
        original = self.source
        self.source = self.root / "source-link"
        self.source.symlink_to(original)
        with self.assertRaises(installer.Rejected): self.install()
        self.source = original
        for mode in [0o777, 0o750, 0o1755]:
            self.target.chmod(mode)
            with self.assertRaises(installer.Rejected): self.install()
        self.target.chmod(0o755)
        os.chown(self.target, 0, 12345)
        with self.assertRaises(installer.Rejected): self.install()
        os.chown(self.target, 0, 0)
        self.root.chmod(0o775)
        with self.assertRaises(installer.Rejected): self.install()
        self.root.chmod(0o755)
        linked = self.root / "linked-bin"
        linked.symlink_to(self.target, target_is_directory=True)
        with patch.dict(os.environ, self.environment, clear=True), self.assertRaises(installer.Rejected):
            installer.install(str(self.source), self.sha, str(linked))
        path_link = self.root / "untrusted-path"
        path_link.symlink_to(self.target, target_is_directory=True)
        os.lchown(path_link, 12345, 0)
        self.environment["PATH"] = str(path_link)
        with self.assertRaises(installer.Rejected): self.install()

    def test_sudo_root_identity_allows_root_source_without_widening_permissions(self):
        self.environment["SUDO_UID"] = "0"
        self.install()
        final = self.target / "vap"
        self.assertEqual(final.read_bytes(), self.source.read_bytes())
        self.assertEqual((final.stat().st_uid, final.stat().st_gid), (0, 0))
        with self.assertRaises(installer.Rejected): self.install()
        final.unlink()
        os.chown(self.source, 12345, 0)
        with self.assertRaises(installer.Rejected): self.install()
        os.chown(self.source, 0, 0)
        self.source.chmod(0o666)
        with self.assertRaises(installer.Rejected): self.install()
        self.source.chmod(0o644)
        self.sha = "0" * 64
        with self.assertRaises(installer.Rejected): self.install()
        self.sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.target.chmod(0o777)
        with self.assertRaises(installer.Rejected): self.install()
        self.target.chmod(0o755)
        for value in ["", "-1", "root", "01", "0\n"]:
            self.environment["SUDO_UID"] = value
            with self.subTest(value=value), self.assertRaises(installer.Rejected): self.install()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_size_hash_and_snapshot_stability(self):
        self.sha = "0" * 64
        with self.assertRaises(installer.Rejected): self.install()
        for size in [0, 64 * 1024 * 1024 + 1]:
            with self.source.open("wb") as stream: stream.truncate(size)
            with self.assertRaises(installer.Rejected): self.install()

    def test_copy_uses_verified_snapshot_and_directory_replacement_rejects(self):
        original = self.source.read_bytes()
        recheck = installer.recheck_directory
        def modify_source(*args, **kwargs):
            self.source.write_bytes(b"replacement")
            recheck(*args, **kwargs)
        with patch.object(installer, "recheck_directory", side_effect=modify_source):
            self.install()
        self.assertEqual((self.target / "vap").read_bytes(), original)
        (self.target / "vap").unlink()
        self.source.write_bytes(original)
        def replace_directory(*args, **kwargs):
            self.target.rename(self.root / "original-bin")
            self.target.mkdir(mode=0o755)
            (self.target / "vap").write_bytes(b"keep")
            recheck(*args, **kwargs)
        with patch.object(installer, "recheck_directory", side_effect=replace_directory):
            with self.assertRaises(installer.Rejected): self.install()
        self.assertEqual((self.target / "vap").read_bytes(), b"keep")
        self.assertEqual(list((self.root / "original-bin").iterdir()), [])

    def test_concurrent_install_has_one_winner(self):
        command = [sys.executable, str(SCRIPT), "install", "--source", str(self.source),
                   "--sha256", self.sha, "--install-dir", str(self.target)]
        processes = [subprocess.Popen(command, env=self.environment, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE) for _ in range(2)]
        results = [p.communicate(timeout=15) for p in processes]
        self.assertEqual(sorted(p.returncode for p in processes), [0, 2], results)
        self.assertEqual([p.name for p in self.target.iterdir()], ["vap"])

    def evidence(self):
        old = self.target / "vpngate-auto-proxy"
        shutil.copyfile(self.source, old)
        old.chmod(0o755)
        artifact = self.root / "release.json"
        artifact.write_text(json.dumps({"project": "vpngate-auto-proxy", "version": "0.1.0",
                                      "binaries": {old.name: self.sha}}))
        record = self.root / "installation.json"
        runtime = self.root / "runtime"
        record.write_text(json.dumps({"schema_version": 1, "project": "vpngate-auto-proxy",
            "version": "0.1.0", "entry_path": str(old), "binary_sha256": self.sha,
            "release": {"path": str(artifact), "source": "受控历史夹具，非生产归属证明",
                        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
            "instances": [{"id": "00000000-0000-0000-0000-000000000001", "runtime_dir": str(runtime)}]}))
        proof = self.root / "stopped.json"
        proof.write_text(json.dumps({"schema_version": 1,
            "installation_sha256": hashlib.sha256(record.read_bytes()).hexdigest(),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "instances": [{"id": "00000000-0000-0000-0000-000000000001", "runtime_dir": str(runtime),
                           "response": {"result": "accepted", "instance_id": "00000000-0000-0000-0000-000000000001"},
                           "exit_code": 0, "resources_reaped": True}]}))
        return old, record, artifact, proof

    def retire(self, evidence):
        old, record, artifact, proof = evidence
        return installer.retire(str(old), str(record), str(artifact), str(proof))

    def test_retirement_preserves_material_and_backups(self):
        evidence = self.evidence()
        backup = self.root / "backup"
        backup.write_bytes("保留备份".encode())
        self.retire(evidence)
        self.assertFalse(evidence[0].exists())
        self.assertTrue(all(p.exists() for p in evidence[1:]))
        self.assertEqual(backup.read_bytes(), "保留备份".encode())

    def test_nonpublic_retirement_preserves_node_and_matching_evidence(self):
        evidence = self.evidence()
        original, record, artifact, proof = evidence
        for relative in ["bin/backups", "bin/data", "bin/history/old/bin", "backups/bin", "data/bin"]:
            with self.subTest(relative=relative):
                parent = self.root / relative
                parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                candidate = parent / "vpngate-auto-proxy"
                shutil.copyfile(original, candidate)
                candidate.chmod(0o755)
                installation = json.loads(record.read_bytes())
                installation["entry_path"] = str(candidate)
                record.write_text(json.dumps(installation))
                stopped = json.loads(proof.read_bytes())
                stopped["installation_sha256"] = hashlib.sha256(record.read_bytes()).hexdigest()
                proof.write_text(json.dumps(stopped))
                selected = (candidate, record, artifact, proof)
                before = {p: (p.stat().st_ino, p.stat().st_mode, p.read_bytes()) for p in selected}
                with self.assertRaises(installer.Rejected):
                    self.retire(selected)
                self.assertEqual({p: (p.stat().st_ino, p.stat().st_mode, p.read_bytes()) for p in selected}, before)
                self.assertTrue(original.exists())

    def test_retirement_rejects_unknown_forged_and_writable_evidence(self):
        evidence = self.evidence()
        old, record, artifact, proof = evidence
        originals = {p: p.read_bytes() for p in evidence}
        for selected in [record, artifact, proof]:
            selected.unlink()
            with self.assertRaises(installer.Rejected): self.retire(evidence)
            selected.write_bytes(originals[selected])
            selected.chmod(0o666)
            with self.assertRaises(installer.Rejected): self.retire(evidence)
            selected.chmod(0o644)
            selected.write_bytes(b"{}")
            with self.assertRaises(installer.Rejected): self.retire(evidence)
            selected.write_bytes(originals[selected])
        runtime = self.root / "runtime"
        runtime.mkdir()
        with self.assertRaises(installer.Rejected): self.retire(evidence)
        runtime.rmdir()
        hard = self.root / "hard"
        os.link(old, hard)
        with self.assertRaises(installer.Rejected): self.retire(evidence)
        hard.unlink()
        old.unlink()
        old.symlink_to(self.source)
        with self.assertRaises(installer.Rejected): self.retire(evidence)
        self.assertTrue(old.is_symlink())

    def test_retirement_rejects_live_or_unknown_consumers(self):
        evidence = self.evidence()
        with evidence[0].open("rb"):
            with self.assertRaises(installer.Rejected): self.retire(evidence)
        with patch.object(installer, "check_consumers", side_effect=installer.Rejected("未知消费者")):
            with self.assertRaises(installer.Rejected): self.retire(evidence)
        self.assertTrue(evidence[0].exists())

    def test_retirement_rejects_wrong_version_and_unconfirmed_stop(self):
        evidence = self.evidence()
        old, record, artifact, proof = evidence
        original = proof.read_bytes()
        for field, value in [("boot_id", "old-boot"), ("installation_sha256", "0" * 64),
                             ("instances", []), ("instances", [{}]), ("instances", [None])]:
            bad = json.loads(original)
            bad[field] = value
            proof.write_text(json.dumps(bad))
            with self.assertRaises(installer.Rejected): self.retire(evidence)
        proof.write_bytes(original)
        changed = json.loads(artifact.read_bytes())
        changed["version"] = "different"
        artifact.write_text(json.dumps(changed))
        installation = json.loads(record.read_bytes())
        installation["release"]["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        record.write_text(json.dumps(installation))
        stopped = json.loads(original)
        stopped["installation_sha256"] = hashlib.sha256(record.read_bytes()).hexdigest()
        proof.write_text(json.dumps(stopped))
        with self.assertRaises(installer.Rejected): self.retire(evidence)
        self.assertTrue(old.exists())

    def test_retirement_rejects_parent_replacement(self):
        evidence = self.evidence()
        original = installer.check_consumers
        def replace(*args):
            original(*args)
            self.target.rename(self.root / "previous-bin")
            self.target.mkdir(mode=0o755)
            (self.target / "vpngate-auto-proxy").write_bytes(b"keep")
        with patch.object(installer, "check_consumers", side_effect=replace):
            with self.assertRaises(installer.Rejected): self.retire(evidence)
        self.assertEqual(evidence[0].read_bytes(), b"keep")
        self.assertTrue((self.root / "previous-bin/vpngate-auto-proxy").exists())

    def test_replacement_and_failed_stage_do_not_delete_other_nodes(self):
        with patch.object(installer.os, "link", side_effect=OSError("受控提交失败")):
            with self.assertRaises(installer.Rejected): self.install()
        self.assertEqual(list(self.target.iterdir()), [])
        evidence = self.evidence()
        original = installer.check_consumers
        def replace(*args):
            original(*args)
            evidence[0].unlink()
            evidence[0].write_bytes("替换节点须保留".encode())
        with patch.object(installer, "check_consumers", side_effect=replace):
            with self.assertRaises(installer.Rejected): self.retire(evidence)
        self.assertEqual(evidence[0].read_bytes(), "替换节点须保留".encode())


if __name__ == "__main__":
    unittest.main()
