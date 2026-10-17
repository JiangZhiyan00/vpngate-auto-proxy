"""版本化宿主部署材料契约。"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import io
import shlex
import stat
from types import SimpleNamespace


class PackageTests(unittest.TestCase):
    def test_standalone_materials_and_no_overwrite(self):
        from package_host_init import package
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "materials"
            manifest = package("v1.2.3", "a" * 40, "sha256:" + "b" * 64, output)
            installer = output / "vap-host-init-v1.2.3.py"
            self.assertEqual(manifest["installer_sha256"], hashlib.sha256(installer.read_bytes()).hexdigest())
            self.assertEqual(json.loads((output / "host-setup.json").read_text()), manifest)
            result = subprocess.run([sys.executable, str(installer), "--help"], cwd=tmp,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("宿主", result.stdout)
            self.assertIn(manifest["installer_sha256"], (output / "host-setup-command.txt").read_text())
            with self.assertRaises((ValueError, FileExistsError)):
                package("v1.2.3", "a" * 40, "sha256:" + "b" * 64, output)

    def test_invalid_identity_rejected_before_output(self):
        from package_host_init import package
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "materials"
            for tag, commit, image in [("latest", "a" * 40, "sha256:" + "b" * 64),
                                      ("v1.0.0", "HEAD", "sha256:" + "b" * 64),
                                      ("v1.0.0", "a" * 40, "latest")]:
                with self.assertRaises(ValueError):
                    package(tag, commit, image, output)
                self.assertFalse(output.exists())

    def test_bad_download_never_executes_installer(self):
        from package_host_init import bootstrap_command
        command = bootstrap_command('v1.2.3', 'vap-host-init-v1.2.3.py', 'a' * 64)
        code = shlex.split(command)[-1]
        temporary_directory = tempfile.TemporaryDirectory
        def private_test_directory(**kwargs):
            self.assertEqual(kwargs.pop('dir'), '/run')
            return temporary_directory(**kwargs)
        with patch('os.getuid', return_value=0), patch('os.geteuid', return_value=0), \
                patch('os.umask'), patch('urllib.request.OpenerDirector.open', return_value=io.BytesIO(b'not trusted')), \
                patch('pathlib.Path.lstat', return_value=SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)), \
                patch('tempfile.TemporaryDirectory', side_effect=private_test_directory), \
                patch('subprocess.call') as execute:
            with self.assertRaises(SystemExit):
                exec(compile(code, '<受控引导>', 'exec'), {})
            execute.assert_not_called()

    def test_manifest_unknown_fields_rejected(self):
        from package_host_init import package, validate_manifest
        with tempfile.TemporaryDirectory() as tmp:
            manifest = package('v1.2.3', 'a' * 40, 'sha256:' + 'b' * 64, Path(tmp) / 'materials')
            manifest['arbitrary_path'] = '/etc/other'
            with self.assertRaises(ValueError):
                validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
