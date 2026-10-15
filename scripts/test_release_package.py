"""公开来源打包范围排除本地秘密、日志及缓存。"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release_package', Path(__file__).with_name('package-docker-release.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ReleasePackageTests(unittest.TestCase):
    def test_project_source_whitelist_excludes_local_secrets_and_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in package.SOURCE_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original source')
            (root / 'scripts').mkdir()
            for name in ['tool.py', 'credentials.local.json', 'config.local.json', '.env', 'private.log', 'cache.pyc']:
                (root / 'scripts' / name).write_text('local value')
            (root / 'credentials.local.json').write_text('root secret')
            with patch.object(package, 'ROOT', root):
                files = {path.relative_to(root).as_posix() for path in package.project_files()}
            self.assertIn('scripts/tool.py', files)
            self.assertIn('.env.example', files)
            self.assertNotIn('scripts/.env', files)
            self.assertFalse(any('credentials.local.json' in name or name.endswith(('.log', '.pyc'))
                                 or ('.env' in name and name != '.env.example') for name in files))

    def test_source_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in package.SOURCE_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('source')
            (root / 'scripts').mkdir()
            (root / 'scripts/tool.py').symlink_to(root / 'README.md')
            with patch.object(package, 'ROOT', root), self.assertRaises(ValueError):
                package.project_files()


if __name__ == '__main__':
    unittest.main()
