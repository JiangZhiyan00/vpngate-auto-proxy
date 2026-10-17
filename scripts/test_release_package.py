"""公开来源打包范围排除本地秘密、日志及缓存。"""
import importlib.util
import ast
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release_package', Path(__file__).with_name('package-docker-release.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ReleasePackageTests(unittest.TestCase):
    def test_host_materials_bind_actual_image_policy_version_and_commit(self):
        from package_host_init import package as host_package
        with tempfile.TemporaryDirectory() as directory:
            materials = Path(directory) / 'host'
            manifest = host_package('v1.2.3', 'a' * 40, 'sha256:' + 'b' * 64, materials)
            labels = {'io.vpngate-auto-proxy.apparmor-sha256': manifest['policy_sha256'],
                      'org.opencontainers.image.version': 'v1.2.3', 'org.opencontainers.image.revision': 'a' * 40}
            image = {'Id': manifest['image_id'], 'Config': {'Labels': labels}}
            self.assertEqual(len(package.host_materials(materials, image)), 3)
            for key in list(labels):
                original = labels[key]
                labels[key] = 'mismatch'
                with self.assertRaises(ValueError):
                    package.host_materials(materials, image)
                labels[key] = original
            installer = materials / manifest['installer_filename']
            installer.write_text(installer.read_text() + '# changed\n')
            with self.assertRaises(ValueError):
                package.host_materials(materials, image)

    def test_cloud_package_contains_local_runtime_imports(self):
        source = Path(__file__).with_name('package-cloud-validation.py')
        description = importlib.util.spec_from_file_location('cloud_package', source)
        cloud = importlib.util.module_from_spec(description)
        description.loader.exec_module(cloud)
        for relative in cloud.FILES:
            if not relative.endswith('.py'):
                continue
            for node in ast.walk(ast.parse((cloud.ROOT / relative).read_text())):
                if isinstance(node, ast.ImportFrom) and node.module:
                    dependency = 'scripts/' + node.module + '.py'
                    if (cloud.ROOT / dependency).is_file():
                        self.assertIn(dependency, cloud.FILES, relative)

    def test_project_source_whitelist_excludes_local_secrets_and_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in package.SOURCE_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original source')
            (root / 'scripts').mkdir()
            for name in ['tool.py', 'install-vap.py', 'credentials.local.json', 'config.local.json',
                         'custom.local.json', 'custom.local.yaml', '.env', 'private.log', 'private.log.1', 'cache.pyc']:
                (root / 'scripts' / name).write_text('local value')
            (root / 'credentials.local.json').write_text('root secret')
            with patch.object(package, 'ROOT', root):
                files = {path.relative_to(root).as_posix() for path in package.project_files()}
            self.assertIn('scripts/tool.py', files)
            self.assertIn('scripts/install-vap.py', files)
            self.assertIn('specs/002-rename-cli-vap/contracts/deployment.md', files)
            self.assertIn('specs/002-rename-cli-vap/contracts/cli.md', files)
            self.assertIn('.env.example', files)
            self.assertNotIn('scripts/.env', files)
            self.assertNotIn('scripts/custom.local.json', files)
            self.assertNotIn('scripts/custom.local.yaml', files)
            self.assertNotIn('scripts/private.log.1', files)
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

    def test_program_extraction_uses_new_product_with_no_network(self):
        with patch.object(package.subprocess, 'check_output', return_value=b'program') as command:
            self.assertEqual(package.program_bytes('example/proxy:tag'), b'program')
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[-1], '/usr/local/bin/vap')
        self.assertIn('none', arguments)
        self.assertIn('--read-only', arguments)
        self.assertIn('ALL', arguments)


if __name__ == '__main__':
    unittest.main()
