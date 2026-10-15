"""发布文件缺失、摘要改变及路径链接必须在打包前拒绝。"""
import hashlib
from pathlib import Path
import tempfile
import unittest

from release_materials import verified


class ReleaseFilesTests(unittest.TestCase):
    def test_original_content_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source').write_bytes(b'original')
            self.assertEqual(verified(root, 'source', hashlib.sha256(b'original').hexdigest()), root / 'source')

    def test_tampering_missing_traversal_and_links_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source').write_bytes(b'changed')
            (root / 'link').symlink_to(root / 'source')
            (root / 'nested').mkdir()
            (root / 'nested/source').write_bytes(b'original')
            (root / 'linked-directory').symlink_to(root / 'nested', target_is_directory=True)
            for path in ('source', 'missing', '../source', 'link', 'linked-directory/source'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    verified(root, path, hashlib.sha256(b'original').hexdigest())


if __name__ == '__main__':
    unittest.main()
