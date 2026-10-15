"""来源配方解析及文件摘要拒绝回归，不访问网络。"""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from collect_alpine_sources import checksums, download, upstream_urls


class AlpineSourcesTests(unittest.TestCase):
    def test_source_variable_resolution_never_executes_commands(self):
        recipe = 'pkgver=1.2.3\nbase="https://example.test"\nsource="source.tar.xz::$base/${pkgver%.*}/$pkgver.tar.xz\n$(touch /tmp/forbidden)"'
        self.assertEqual(upstream_urls(recipe), {'source.tar.xz': ['https://example.test/1.2/1.2.3.tar.xz']})

    def test_complete_multiline_checksums(self):
        digest = 'a' * 128
        self.assertEqual(checksums(f'sha512sums="\n{digest}  source.tar.gz\n{digest}  fix.patch\n"'),
                         {'source.tar.gz': digest, 'fix.patch': digest})

    def test_missing_traversal_duplicate_and_unchecked_sources_rejected(self):
        for text in ('source="source.tar.gz"', 'sha512sums="SKIP source.tar.gz"',
                     f'sha512sums="{"a" * 128} ../secret"',
                     f'sha512sums="{"a" * 128} x\n{"b" * 128} x"', 'sha512sums=""'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                checksums(text)

    def test_download_rejects_wrong_digest_and_does_not_replace_existing(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'source'
            path.write_bytes(b'old')
            with patch('urllib.request.urlopen', return_value=io.BytesIO(b'changed')):
                with self.assertRaises(ValueError):
                    download('https://example.test/source', path, hashlib.sha512(b'expected').hexdigest())
            self.assertEqual(path.read_bytes(), b'old')

    def test_verified_cache_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'source'
            path.write_bytes(b'cached')
            with patch('urllib.request.urlopen') as request:
                download('https://example.test/source', path, hashlib.sha512(b'cached').hexdigest())
                request.assert_not_called()
            link = Path(name) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                download('https://example.test/source', link)


if __name__ == '__main__':
    unittest.main()
