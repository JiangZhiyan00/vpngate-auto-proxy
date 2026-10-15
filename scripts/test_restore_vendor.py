"""来源恢复必须拒绝摘要篡改和归档越界，失败不交付半成品。"""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from restore_vendor import restore


class VendorTests(unittest.TestCase):
    def fixture(self, directory, member='sample-1.0.0/Cargo.toml', symlink=False):
        root = Path(directory)
        (root / 'crates').mkdir()
        archive = root / 'crates/sample-1.0.0.crate'
        with tarfile.open(archive, 'w:gz') as stream:
            entry = tarfile.TarInfo(member)
            data = b'original source'
            entry.size = len(data)
            if symlink:
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/tmp/outside'
            stream.addfile(entry, io.BytesIO(data))
        record = {'name': 'sample', 'version': '1.0.0', 'archive': archive.name,
                  'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
        (root / 'manifest.json').write_text(json.dumps({'status': 'passed', 'crates': [record]}))
        return root, archive

    def test_original_source_and_cargo_checksums_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.fixture(directory)
            destination = root / 'vendor'
            restore(root, destination)
            package = destination / 'sample-1.0.0'
            self.assertEqual((package / 'Cargo.toml').read_bytes(), b'original source')
            value = json.loads((package / '.cargo-checksum.json').read_text())
            self.assertEqual(value['files']['Cargo.toml'], hashlib.sha256(b'original source').hexdigest())

    def test_tampered_archive_traversal_and_links_never_delivered(self):
        for member, link, tamper in [('sample-1.0.0/Cargo.toml', False, True),
                                     ('sample-1.0.0/../../outside', False, False),
                                     ('sample-1.0.0/link', True, False)]:
            with self.subTest(member=member, tamper=tamper), tempfile.TemporaryDirectory() as directory:
                root, archive = self.fixture(directory, member, link)
                if tamper:
                    archive.write_bytes(b'changed')
                destination = root / 'vendor'
                with self.assertRaises(ValueError):
                    restore(root, destination)
                self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
