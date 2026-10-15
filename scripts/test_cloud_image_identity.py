"""离线镜像身份兼容与拒绝路径回归测试。"""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from cloud_image_identity import archive_identities, verify_image


class ImageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.archive = Path(self.directory.name) / "images.tar"
        self.tag = "example:cloud"
        self.blobs = {}
        self.config = self.add_blob({"architecture": "amd64", "os": "linux"})
        self.manifest = self.add_blob({"config": self.config})
        self.manifest["annotations"] = {"io.containerd.image.name": "docker.io/library/" + self.tag}
        self.item = {"tag": self.tag, "id": self.config["digest"]}
        self.write_archive()

    def add_blob(self, value):
        data = json.dumps(value).encode()
        digest = hashlib.sha256(data).hexdigest()
        self.blobs["blobs/sha256/" + digest] = data
        return {"digest": "sha256:" + digest, "size": len(data)}

    def write_archive(self):
        with tarfile.open(self.archive, "w") as saved:
            entries = {**self.blobs, "index.json": json.dumps({"manifests": [self.manifest]}).encode()}
            for name, data in entries.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                saved.addfile(entry, io.BytesIO(data))

    def test_both_verified_id_representations(self):
        identities = archive_identities(self.archive, self.item)
        self.assertEqual(identities, {self.config["digest"], self.manifest["digest"]})
        for identity in identities:
            verify_image({"Id": identity, "Architecture": "amd64", "Os": "linux"}, self.item, identities)

    def test_unknown_identity_and_wrong_platform_rejected(self):
        identities = archive_identities(self.archive, self.item)
        for identity, architecture, system in [("sha256:" + "0" * 64, "amd64", "linux"),
                                                (self.item["id"], "arm64", "linux"),
                                                (self.item["id"], "amd64", "windows")]:
            with self.subTest(identity=identity, architecture=architecture, system=system):
                with self.assertRaises(ValueError):
                    verify_image({"Id": identity, "Architecture": architecture, "Os": system}, self.item, identities)

    def test_wrong_bundle_identity_rejected(self):
        with self.assertRaises(ValueError):
            archive_identities(self.archive, {**self.item, "id": "sha256:" + "0" * 64})

    def test_wrong_tag_rejected(self):
        with self.assertRaises(ValueError):
            archive_identities(self.archive, {**self.item, "tag": "other:cloud"})

    def test_tampered_blob_rejected(self):
        self.blobs["blobs/sha256/" + self.config["digest"].split(":")[1]] = b"{}"
        self.write_archive()
        with self.assertRaises(ValueError):
            archive_identities(self.archive, self.item)

    def test_namespaced_registry_tag_matches_canonical_name(self):
        self.item['tag'] = 'team/example:cloud'
        self.manifest['annotations']['io.containerd.image.name'] = 'docker.io/team/example:cloud'
        self.write_archive()
        self.assertIn(self.item['id'], archive_identities(self.archive, self.item))

    def test_classic_archive_accepts_only_proven_configuration_identity(self):
        config_name = self.config['digest'].split(':')[1] + '.json'
        data = self.blobs['blobs/sha256/' + self.config['digest'].split(':')[1]]
        entries = {config_name: data, 'manifest.json': json.dumps([
            {'Config': config_name, 'RepoTags': [self.tag], 'Layers': []}]).encode()}
        with tarfile.open(self.archive, 'w') as saved:
            for name, content in entries.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                saved.addfile(entry, io.BytesIO(content))
        self.assertEqual(archive_identities(self.archive, self.item), {self.item['id']})
        with self.assertRaises(ValueError):
            archive_identities(self.archive, {**self.item, 'id': self.manifest['digest']})


if __name__ == "__main__":
    unittest.main()
