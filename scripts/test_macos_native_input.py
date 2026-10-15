"""普通权限节点材料准备回归；不联网、不启动隧道。"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("native_input", Path(__file__).with_name("prepare-macos-native-input.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "nodes.json"
        self.output = self.directory / "input.json"
        self.nodes = [{"id": "a", "source_fetched_at": "2026-10-13T01:02:03Z", "profile": "私有材料"}, {"id": "b"}]
        self.source.write_text(json.dumps({"schema_version": 1, "nodes": self.nodes}))

    def run_prepare(self, identities):
        return module.prepare(self.source, identities, ["https://example.com/"], self.output)

    def test_exact_selection_preserves_time_private_mode_and_digest(self):
        result = self.run_prepare(["b", "a"])
        self.assertEqual(json.loads(self.output.read_bytes())["nodes"], [self.nodes[1], self.nodes[0]])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["sha256"], module.hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertNotIn("私有材料", json.dumps(result, ensure_ascii=False))

    def test_selection_and_output_are_never_silently_replaced(self):
        for identities in [[], ["a", "a"], ["missing"], ["a", "b", "c", "d"]]:
            with self.assertRaises(ValueError):
                self.run_prepare(identities)
            self.assertFalse(self.output.exists())
        self.run_prepare(["a"])
        original = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            self.run_prepare(["b"])
        self.assertEqual(self.output.read_bytes(), original)

    def test_source_symlink_and_hardlink_are_rejected(self):
        link = self.directory / "linked"
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            module.prepare(link, ["a"], ["https://example.com/"], self.output)
        link.unlink()
        os.link(self.source, link)
        with self.assertRaises(ValueError):
            self.run_prepare(["a"])
        self.assertFalse(self.output.exists())

    def test_duplicate_source_identity_is_rejected(self):
        self.source.write_text(json.dumps({"schema_version": 1, "nodes": [self.nodes[0], self.nodes[0]]}))
        with self.assertRaises(ValueError):
            self.run_prepare(["a"])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
