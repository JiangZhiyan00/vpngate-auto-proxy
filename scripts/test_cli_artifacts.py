"""唯一产品目标与指定干净构建目录的契约。"""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Artifacts(unittest.TestCase):
    def test_only_product_bin_and_original_library_identity(self):
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        package = next(p for p in json.loads(result.stdout)["packages"]
                       if p["name"] == "vpngate-auto-proxy")
        self.assertEqual([t["name"] for t in package["targets"] if "bin" in t["kind"]], ["vap"])
        self.assertEqual([t["name"] for t in package["targets"] if "lib" in t["kind"]],
                         ["vpngate_auto_proxy"])
        self.assertEqual(package["default_run"], "vap")

    @unittest.skipUnless(os.environ.get("VAP_ARTIFACT_DIR"), "需指定本轮干净产物目录")
    def test_selected_clean_build_has_no_old_product(self):
        directory = Path(os.environ["VAP_ARTIFACT_DIR"])
        self.assertTrue((directory / "vap").is_file())
        self.assertTrue(os.access(directory / "vap", os.X_OK))
        self.assertFalse(os.path.lexists(directory / "vpngate-auto-proxy"))


if __name__ == "__main__":
    unittest.main()
