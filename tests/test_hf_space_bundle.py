from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_hf_space_bundle import build_bundle


SOURCE_SHA = "a" * 40


class HuggingFaceSpaceBundleTests(unittest.TestCase):
    def test_bundle_is_source_bound_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            manifest = build_bundle(output, SOURCE_SHA)
            self.assertEqual(manifest["source_revision"], SOURCE_SHA)
            self.assertEqual(manifest["target"], "SZLHOLDINGS/szl-kernels-live")
            self.assertTrue((output / "index.html").is_file())
            self.assertTrue((output / "contracts" / "index.json").is_file())
            self.assertTrue((output / "registry" / "kernel-pins.json").is_file())
            self.assertTrue((output / "evidence" / "kernel-selfcheck-20260726.json").is_file())
            readme = (output / "README.md").read_text(encoding="utf-8")
            self.assertTrue(readme.startswith("---\n"))
            self.assertIn("sdk: static", readme)
            self.assertIn("ten public", readme)

    def test_manifest_digests_match_every_listed_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            build_bundle(output, SOURCE_SHA)
            manifest = json.loads(
                (output / "hf-deploy-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["file_count"], len(manifest["files"]))
            for entry in manifest["files"]:
                path = output / entry["path"]
                self.assertEqual(path.stat().st_size, entry["bytes"])
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"]
                )

    def test_bundle_rejects_mutable_or_malformed_source_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for bad_revision in ("main", "a" * 12, "G" * 40):
                with self.subTest(source_sha=bad_revision):
                    with self.assertRaises(ValueError):
                        build_bundle(Path(temporary) / bad_revision, bad_revision)


if __name__ == "__main__":
    unittest.main()
