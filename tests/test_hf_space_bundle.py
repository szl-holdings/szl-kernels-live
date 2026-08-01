from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_hf_space_bundle import build_bundle


SOURCE_SHA = "a" * 40


class LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        values = dict(attrs)
        if values.get("href"):
            self.hrefs.append(values["href"] or "")


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
            self.assertTrue(
                (output / "evidence" / "kernel-selfcheck-20260726.json").is_file()
            )
            self.assertTrue((output / "SPACE_PROVENANCE.json").is_file())
            self.assertTrue((output / "hf-deploy-manifest.json").is_file())
            readme = (output / "README.md").read_text(encoding="utf-8")
            self.assertTrue(readme.startswith("---\n"))
            self.assertIn("sdk: static", readme)
            self.assertIn("ten public", readme)

            collector = LinkCollector()
            collector.feed((output / "index.html").read_text(encoding="utf-8"))
            for href in ("SPACE_PROVENANCE.json", "hf-deploy-manifest.json"):
                self.assertIn(href, collector.hrefs)
                self.assertTrue((output / href).is_file())

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

    def test_portfolio_truth_labels_fail_closed_until_all_checks_settle(self) -> None:
        html = (Path(__file__).resolve().parents[1] / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn('<strong id="kernel-count">—</strong>', html)
        self.assertIn('<strong id="pass-count">—</strong>', html)
        self.assertIn('<strong id="head-count">—</strong>', html)
        self.assertIn("SNAPSHOT CPU PROBE PASS", html)
        self.assertIn('badge.textContent = "LIVE HEAD MATCH"', html)
        self.assertIn('badge.textContent = "HEAD DRIFT"', html)
        self.assertIn('badge.textContent = "HEAD UNAVAILABLE"', html)
        self.assertIn('count.textContent = "—"', html)
        self.assertIn("settled !== total", html)
        self.assertIn('unavailable === 0 ? `${matches}/${total}` : "INCOMPLETE"', html)
        self.assertIn(
            "${matches} match · ${drifts} drift · ${unavailable} unavailable",
            html,
        )

    def test_small_viewports_preserve_safe_area_spacing(self) -> None:
        html = (Path(__file__).resolve().parents[1] / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'content="width=device-width, initial-scale=1, viewport-fit=cover"',
            html,
        )
        self.assertIn(
            "header { padding-top: max(42px, env(safe-area-inset-top)); }", html
        )
        self.assertIn(
            "max(22px, env(safe-area-inset-left) + env(safe-area-inset-right))",
            html,
        )


if __name__ == "__main__":
    unittest.main()
