from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_hf_space_bundle import build_bundle
from scripts.deploy_hf_space import validate_bundle


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
            self.assertEqual(manifest["schema"], "szl.hf-deploy-manifest/v2")
            self.assertEqual(
                manifest["self_manifest"],
                {
                    "path": "hf-deploy-manifest.json",
                    "included_in_files": False,
                    "reason": "self-digest would be recursive; exact bytes are bound by GitHub OIDC attestation",
                },
            )
            actual_paths = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
            listed_paths = {entry["path"] for entry in manifest["files"]}
            self.assertEqual(
                actual_paths,
                listed_paths | {manifest["self_manifest"]["path"]},
            )
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

    def test_deployer_revalidates_exact_bundle_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            build_bundle(output, SOURCE_SHA)
            self.assertEqual(
                validate_bundle(output, SOURCE_SHA)["target"],
                "SZLHOLDINGS/szl-kernels-live",
            )

            (output / "index.html").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeError, "bundle (byte count|digest) does not match"
            ):
                validate_bundle(output, SOURCE_SHA)

            build_bundle(output, SOURCE_SHA)
            (output / "unexpected.txt").write_text("extra", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "tree is not closed"):
                validate_bundle(output, SOURCE_SHA)

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
        self.assertIn("padding-left: max(11px, env(safe-area-inset-left));", html)
        self.assertIn("padding-right: max(11px, env(safe-area-inset-right));", html)

    def test_protected_deploy_reauthorizes_main_before_hf_token_use(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "hf-space-deploy.yml"
        ).read_text(encoding="utf-8")
        install = workflow.index(
            "Install pinned Hugging Face client without credentials"
        )
        guard = workflow.index("Reauthorize exact protected main before credential use")
        token = workflow.index("HF_TOKEN: ${{ secrets.HF_TOKEN }}")
        publish = workflow.index("python scripts/deploy_hf_space.py")
        self.assertLess(install, guard)
        self.assertLess(guard, token)
        self.assertLess(token, publish)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn('test "$GITHUB_REF" = "refs/heads/main"', workflow)
        self.assertIn("--connect-timeout 10 --max-time 30", workflow)
        self.assertIn("branches/main", workflow)
        self.assertIn('data.get("protected") is True or sys.exit', workflow)
        self.assertIn('test "$live_sha" = "$GITHUB_SHA"', workflow)


if __name__ == "__main__":
    unittest.main()
