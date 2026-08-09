from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import urllib.parse

from scripts.build_hf_space_bundle import build_bundle
from scripts.deploy_hf_space import (
    HF_REPO,
    attest_publication,
    canonical_json,
    evaluate_effective_rulesets,
    require_governed_main,
    validate_bundle,
)


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
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn('--result "$RUNNER_TEMP/hf-deploy-result.json"', workflow)
        self.assertIn(
            '--attestation "$RUNNER_TEMP/hf-live-attestation.json"', workflow
        )
        self.assertIn(
            '--failure-evidence "$RUNNER_TEMP/hf-deploy-failure.json"', workflow
        )
        publish = workflow.index("python scripts/deploy_hf_space.py")
        final_attestation = workflow.index("Attest final exact-revision receipt")
        final_subject = workflow.index(
            "subject-path: ${{ runner.temp }}/hf-live-attestation.json"
        )
        success_evidence = workflow.index(
            "Upload required successful deployment evidence"
        )
        self.assertLess(publish, final_attestation)
        self.assertLess(final_attestation, final_subject)
        self.assertLess(final_subject, success_evidence)
        self.assertEqual(workflow.count("actions/attest-build-provenance@"), 2)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertIn("Upload separate failed-deployment evidence", workflow)
        self.assertIn("hf-space-deployment-failure", workflow)
        self.assertIn("hf-space-deployment-evidence", workflow)

    def test_inherited_projected_ruleset_is_bound_to_effective_main(self) -> None:
        summaries = [
            {
                "id": 7,
                "name": "org-default-branch-protection",
                "source": "szl-holdings",
                "source_type": "Organization",
                "enforcement": "active",
            }
        ]
        details = {7: {"id": 7, "bypass_actors": []}}
        effective = [
            {
                "type": rule_type,
                "ruleset_id": 7,
                "ruleset_source": "szl-holdings",
                "ruleset_source_type": "Organization",
            }
            for rule_type in (
                "pull_request",
                "non_fast_forward",
                "required_linear_history",
            )
        ]

        accepted, diagnostics = evaluate_effective_rulesets(
            summaries,
            details,
            effective,
        )

        self.assertEqual(accepted, [7])
        self.assertEqual(diagnostics, [])

    def test_policy_rejections_are_candidate_specific_and_secret_free(self) -> None:
        summaries = [
            {"id": 7, "enforcement": "active"},
            {"id": 8, "enforcement": "active"},
            {"id": 9, "enforcement": "active"},
        ]
        details = {
            7: {"bypass_actors": [{"actor_type": "OrganizationAdmin"}]},
            8: {"bypass_actors": []},
            9: {"_retrieval_error": "HTTPError"},
        }
        effective = [
            {"type": rule_type, "ruleset_id": ruleset_id}
            for ruleset_id, rule_types in (
                (7, ("pull_request", "non_fast_forward", "required_linear_history")),
                (8, ("pull_request", "non_fast_forward")),
                (9, ("pull_request", "non_fast_forward", "required_linear_history")),
            )
            for rule_type in rule_types
        ]

        accepted, diagnostics = evaluate_effective_rulesets(
            summaries,
            details,
            effective,
        )
        message = " | ".join(diagnostics)

        self.assertEqual(accepted, [])
        self.assertIn("ruleset 7: 1 bypass actor(s) are present", message)
        self.assertIn(
            "ruleset 8: missing effective rules: required_linear_history",
            message,
        )
        self.assertIn("ruleset 9: detail retrieval failed (HTTPError)", message)
        self.assertIn("bypass actors were not disclosed", message)
        self.assertNotIn("test-token", message)

    def test_in_process_guard_requires_exact_effective_no_bypass_main(self) -> None:
        def response(url: str, _token: str = "") -> object:
            if url.endswith("/repos/szl-holdings/szl-kernels-live"):
                return {"default_branch": "main"}
            if url.endswith("/rulesets?includes_parents=true"):
                return [
                    {
                        "id": 7,
                        "enforcement": "active",
                        "source": "szl-holdings",
                        "source_type": "Organization",
                    }
                ]
            if url.endswith("/rules/branches/main"):
                return [
                    {
                        "type": rule_type,
                        "ruleset_id": 7,
                        "ruleset_source": "szl-holdings",
                    }
                    for rule_type in (
                        "pull_request",
                        "non_fast_forward",
                        "required_linear_history",
                    )
                ]
            if url.endswith("/branches/main"):
                return {"commit": {"sha": SOURCE_SHA}}
            if url.endswith("/rulesets/7"):
                return {"bypass_actors": []}
            raise AssertionError(url)

        environment = {
            "GITHUB_REPOSITORY": "szl-holdings/szl-kernels-live",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
            "scripts.deploy_hf_space._request_json", side_effect=response
        ):
            authorization = require_governed_main(SOURCE_SHA)
            self.assertEqual(authorization["ruleset_ids"], [7])

        def undisclosed(url: str, token: str = "") -> object:
            value = response(url, token)
            if url.endswith("/rulesets/7"):
                value.pop("bypass_actors")
            return value

        with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
            "scripts.deploy_hf_space._request_json", side_effect=undisclosed
        ), self.assertRaisesRegex(RuntimeError, "bypass actors were not disclosed"):
            require_governed_main(SOURCE_SHA)

    def test_public_attestation_binds_exact_revision_bytes_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            target_sha = "b" * 40
            result = Path(temporary) / "result.json"
            result.write_text(
                json.dumps(
                    {
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "hf_revision": target_sha,
                    }
                ),
                encoding="utf-8",
            )
            attestation = Path(temporary) / "attestation.json"
            expected_paths = {
                path.relative_to(bundle).as_posix()
                for path in bundle.rglob("*")
                if path.is_file()
            }

            def hf_json(url: str, _token: str = "") -> object:
                if "/tree/" in url:
                    return [
                        {"type": "file", "path": path}
                        for path in sorted(expected_paths | {".gitattributes"})
                    ]
                return {"sha": target_sha, "runtime": {"stage": "RUNNING"}}

            def public_bytes(url: str) -> tuple[int, bytes]:
                if "/resolve/" in url:
                    marker = f"/resolve/{target_sha}/"
                    relative = urllib.parse.unquote(url.split(marker, 1)[1])
                    return 200, (bundle / relative).read_bytes()
                if "SPACE_PROVENANCE.json" in url:
                    return 200, (bundle / "SPACE_PROVENANCE.json").read_bytes()
                return 200, b"<html>operational</html>"

            with mock.patch(
                "scripts.deploy_hf_space._request_json", side_effect=hf_json
            ), mock.patch(
                "scripts.deploy_hf_space._public_bytes", side_effect=public_bytes
            ):
                evidence = attest_publication(
                    bundle,
                    SOURCE_SHA,
                    result,
                    attestation,
                    timeout=1,
                )
            self.assertEqual(evidence["schema"], "szl.hf-live-attestation/v2")
            self.assertEqual(evidence["status"], "MEASURED")
            self.assertEqual(evidence["hf_revision"], target_sha)
            self.assertEqual(evidence["source_revision"], SOURCE_SHA)
            self.assertEqual(evidence["target"], HF_REPO)
            self.assertEqual(evidence["runtime_stage"], "RUNNING")
            self.assertEqual(evidence["file_count"], len(expected_paths))
            self.assertRegex(evidence["bundle_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(evidence["tree_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                evidence["public_provenance"],
                {
                    "schema": "szl.deployment-source/v3",
                    "source_revision": SOURCE_SHA,
                    "relation": "source-bound-release-bundle",
                    "verified": True,
                },
            )
            self.assertEqual(
                json.loads(attestation.read_text(encoding="utf-8")), evidence
            )
            self.assertEqual(attestation.read_bytes(), canonical_json(evidence))


if __name__ == "__main__":
    unittest.main()
