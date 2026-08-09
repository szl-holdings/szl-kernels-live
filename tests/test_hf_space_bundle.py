from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import urllib.error
import urllib.parse

from scripts.build_hf_space_bundle import build_bundle
from scripts.deploy_hf_space import (
    GOVERNED_RULESET_ID,
    HF_REPO,
    REQUIRED_RULE_TYPES as REQUIRED_RULE_TYPES_FOR_TEST,
    RetryExhausted,
    SOURCE_RELATION,
    SOURCE_REPO,
    _public_bytes,
    _public_bytes_once,
    _static_origin,
    attest_publication,
    canonical_json,
    evaluate_effective_rulesets,
    require_governed_main,
    validate_bundle,
    validate_public_provenance,
    write_failure_evidence,
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
        install = workflow.index("Create hash-closed isolated publisher")
        guard = workflow.index("Reauthorize exact protected main before credential use")
        token = workflow.index("HF_TOKEN: ${{ secrets.HF_TOKEN }}")
        publisher_command = (
            '"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P '
            "scripts/deploy_hf_space.py"
        )
        publish = workflow.index(publisher_command)
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
        governance_action = (
            "actions/create-github-app-token@"
            "bcd2ba49218906704ab6c1aa796996da409d3eb1"
        )
        self.assertIn(governance_action, workflow)
        self.assertIn("client-id: ${{ vars.QILLQAQ_CLIENT_ID }}", workflow)
        self.assertIn(
            "private-key: ${{ secrets.QILLQAQ_PRIVATE_KEY }}", workflow
        )
        self.assertIn("owner: ${{ github.repository_owner }}", workflow)
        self.assertIn("repositories: ${{ github.event.repository.name }}", workflow)
        self.assertIn("permission-administration: read", workflow)
        self.assertIn("permission-contents: read", workflow)
        self.assertEqual(workflow.count("          permission-"), 2)
        self.assertGreaterEqual(
            workflow.count(
                "GOVERNANCE_TOKEN: ${{ steps.governance-token.outputs.token }}"
            ),
            3,
        )
        self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertNotIn("GH_TOKEN: ${{ github.token }}", workflow)
        mint_governance = workflow.index(
            "Mint least-privilege governed ruleset reader"
        )
        require_governance = workflow.index(
            "Require governed ruleset reader token"
        )
        hf_credential = workflow.index("HF_TOKEN: ${{ secrets.HF_TOKEN }}")
        self.assertLess(mint_governance, require_governance)
        self.assertLess(require_governance, guard)
        self.assertLess(guard, hf_credential)
        self.assertIn('test -n "$GOVERNANCE_TOKEN"', workflow)
        self.assertIn('--result "$RUNNER_TEMP/hf-deploy-result.json"', workflow)
        self.assertIn(
            '--attestation "$RUNNER_TEMP/hf-live-attestation.json"', workflow
        )
        self.assertIn(
            '--failure-evidence "$RUNNER_TEMP/hf-deploy-failure.json"', workflow
        )
        publish = workflow.index(publisher_command)
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
        self.assertIn(
            "group: hf-space-deploy-${{ github.repository }}-production", workflow
        )
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn('python-version: "3.12.13"', workflow)
        self.assertIn("python -I -P -m venv", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("--only-binary=:all:", workflow)
        self.assertIn("--ignore-installed", workflow)
        self.assertIn('"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P', workflow)
        self.assertNotIn("pip install --disable-pip-version-check huggingface", workflow)

        lock = (
            Path(__file__).resolve().parents[1]
            / "requirements"
            / "hf-publisher.lock"
        ).read_text(encoding="utf-8")
        entries = [line for line in lock.splitlines() if line and not line.startswith("#")]
        self.assertEqual(len(entries), 23)
        for entry in entries:
            self.assertRegex(
                entry,
                r"^[A-Za-z0-9_.-]+==[^ ]+ --hash=sha256:[0-9a-f]{64}$",
            )
        self.assertEqual(lock.lower().count("huggingface_hub=="), 1)

    def test_inherited_projected_ruleset_is_bound_to_effective_main(self) -> None:
        summaries = [
            {
                "id": GOVERNED_RULESET_ID,
                "name": "org-default-branch-protection",
                "source": "szl-holdings",
                "source_type": "Organization",
                "enforcement": "active",
            }
        ]
        details = {
            GOVERNED_RULESET_ID: {
                "id": GOVERNED_RULESET_ID,
                "bypass_actors": [],
            }
        }
        effective = [
            {
                "type": rule_type,
                "ruleset_id": GOVERNED_RULESET_ID,
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

        self.assertEqual(accepted, [GOVERNED_RULESET_ID])
        self.assertEqual(diagnostics, [])

    def test_policy_rejections_are_candidate_specific_and_secret_free(self) -> None:
        summary = {
            "id": GOVERNED_RULESET_ID,
            "source": "szl-holdings",
            "source_type": "Organization",
            "enforcement": "active",
        }
        details = {GOVERNED_RULESET_ID: {"bypass_actors": []}}
        effective = [
            {
                "type": rule_type,
                "ruleset_id": GOVERNED_RULESET_ID,
                "ruleset_source": "szl-holdings",
                "ruleset_source_type": "Organization",
            }
            for rule_type in REQUIRED_RULE_TYPES_FOR_TEST
        ]
        mutations = (
            ("missing inventory source", [{k: v for k, v in summary.items() if k != "source"}], effective),
            ("wrong inventory source_type", [{**summary, "source_type": "Repository"}], effective),
            ("mixed row id", [summary], [{**effective[0], "ruleset_id": 9}, *effective[1:]]),
            ("missing row source", [summary], [{k: v for k, v in effective[0].items() if k != "ruleset_source"}, *effective[1:]]),
            ("mixed row source_type", [summary], [{**effective[0], "ruleset_source_type": "Repository"}, *effective[1:]]),
        )
        for label, summaries, rows in mutations:
            with self.subTest(label=label):
                accepted, diagnostics = evaluate_effective_rulesets(
                    summaries, details, rows
                )
                self.assertEqual(accepted, [])
                self.assertTrue(diagnostics)
                self.assertNotIn("test-token", " | ".join(diagnostics))

    def test_in_process_guard_requires_exact_effective_no_bypass_main(self) -> None:
        def response(url: str, _token: str = "") -> object:
            self.assertEqual(_token, "test-token")
            if url.endswith("/repos/szl-holdings/szl-kernels-live"):
                return {"default_branch": "main"}
            if url.endswith("/rulesets?includes_parents=true"):
                return [
                    {
                        "id": GOVERNED_RULESET_ID,
                        "enforcement": "active",
                        "source": "szl-holdings",
                        "source_type": "Organization",
                    }
                ]
            if url.endswith("/rules/branches/main"):
                return [
                    {
                        "type": rule_type,
                        "ruleset_id": GOVERNED_RULESET_ID,
                        "ruleset_source": "szl-holdings",
                        "ruleset_source_type": "Organization",
                    }
                    for rule_type in (
                        "pull_request",
                        "non_fast_forward",
                        "required_linear_history",
                    )
                ]
            if url.endswith("/branches/main"):
                return {"commit": {"sha": SOURCE_SHA}}
            if url.endswith(f"/rulesets/{GOVERNED_RULESET_ID}"):
                return {"bypass_actors": []}
            raise AssertionError(url)

        environment = {
            "GITHUB_REPOSITORY": "szl-holdings/szl-kernels-live",
            "GITHUB_REF": "refs/heads/main",
            "GOVERNANCE_TOKEN": "test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
            "scripts.deploy_hf_space._request_json", side_effect=response
        ):
            authorization = require_governed_main(SOURCE_SHA)
            self.assertEqual(
                authorization["ruleset_ids"], [GOVERNED_RULESET_ID]
            )

        def undisclosed(url: str, token: str = "") -> object:
            value = response(url, token)
            if url.endswith(f"/rulesets/{GOVERNED_RULESET_ID}"):
                value.pop("bypass_actors")
            return value

        with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
            "scripts.deploy_hf_space._request_json", side_effect=undisclosed
        ), self.assertRaisesRegex(RuntimeError, "bypass actors were not disclosed"):
            require_governed_main(SOURCE_SHA)

    def test_in_process_guard_rejects_empty_governance_token_before_api(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": "szl-holdings/szl-kernels-live",
            "GITHUB_REF": "refs/heads/main",
            "GOVERNANCE_TOKEN": "",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
            "scripts.deploy_hf_space._request_json"
        ) as request_json, self.assertRaisesRegex(
            RuntimeError,
            "GOVERNANCE_TOKEN is required for protected-main reauthorization",
        ):
            require_governed_main(SOURCE_SHA)
        request_json.assert_not_called()

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
            runtime_provenance = json.loads(
                (bundle / "SPACE_PROVENANCE.json").read_text(encoding="utf-8")
            )
            expected_paths = {
                path.relative_to(bundle).as_posix()
                for path in bundle.rglob("*")
                if path.is_file()
            }

            def hf_json(url: str, _token: str = "") -> object:
                if url.endswith("/repos/szl-holdings/szl-kernels-live/branches/main"):
                    return {"commit": {"sha": SOURCE_SHA}}
                if "/tree/" in url:
                    return [
                        {"type": "file", "path": path}
                        for path in sorted(expected_paths | {".gitattributes"})
                    ]
                return {"sha": target_sha, "runtime": {"stage": "RUNNING"}}

            def public_bytes(url: str, **_kwargs) -> tuple[int, bytes, str, int]:
                if "/resolve/" in url:
                    marker = f"/resolve/{target_sha}/"
                    relative = urllib.parse.unquote(url.split(marker, 1)[1])
                    return 200, (bundle / relative).read_bytes(), url, 0
                if "SPACE_PROVENANCE.json" in url:
                    return 200, (bundle / "SPACE_PROVENANCE.json").read_bytes(), url, 0
                return 200, (bundle / "index.html").read_bytes(), url, 0

            environment = {
                "GITHUB_REPOSITORY": SOURCE_REPO,
                "GITHUB_REF": "refs/heads/main",
                "GOVERNANCE_TOKEN": "test-token",
                "GITHUB_API_URL": "https://api.github.test",
            }
            with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
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
                    "source_repository": SOURCE_REPO,
                    "source_revision": SOURCE_SHA,
                    "relation": SOURCE_RELATION,
                    "verified": True,
                },
            )
            self.assertEqual(
                evidence["source"],
                {
                    "repository": SOURCE_REPO,
                    "revision": SOURCE_SHA,
                    "relation": SOURCE_RELATION,
                },
            )
            self.assertEqual(
                json.loads(attestation.read_text(encoding="utf-8")), evidence
            )
            self.assertEqual(attestation.read_bytes(), canonical_json(evidence))

            invalid_sources = (
                ("missing repository", "repository", None),
                ("wrong repository", "repository", "szl-holdings/other"),
                ("missing relation", "relation", None),
                ("wrong relation", "relation", "unbound-observation"),
            )
            for label, field, value in invalid_sources:
                with self.subTest(label=label):
                    runtime_provenance = json.loads(
                        (bundle / "SPACE_PROVENANCE.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    if value is None:
                        runtime_provenance["source"].pop(field)
                    else:
                        runtime_provenance["source"][field] = value
                    with self.assertRaisesRegex(
                        RuntimeError, "public static source identity did not close"
                    ):
                        validate_public_provenance(runtime_provenance, SOURCE_SHA)

    def test_public_redirect_and_exact_byte_contracts_fail_closed(self) -> None:
        origin = _static_origin()
        query = urllib.parse.urlencode({"source": SOURCE_SHA})
        url = origin + "/?" + query

        def redirect(location: str) -> urllib.error.HTTPError:
            return urllib.error.HTTPError(
                url,
                302,
                "Found",
                {"Location": location},
                None,
            )

        for label, location in (
            ("wrong origin", "https://example.test/?" + query),
            ("wrong path", origin + "/other?" + query),
            ("wrong query", origin + "/?source=" + "b" * 40),
        ):
            opener = mock.Mock()
            opener.open.side_effect = redirect(location)
            with self.subTest(label=label), mock.patch(
                "scripts.deploy_hf_space.urllib.request.build_opener",
                return_value=opener,
            ), self.assertRaisesRegex(RuntimeError, "public readback redirect"):
                _public_bytes_once(
                    url,
                    allowed_origins=frozenset({origin}),
                    expected_path="/",
                    expected_query=query,
                    max_redirects=1,
                )

        opener = mock.Mock()
        opener.open.side_effect = redirect(origin + "/?" + query)
        with mock.patch(
            "scripts.deploy_hf_space.urllib.request.build_opener",
            return_value=opener,
        ), self.assertRaisesRegex(RuntimeError, "redirect limit exceeded"):
            _public_bytes_once(
                url,
                allowed_origins=frozenset({origin}),
                expected_path="/",
                expected_query=query,
                max_redirects=0,
            )

    def test_transient_public_readback_retries_and_exhausts_safely(self) -> None:
        origin = _static_origin()
        attempts = [ConnectionResetError(), (200, b"ok", origin + "/", 0)]
        with mock.patch(
            "scripts.deploy_hf_space._public_bytes_once", side_effect=attempts
        ), mock.patch("scripts.deploy_hf_space.time.sleep"):
            response = _public_bytes(
                origin + "/",
                deadline=float("inf"),
                label="public index readback",
                allowed_origins=frozenset({origin}),
                expected_path="/",
                expected_query="",
                max_redirects=1,
            )
        self.assertEqual(response[0:2], (200, b"ok"))

        with mock.patch(
            "scripts.deploy_hf_space._public_bytes_once",
            side_effect=urllib.error.HTTPError(
                origin, 503, "Unavailable", {}, None
            ),
        ), mock.patch(
            "scripts.deploy_hf_space.time.monotonic", side_effect=(0.0, 2.0)
        ), self.assertRaises(RetryExhausted):
            _public_bytes(
                origin + "/",
                deadline=1.0,
                label="public index readback",
                allowed_origins=frozenset({origin}),
                expected_path="/",
                expected_query="",
                max_redirects=1,
            )

    def test_post_mutation_main_drift_writes_partial_evidence_not_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            target_sha = "b" * 40
            result = Path(temporary) / "result.json"
            result.write_bytes(
                canonical_json(
                    {
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "hf_revision": target_sha,
                    }
                )
            )
            attestation = Path(temporary) / "attestation.json"
            failure = Path(temporary) / "failure.json"
            expected_paths = {
                path.relative_to(bundle).as_posix()
                for path in bundle.rglob("*")
                if path.is_file()
            }

            def response(url: str, _token: str = "") -> object:
                if url.endswith("/repos/szl-holdings/szl-kernels-live/branches/main"):
                    return {"commit": {"sha": "c" * 40}}
                if "/tree/" in url:
                    return [
                        {"type": "file", "path": path}
                        for path in sorted(expected_paths | {".gitattributes"})
                    ]
                return {"sha": target_sha, "runtime": {"stage": "RUNNING"}}

            def public(url: str, **_kwargs) -> tuple[int, bytes, str, int]:
                if "/resolve/" in url:
                    marker = f"/resolve/{target_sha}/"
                    relative = urllib.parse.unquote(url.split(marker, 1)[1])
                    return 200, (bundle / relative).read_bytes(), url, 0
                name = "SPACE_PROVENANCE.json" if "SPACE_PROVENANCE" in url else "index.html"
                return 200, (bundle / name).read_bytes(), url, 0

            environment = {
                "GITHUB_REPOSITORY": SOURCE_REPO,
                "GITHUB_REF": "refs/heads/main",
                "GOVERNANCE_TOKEN": "test-token",
                "GITHUB_API_URL": "https://api.github.test",
            }
            with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
                "scripts.deploy_hf_space._request_json", side_effect=response
            ), mock.patch(
                "scripts.deploy_hf_space._public_bytes", side_effect=public
            ), self.assertRaisesRegex(RuntimeError, "drifted after publication") as caught:
                attest_publication(
                    bundle, SOURCE_SHA, result, attestation, timeout=1
                )
            write_failure_evidence(failure, SOURCE_SHA, caught.exception, result)
            evidence = json.loads(failure.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "PARTIAL_AFTER_MUTATION")
            self.assertEqual(evidence["hf_revision"], target_sha)
            self.assertFalse(evidence["receipt_minted"])
            self.assertFalse(evidence["measured"])
            self.assertFalse(attestation.exists())


if __name__ == "__main__":
    unittest.main()
