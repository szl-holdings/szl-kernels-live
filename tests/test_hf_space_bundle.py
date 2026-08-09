from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import sys
import tempfile
import types
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
    _fetch_public_index,
    _public_bytes,
    _request_json_retry,
    _static_origin,
    _wait_for_exact_running,
    attest_publication,
    canonical_json,
    deploy_bundle,
    evaluate_effective_rulesets,
    require_governed_main,
    validate_bundle,
    validate_public_provenance,
    write_failure_evidence,
    write_workflow_stage_failure,
)


SOURCE_SHA = "a" * 40
TARGET_SHA = "b" * 40
PARENT_SHA = "c" * 40


def baseline_summary() -> dict[str, object]:
    return {
        "id": GOVERNED_RULESET_ID,
        "name": "org-default-branch-protection",
        "target": "branch",
        "source": "szl-holdings",
        "source_type": "Organization",
        "enforcement": "active",
    }


def pull_request_parameters() -> dict[str, object]:
    return {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": True,
        "required_reviewers": [],
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": True,
        "allowed_merge_methods": ["squash", "rebase"],
    }


def baseline_ruleset() -> dict[str, object]:
    return {
        **baseline_summary(),
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_name": {"exclude": [], "include": ["~ALL"]},
        },
        "rules": [
            {"type": "pull_request", "parameters": pull_request_parameters()},
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
        ],
    }


def baseline_effective() -> list[dict[str, object]]:
    return [
        {
            "type": "pull_request",
            "parameters": pull_request_parameters(),
            "ruleset_id": GOVERNED_RULESET_ID,
            "ruleset_source": "szl-holdings",
            "ruleset_source_type": "Organization",
        },
        *[
            {
                "type": rule_type,
                "ruleset_id": GOVERNED_RULESET_ID,
                "ruleset_source": "szl-holdings",
                "ruleset_source_type": "Organization",
            }
            for rule_type in ("non_fast_forward", "required_linear_history")
        ],
    ]


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
        success_evidence = workflow.index(
            "Upload locally measured deployment evidence"
        )
        final_attestation = workflow.index("Attest final exact-revision receipt")
        final_subject = workflow.index(
            "subject-path: ${{ runner.temp }}/hf-live-attestation.json"
        )
        stage_failure = workflow.index("Synthesize receipt-stage failure evidence")
        terminal_gate = workflow.index("Enforce terminal publication evidence")
        self.assertLess(publish, success_evidence)
        self.assertLess(success_evidence, final_attestation)
        self.assertLess(final_attestation, final_subject)
        self.assertLess(final_subject, stage_failure)
        self.assertLess(stage_failure, terminal_gate)
        self.assertEqual(workflow.count("actions/attest-build-provenance@"), 2)
        self.assertIn("id: publish-measure", workflow)
        self.assertIn("id: success-artifact", workflow)
        self.assertIn("id: oidc-receipt", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("stage-failure", workflow)
        self.assertIn("hf-space-receipt-stage-failure", workflow)
        self.assertIn('test "${{ steps.oidc-receipt.outcome }}" = "success"', workflow)
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

        contracts_workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "kernel-contracts.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(contracts_workflow.count('python-version: "3.12.13"'), 2)
        self.assertNotIn('python-version: "3.11"', contracts_workflow)
        self.assertIn("Prove clean hash-locked publisher runtime", contracts_workflow)
        self.assertIn("python -I -P -m venv", contracts_workflow)
        self.assertIn("--require-hashes", contracts_workflow)
        self.assertIn("--only-binary=:all:", contracts_workflow)
        self.assertIn("--ignore-installed", contracts_workflow)
        self.assertIn(
            'huggingface_hub.__version__ == "1.19.0"', contracts_workflow
        )

    def test_inherited_projected_ruleset_is_bound_to_effective_main(self) -> None:
        accepted, diagnostics = evaluate_effective_rulesets(
            [baseline_summary()],
            {GOVERNED_RULESET_ID: baseline_ruleset()},
            baseline_effective()
            + [
                {
                    "type": "required_workflows",
                    "ruleset_id": 999,
                    "ruleset_source": "szl-holdings",
                    "ruleset_source_type": "Organization",
                }
            ],
        )

        self.assertEqual(accepted, [GOVERNED_RULESET_ID])
        self.assertEqual(diagnostics, [])

    def test_policy_rejections_are_candidate_specific_and_secret_free(self) -> None:
        summary = baseline_summary()
        details = {GOVERNED_RULESET_ID: baseline_ruleset()}
        effective = baseline_effective()
        mutations = (
            ("missing inventory source", [{k: v for k, v in summary.items() if k != "source"}], effective),
            ("wrong inventory source_type", [{**summary, "source_type": "Repository"}], effective),
            ("missing row source", [summary], [{k: v for k, v in effective[0].items() if k != "ruleset_source"}, *effective[1:]]),
            ("mixed row source_type", [summary], [{**effective[0], "ruleset_source_type": "Repository"}, *effective[1:]]),
            ("wrong pull request parameters", [summary], [{**effective[0], "parameters": {**pull_request_parameters(), "required_approving_review_count": 1}}, *effective[1:]]),
        )
        for label, summaries, rows in mutations:
            with self.subTest(label=label):
                accepted, diagnostics = evaluate_effective_rulesets(
                    summaries, details, rows
                )
                self.assertEqual(accepted, [])
                self.assertTrue(diagnostics)
                self.assertNotIn("test-token", " | ".join(diagnostics))

        detail_mutations = (
            ("wrong name", {**baseline_ruleset(), "name": "other"}),
            ("wrong target", {**baseline_ruleset(), "target": "tag"}),
            ("bypass", {**baseline_ruleset(), "bypass_actors": [{"actor_id": 1}]}),
            ("exclusion", {**baseline_ruleset(), "conditions": {**baseline_ruleset()["conditions"], "ref_name": {"exclude": ["refs/heads/dev"], "include": ["~DEFAULT_BRANCH"]}}}),
        )
        for label, detail in detail_mutations:
            with self.subTest(label=label):
                accepted, diagnostics = evaluate_effective_rulesets(
                    [summary], {GOVERNED_RULESET_ID: detail}, effective
                )
                self.assertEqual(accepted, [])
                self.assertTrue(diagnostics)

    def test_in_process_guard_requires_exact_effective_no_bypass_main(self) -> None:
        def response(url: str, _token: str = "") -> object:
            self.assertEqual(_token, "test-token")
            if url.endswith("/repos/szl-holdings/szl-kernels-live"):
                return {
                    "id": 1295941334,
                    "full_name": SOURCE_REPO,
                    "default_branch": "main",
                }
            if url.endswith("/rulesets?includes_parents=true"):
                return [baseline_summary()]
            if url.endswith("/rules/branches/main"):
                return baseline_effective()
            if url.endswith("/branches/main"):
                return {"protected": True, "commit": {"sha": SOURCE_SHA}}
            if url.endswith(f"/rulesets/{GOVERNED_RULESET_ID}"):
                return baseline_ruleset()
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

        def weakened(url: str, token: str = "") -> object:
            value = response(url, token)
            if url.endswith(f"/rulesets/{GOVERNED_RULESET_ID}"):
                value["bypass_actors"] = [{"actor_id": 1}]
            return value

        with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
            "scripts.deploy_hf_space._request_json", side_effect=weakened
        ), self.assertRaisesRegex(RuntimeError, "baseline ruleset detail is not exact"):
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

    def _public_readback_mocks(
        self, bundle: Path, target_sha: str
    ) -> tuple[object, object]:
        expected_paths = {
            path.relative_to(bundle).as_posix()
            for path in bundle.rglob("*")
            if path.is_file()
        }

        def hf_json(url: str, **_kwargs) -> object:
            if "/tree/" in url:
                return [
                    {"type": "file", "path": path}
                    for path in sorted(expected_paths | {".gitattributes"})
                ]
            return {"sha": target_sha, "runtime": {"stage": "RUNNING"}}

        def public_bytes(url: str, **_kwargs) -> tuple[int, bytes, str, int]:
            if "/resolve/" not in url:
                raise AssertionError(url)
            marker = f"/resolve/{target_sha}/"
            relative = urllib.parse.unquote(url.split(marker, 1)[1])
            return 200, (bundle / relative).read_bytes(), url, 0

        def public_response(
            url: str, **_kwargs
        ) -> tuple[int, bytes, str | None]:
            parsed = urllib.parse.urlsplit(url)
            if parsed.path == "/":
                return 302, b"", "/index.html?" + parsed.query
            if parsed.path == "/index.html":
                return 200, (bundle / "index.html").read_bytes(), None
            if parsed.path == "/SPACE_PROVENANCE.json":
                return (
                    200,
                    (bundle / "SPACE_PROVENANCE.json").read_bytes(),
                    None,
                )
            raise AssertionError(url)

        return (hf_json, public_bytes, public_response)

    def test_public_attestation_binds_exact_revision_bytes_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            result = Path(temporary) / "result.json"
            result.write_bytes(
                canonical_json(
                    {
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "hf_revision": TARGET_SHA,
                    }
                )
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
            hf_json, public_bytes, public_response = self._public_readback_mocks(
                bundle, TARGET_SHA
            )
            final_guard = {
                "status": "AUTHORIZED_EXACT_PROTECTED_MAIN",
                "source_revision": SOURCE_SHA,
                "ruleset_ids": [GOVERNED_RULESET_ID],
            }
            with mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                side_effect=hf_json,
            ), mock.patch(
                "scripts.deploy_hf_space._public_bytes",
                side_effect=public_bytes,
            ), mock.patch(
                "scripts.deploy_hf_space._public_response",
                side_effect=public_response,
            ), mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                return_value=final_guard,
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
            self.assertEqual(evidence["hf_revision"], TARGET_SHA)
            self.assertEqual(evidence["source_revision"], SOURCE_SHA)
            self.assertEqual(evidence["target"], HF_REPO)
            self.assertEqual(evidence["runtime_stage"], "RUNNING")
            self.assertEqual(evidence["file_count"], len(expected_paths))
            self.assertEqual(evidence["post_publication_main"], final_guard)
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
                    candidate = json.loads(json.dumps(runtime_provenance))
                    if value is None:
                        candidate["source"].pop(field)
                    else:
                        candidate["source"][field] = value
                    with self.assertRaisesRegex(
                        RuntimeError, "public static source identity did not close"
                    ):
                        validate_public_provenance(candidate, SOURCE_SHA)

    def test_public_root_requires_one_exact_302_then_terminal_200_bytes(self) -> None:
        origin = _static_origin()
        query = urllib.parse.urlencode({"source": SOURCE_SHA})
        exact_location = origin + "/index.html?" + query
        expected = b"exact-index"

        with mock.patch(
            "scripts.deploy_hf_space._public_response",
            side_effect=[
                (302, b"", exact_location),
                (200, expected, None),
            ],
        ):
            self.assertEqual(
                _fetch_public_index(
                    origin,
                    SOURCE_SHA,
                    expected,
                    deadline=float("inf"),
                ),
                expected,
            )

        failures = (
            ("direct root 200", [(200, expected, None)], "exactly one 302"),
            (
                "wrong origin",
                [(302, b"", "https://example.test/index.html?" + query)],
                "unapproved origin",
            ),
            (
                "wrong path",
                [(302, b"", origin + "/other?" + query)],
                "requested path",
            ),
            (
                "wrong query",
                [(302, b"", origin + "/index.html?source=" + TARGET_SHA)],
                "requested query",
            ),
            (
                "second redirect",
                [(302, b"", exact_location), (302, b"", exact_location)],
                "terminate at one redirect",
            ),
            (
                "wrong bytes",
                [(302, b"", exact_location), (200, b"wrong", None)],
                "bytes differ",
            ),
        )
        for label, responses, message in failures:
            with self.subTest(label=label), mock.patch(
                "scripts.deploy_hf_space._public_response",
                side_effect=responses,
            ), self.assertRaisesRegex(RuntimeError, message):
                _fetch_public_index(
                    origin,
                    SOURCE_SHA,
                    expected,
                    deadline=float("inf"),
                )

    def test_transient_reads_are_bounded_and_all_5xx_retry(self) -> None:
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
                max_redirects=0,
            )
        self.assertEqual(response[0:2], (200, b"ok"))

        with mock.patch(
            "scripts.deploy_hf_space._public_bytes_once",
            side_effect=urllib.error.HTTPError(
                origin, 599, "Unavailable", {}, None
            ),
        ), mock.patch(
            "scripts.deploy_hf_space.time.monotonic",
            side_effect=(0.0, 0.0, 2.0),
        ), self.assertRaises(RetryExhausted):
            _public_bytes(
                origin + "/",
                deadline=1.0,
                label="public index readback",
                allowed_origins=frozenset({origin}),
                expected_path="/",
                expected_query="",
                max_redirects=0,
            )

        with mock.patch(
            "scripts.deploy_hf_space._request_json",
            return_value={"ok": True},
        ) as request_json, mock.patch(
            "scripts.deploy_hf_space.time.monotonic",
            side_effect=(5.0, 5.0),
        ):
            self.assertEqual(
                _request_json_retry(
                    "https://example.test/data",
                    deadline=10.0,
                    label="bounded request",
                ),
                {"ok": True},
            )
        self.assertLessEqual(request_json.call_args.kwargs["timeout"], 5.0)

    def test_prior_runtime_revision_is_retried_as_propagation(self) -> None:
        with mock.patch(
            "scripts.deploy_hf_space._request_json_retry",
            side_effect=[
                {"sha": PARENT_SHA, "runtime": {"stage": "RUNNING"}},
                {"sha": TARGET_SHA, "runtime": {"stage": "RUNNING"}},
            ],
        ) as request_json, mock.patch(
            "scripts.deploy_hf_space.time.monotonic", return_value=0.0
        ), mock.patch(
            "scripts.deploy_hf_space.time.sleep"
        ):
            self.assertEqual(
                _wait_for_exact_running(TARGET_SHA, deadline=10.0), "RUNNING"
            )
        self.assertEqual(request_json.call_count, 2)

    def test_same_sha_governance_weakening_writes_partial_not_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            result = Path(temporary) / "result.json"
            result.write_bytes(
                canonical_json(
                    {
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "hf_revision": TARGET_SHA,
                    }
                )
            )
            attestation = Path(temporary) / "attestation.json"
            failure = Path(temporary) / "failure.json"
            hf_json, public_bytes, public_response = self._public_readback_mocks(
                bundle, TARGET_SHA
            )
            with mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                side_effect=hf_json,
            ), mock.patch(
                "scripts.deploy_hf_space._public_bytes",
                side_effect=public_bytes,
            ), mock.patch(
                "scripts.deploy_hf_space._public_response",
                side_effect=public_response,
            ), mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                side_effect=RuntimeError("baseline governance weakened"),
            ), self.assertRaisesRegex(
                RuntimeError, "baseline governance weakened"
            ) as caught:
                attest_publication(
                    bundle, SOURCE_SHA, result, attestation, timeout=1
                )
            mutation_state = {
                "upload_call_entered": True,
                "authoritative_readback_attempted": False,
                "known_hf_revision": TARGET_SHA,
            }
            write_failure_evidence(
                failure,
                SOURCE_SHA,
                caught.exception,
                result,
                mutation_state,
            )
            evidence = json.loads(failure.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "PARTIAL_AFTER_MUTATION")
            self.assertEqual(evidence["hf_revision"], TARGET_SHA)
            self.assertFalse(evidence["receipt_minted"])
            self.assertFalse(evidence["measured"])
            self.assertFalse(evidence["deployment_success"])
            self.assertFalse(attestation.exists())

    def test_upload_entry_and_ambiguous_mutation_state_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            result = Path(temporary) / "result.json"
            state: dict[str, object] = {}
            api = mock.Mock()
            api.space_info.return_value = mock.Mock(sha=PARENT_SHA)
            api.upload_folder.side_effect = TimeoutError("transport reset")
            module = types.ModuleType("huggingface_hub")
            module.HfApi = lambda token: api
            environment = {"HF_TOKEN": "test-hf-token"}
            with mock.patch.dict("os.environ", environment, clear=True), mock.patch.dict(
                sys.modules, {"huggingface_hub": module}
            ), mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                return_value={"status": "AUTHORIZED"},
            ), mock.patch(
                "scripts.deploy_hf_space._recover_authoritative_revision",
                return_value=None,
            ), self.assertRaises(TimeoutError):
                deploy_bundle(bundle, SOURCE_SHA, result, state)

            self.assertTrue(state["upload_call_entered"])
            self.assertTrue(state["authoritative_readback_attempted"])
            self.assertIsNone(state["known_hf_revision"])
            api.upload_folder.assert_called_once()
            upload = api.upload_folder.call_args.kwargs
            self.assertEqual(upload["parent_commit"], PARENT_SHA)
            self.assertEqual(upload["delete_patterns"], "*")

            failure = Path(temporary) / "unknown.json"
            write_failure_evidence(
                failure, SOURCE_SHA, TimeoutError("transport reset"), result, state
            )
            unknown = json.loads(failure.read_text(encoding="utf-8"))
            self.assertEqual(unknown["status"], "MUTATION_OUTCOME_UNKNOWN")
            self.assertIsNone(unknown["hf_revision"])

            precondition_state: dict[str, object] = {}
            with mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                side_effect=RuntimeError("governance unavailable"),
            ), self.assertRaises(RuntimeError):
                deploy_bundle(bundle, SOURCE_SHA, result, precondition_state)
            before = Path(temporary) / "before.json"
            write_failure_evidence(
                before,
                SOURCE_SHA,
                RuntimeError("governance unavailable"),
                result,
                precondition_state,
            )
            self.assertEqual(
                json.loads(before.read_text(encoding="utf-8"))["status"],
                "FAILED_BEFORE_MUTATION",
            )

    def test_workflow_stage_failure_is_machine_readable_and_never_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = root / "result.json"
            receipt = root / "receipt.json"
            output = root / "failure.json"
            result.write_bytes(
                canonical_json(
                    {
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "hf_revision": TARGET_SHA,
                    }
                )
            )
            receipt.write_bytes(
                canonical_json(
                    {
                        "status": "MEASURED",
                        "source_revision": SOURCE_SHA,
                        "hf_revision": TARGET_SHA,
                        "target": HF_REPO,
                        "source": {
                            "repository": SOURCE_REPO,
                            "revision": SOURCE_SHA,
                            "relation": SOURCE_RELATION,
                        },
                    }
                )
            )
            evidence = write_workflow_stage_failure(
                output,
                SOURCE_SHA,
                result,
                receipt,
                failure_stage="OIDC_RECEIPT_ATTESTATION",
                artifact_outcome="success",
                oidc_outcome="failure",
            )
            self.assertEqual(
                evidence["status"], "FAILED_AFTER_LOCAL_MEASUREMENT"
            )
            self.assertEqual(evidence["hf_revision"], TARGET_SHA)
            self.assertFalse(evidence["receipt_minted"])
            self.assertFalse(evidence["deployment_success"])
            self.assertEqual(
                output.read_bytes(), canonical_json(evidence)
            )

if __name__ == "__main__":
    unittest.main()
