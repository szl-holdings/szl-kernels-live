from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import os
import re
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock
import urllib.error
import urllib.parse

from scripts.build_hf_space_bundle import build_bundle
from scripts.deploy_hf_space import (
    GOVERNED_RULESET_ID,
    HF_WINDOW_MAX_INJECTION_BYTES,
    HF_REPO,
    REQUIRED_RULE_TYPES as REQUIRED_RULE_TYPES_FOR_TEST,
    RetryExhausted,
    SOURCE_RELATION,
    SOURCE_REPO,
    _fetch_public_index,
    _hf_upload_child_environment,
    _recover_authoritative_revision,
    _run_bounded_process,
    _run_killable_child,
    _public_bytes,
    _request_json_retry,
    _static_origin,
    _validate_readback_url,
    _wait_for_exact_running,
    attest_publication,
    canonical_json,
    cleanup_terminal_success_files,
    deploy_bundle,
    enforce_terminal_evidence,
    evaluate_effective_rulesets,
    finalize_attested_receipt,
    normalize_public_static_index,
    require_governed_main,
    require_receipt_failure_artifact,
    synthesize_candidate_receipt,
    validate_deployment_failure_receipt,
    validate_bundle,
    validate_public_provenance,
    write_failure_evidence,
    write_workflow_stage_failure,
)


SOURCE_SHA = "a" * 40
TARGET_SHA = "b" * 40
PARENT_SHA = "c" * 40
LIVE_INJECTION_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "hf-static-window-huggingface-injection.html"
)


def inject_hf_window(index_bytes: bytes, injection: bytes | None = None) -> bytes:
    injection = (
        injection
        if injection is not None
        else LIVE_INJECTION_FIXTURE.read_bytes().rstrip(b"\r\n")
    )
    boundary = index_bytes.index(b"<head>") + len(b"<head>")
    return index_bytes[:boundary] + injection + index_bytes[boundary:]


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
        self.assertIn(
            '--connect-timeout 10 --max-time "$request_timeout"', workflow
        )
        self.assertIn(
            'operation_deadline="$((HF_TERMINAL_DEADLINE_EPOCH - 600))"',
            workflow,
        )
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
        candidate_receipt = workflow.index(
            "Synthesize deterministic canonical success receipt candidate"
        )
        final_attestation = workflow.index("Attest canonical final success receipt bytes")
        final_subject = workflow.index(
            "DEADLINE_ACTION_INPUT_SUBJECT_PATH: ${{ runner.temp }}/hf-terminal-candidate/hf-canonical-success-receipt.json"
        )
        final_receipt = workflow.index(
            "Promote attested receipt and bind separate metadata envelope"
        )
        terminal_success = workflow.index("Upload required terminal success evidence")
        stage_failure = workflow.index("Synthesize receipt-stage failure evidence")
        terminal_gate = workflow.index("Enforce terminal publication evidence")
        self.assertLess(publish, success_evidence)
        self.assertLess(success_evidence, candidate_receipt)
        self.assertLess(candidate_receipt, final_attestation)
        self.assertLess(final_attestation, final_subject)
        self.assertLess(final_subject, final_receipt)
        self.assertLess(final_receipt, terminal_success)
        self.assertLess(terminal_success, stage_failure)
        self.assertLess(stage_failure, terminal_gate)
        self.assertEqual(workflow.count("actions/attest-build-provenance@"), 1)
        self.assertIn("id: publish-measure", workflow)
        self.assertIn("id: success-artifact", workflow)
        self.assertIn("id: candidate-receipt", workflow)
        self.assertIn("id: oidc-receipt", workflow)
        self.assertIn("id: finalize-receipt", workflow)
        self.assertIn("id: terminal-success-artifact", workflow)
        for output_name in ("attestation-id", "attestation-url", "bundle-path"):
            self.assertIn(
                "steps.oidc-receipt.outputs." + output_name,
                workflow,
            )
        self.assertIn("hf-canonical-success-receipt.json", workflow)
        self.assertIn("hf-oidc-attestation-envelope.json", workflow)
        self.assertIn("hf-space-terminal-success-evidence", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("stage-failure", workflow)
        self.assertIn("hf-space-receipt-stage-failure", workflow)
        self.assertIn("scripts/deploy_hf_space.py enforce-terminal", workflow)
        for outcome_binding in (
            '--publish-outcome "${{ steps.publish-measure.outcome }}"',
            '--artifact-outcome "${{ steps.success-artifact.outcome }}"',
            '--candidate-receipt-outcome "${{ steps.candidate-receipt.outcome }}"',
            '--oidc-outcome "${{ steps.oidc-receipt.outcome }}"',
            '--finalize-receipt-outcome "${{ steps.finalize-receipt.outcome }}"',
            '--terminal-artifact-outcome "${{ steps.terminal-success-artifact.outcome }}"',
            '--failure-synthesis-outcome "${{ steps.receipt-stage-failure.outcome }}"',
            '--failure-artifact-primary-outcome "${{ steps.receipt-stage-failure-artifact-primary.outcome }}"',
            '--failure-artifact-retry-outcome "${{ steps.receipt-stage-failure-artifact-retry.outcome }}"',
            '--deployment-failure-receipt-outcome "${{ steps.deployment-failure-receipt.outcome }}"',
        ):
            self.assertIn(outcome_binding, workflow)
        self.assertIn("enforce-terminal", workflow)
        self.assertIn("receipt-stage-failure-artifact-primary", workflow)
        self.assertIn("receipt-stage-failure-artifact-retry", workflow)
        self.assertIn(
            "steps.receipt-stage-failure-artifact-primary.outcome != 'success'",
            workflow,
        )
        self.assertIn("--failure-artifact-primary-outcome", workflow)
        self.assertIn("--failure-artifact-retry-outcome", workflow)
        for cleanup_path in (
            "$RUNNER_TEMP/hf-terminal-candidate/hf-canonical-success-receipt.json",
            "$RUNNER_TEMP/hf-canonical-success-receipt.json",
            "$RUNNER_TEMP/hf-oidc-attestation-envelope.json",
        ):
            self.assertIn(f'--cleanup-path "{cleanup_path}"', workflow)
        self.assertIn("DEADLINE_ACTION_INPUT_IF_NO_FILES_FOUND: error", workflow)
        self.assertIn("deployment-failure-artifact-primary", workflow)
        self.assertIn("deployment-failure-artifact-retry", workflow)
        self.assertIn("id: deployment-failure-receipt", workflow)
        self.assertIn("validate-deployment-failure", workflow)
        self.assertIn("hf-space-deployment-failure-receipt-primary", workflow)
        self.assertIn("hf-space-deployment-failure-receipt-retry", workflow)
        self.assertIn("hf-space-deployment-failure-supporting", workflow)
        self.assertIn(
            "DEADLINE_ACTION_INPUT_PATH: ${{ runner.temp }}/hf-deploy-failure.json",
            workflow,
        )
        self.assertIn("steps.deployment-failure-receipt.outcome == 'success'", workflow)
        self.assertIn("--deployment-failure-receipt-outcome", workflow)
        self.assertIn("--deployment-failure-artifact-primary-outcome", workflow)
        self.assertIn("--deployment-failure-artifact-retry-outcome", workflow)
        self.assertIn("hf-space-deployment-evidence", workflow)
        self.assertIn(
            "group: hf-space-deploy-${{ github.repository }}-production", workflow
        )
        self.assertIn("cancel-in-progress: false", workflow)
        timeout = re.search(r"^\s+timeout-minutes:\s+(\d+)$", workflow, re.MULTILINE)
        self.assertIsNotNone(timeout)
        timeout_seconds = int(timeout.group(1)) * 60
        self.assertEqual(timeout_seconds, 3600)
        self.assertIn(
            "55m final-evidence deadline plus 5m runner-shutdown slack",
            workflow,
        )
        self.assertIn("Record cumulative job budget origin", workflow)
        self.assertIn("HF_JOB_STARTED_AT_EPOCH", workflow)
        self.assertIn("HF_TERMINAL_DEADLINE_EPOCH", workflow)
        self.assertIn("operation_remaining", workflow)
        self.assertIn("10m terminal-evidence, and 5m runner slack", workflow)
        self.assertIn("Reserve full terminal-evidence budget before mutation", workflow)
        self.assertIn("max_pre_mutation_seconds=900", workflow)
        self.assertLess(
            workflow.index("Reserve full terminal-evidence budget before mutation"),
            workflow.index("Publish and measure exact protected-main bundle"),
        )
        self.assertIn('--bundle "$RUNNER_TEMP/hf-bundle"', workflow)
        self.assertIn('python-version: "3.12.13"', workflow)
        self.assertIn("python -I -P -m venv", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("--only-binary=:all:", workflow)
        self.assertIn("--ignore-installed", workflow)
        self.assertIn('"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P', workflow)
        self.assertIn(
            '"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P -c', workflow
        )
        self.assertIn(
            '"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P scripts/build_hf_space_bundle.py',
            workflow,
        )
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
        self.assertIn(
            '"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P -c',
            contracts_workflow,
        )
        self.assertIn(
            '"$RUNNER_TEMP/hf-publisher-venv/bin/python" -I -P scripts/build_hf_space_bundle.py',
            contracts_workflow,
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
        def response(
            url: str,
            _token: str = "",
            timeout: float = 30,
        ) -> object:
            self.assertEqual(_token, "test-token")
            self.assertGreater(timeout, 0)
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

        def weakened(
            url: str,
            token: str = "",
            timeout: float = 30,
        ) -> object:
            value = response(url, token, timeout)
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

    def test_slow_governance_requests_deplete_one_shared_deadline(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPO,
            "GITHUB_REF": "refs/heads/main",
            "GOVERNANCE_TOKEN": "governance-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        clock = [0.0]
        timeouts: list[float] = []
        responses = [
            {
                "id": 1295941334,
                "full_name": SOURCE_REPO,
                "default_branch": "main",
            },
            {"protected": True, "commit": {"sha": SOURCE_SHA}},
        ]

        def slow_request(url: str, token: str = "", timeout: float = 30) -> object:
            self.assertEqual(token, "governance-token")
            timeouts.append(timeout)
            clock[0] += 28 if len(timeouts) == 1 else 4
            return responses[len(timeouts) - 1]

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch(
            "scripts.deploy_hf_space.time.monotonic",
            side_effect=lambda: clock[0],
        ), mock.patch(
            "scripts.deploy_hf_space._request_json",
            side_effect=slow_request,
        ), self.assertRaisesRegex(RetryExhausted, "shared deadline expired"):
            require_governed_main(SOURCE_SHA, deadline=31.0)
        self.assertEqual(timeouts, [30, 3])

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
            self.assertTrue(_kwargs.get("allow_hf_resolve_redirects"))
            self.assertEqual(_kwargs.get("max_redirects"), 3)
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
                return 200, inject_hf_window((bundle / "index.html").read_bytes()), None
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
                        "previous_hf_revision": PARENT_SHA,
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
            immutable_attempts: dict[str, int] = {}

            def eventual_public_bytes(url: str, **kwargs):
                response = public_bytes(url, **kwargs)
                immutable_attempts[url] = immutable_attempts.get(url, 0) + 1
                if immutable_attempts[url] == 1:
                    return response[0], b"propagating", response[2], response[3]
                return response

            provenance_attempts = 0

            def eventual_public_response(url: str, **kwargs):
                nonlocal provenance_attempts
                response = public_response(url, **kwargs)
                if urllib.parse.urlsplit(url).path == "/SPACE_PROVENANCE.json":
                    provenance_attempts += 1
                    if provenance_attempts == 1:
                        return response[0], b"propagating", response[2]
                return response

            with mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                side_effect=hf_json,
            ), mock.patch(
                "scripts.deploy_hf_space._public_bytes",
                side_effect=eventual_public_bytes,
            ), mock.patch(
                "scripts.deploy_hf_space._public_response",
                side_effect=eventual_public_response,
            ), mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                return_value=final_guard,
            ), mock.patch(
                "scripts.deploy_hf_space.time.sleep"
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
            self.assertFalse(evidence["receipt_minted"])
            self.assertFalse(evidence["deployment_success"])
            self.assertEqual(evidence["hf_revision"], TARGET_SHA)
            self.assertEqual(evidence["source_revision"], SOURCE_SHA)
            self.assertEqual(evidence["target"], HF_REPO)
            self.assertEqual(evidence["runtime_stage"], "RUNNING")
            self.assertEqual(evidence["file_count"], len(expected_paths))
            self.assertEqual(evidence["post_publication_main"], final_guard)
            self.assertRegex(evidence["bundle_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(evidence["tree_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                evidence["public_index"]["transformation"],
                "HF_WINDOW_HUGGINGFACE_HEAD_INJECTION_V1",
            )
            self.assertEqual(
                evidence["public_index"]["normalized_sha256"],
                hashlib.sha256((bundle / "index.html").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                evidence["public_index"]["injection_bytes"],
                len(LIVE_INJECTION_FIXTURE.read_bytes().rstrip(b"\r\n")),
            )
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
            self.assertGreaterEqual(min(immutable_attempts.values()), 2)
            self.assertEqual(provenance_attempts, 2)

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

    def test_public_provenance_rejects_terminal_nonmatching_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            result = Path(temporary) / "result.json"
            result.write_bytes(
                canonical_json(
                    {
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "previous_hf_revision": PARENT_SHA,
                        "hf_revision": TARGET_SHA,
                    }
                )
            )
            with mock.patch(
                "scripts.deploy_hf_space._wait_for_exact_running",
                return_value="RUNNING",
            ), mock.patch(
                "scripts.deploy_hf_space._verify_exact_hf_revision",
                return_value=[],
            ), mock.patch(
                "scripts.deploy_hf_space._fetch_public_index",
                return_value=(bundle / "index.html").read_bytes(),
            ), mock.patch(
                "scripts.deploy_hf_space._public_response",
                return_value=(200, b"terminal mismatch", None),
            ), mock.patch(
                "scripts.deploy_hf_space.time.monotonic",
                side_effect=(0.0, 1.0),
            ), self.assertRaisesRegex(RuntimeError, "provenance bytes differ"):
                attest_publication(
                    bundle,
                    SOURCE_SHA,
                    result,
                    Path(temporary) / "attestation.json",
                    timeout=1,
                )

    def test_public_root_requires_one_exact_302_then_terminal_200_bytes(self) -> None:
        origin = _static_origin()
        query = urllib.parse.urlencode({"source": SOURCE_SHA})
        exact_location = origin + "/index.html?" + query
        expected = b"<!doctype html>\n<html><head>\n</head><body>exact</body></html>\n"
        observed = inject_hf_window(expected)

        with mock.patch(
            "scripts.deploy_hf_space._public_response",
            side_effect=[
                (302, b"", exact_location),
                (200, b"propagating", None),
                (200, observed, None),
            ],
        ), mock.patch(
            "scripts.deploy_hf_space.time.sleep"
        ):
            measurement = _fetch_public_index(
                    origin,
                    SOURCE_SHA,
                    expected,
                    deadline=float("inf"),
                )
            self.assertEqual(measurement["normalized_sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(measurement["injection_sha256"], hashlib.sha256(LIVE_INJECTION_FIXTURE.read_bytes().rstrip(b"\r\n")).hexdigest())

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

        with mock.patch(
            "scripts.deploy_hf_space._public_response",
            side_effect=[
                (302, b"", exact_location),
                (200, b"wrong", None),
            ],
        ), mock.patch(
            "scripts.deploy_hf_space.time.monotonic",
            return_value=1.0,
        ), self.assertRaisesRegex(RuntimeError, "platform injection"):
            _fetch_public_index(
                origin,
                SOURCE_SHA,
                expected,
                deadline=0.5,
            )

    def test_live_hf_window_fixture_has_one_strict_normalizable_injection(self) -> None:
        immutable = b"<!doctype html>\n<html><head>\n</head><body>exact</body></html>\n"
        fixture = LIVE_INJECTION_FIXTURE.read_bytes().rstrip(b"\r\n")
        observed = inject_hf_window(immutable, fixture)
        measurement = normalize_public_static_index(observed, immutable)
        self.assertEqual(measurement["normalized_sha256"], hashlib.sha256(immutable).hexdigest())
        self.assertEqual(measurement["injection_sha256"], hashlib.sha256(fixture).hexdigest())
        self.assertEqual(measurement["injection_bytes"], len(fixture))

        boundary = immutable.index(b"<head>") + len(b"<head>")
        oversized = (
            b'<script>window.huggingface={variables:{"x":"'
            + b"a" * HF_WINDOW_MAX_INJECTION_BYTES
            + b'"}};</script>'
        )
        invalid = {
            "zero": immutable,
            "multiple": inject_hf_window(inject_hf_window(immutable, fixture), fixture),
            "wrong_location": immutable[: boundary + 1] + fixture + immutable[boundary + 1 :],
            "wrong_prefix": inject_hf_window(immutable, fixture.replace(b"window.huggingface=", b"window.huggingface =")),
            "non_object": inject_hf_window(immutable, b"<script>window.huggingface=[];</script>"),
            "oversize": inject_hf_window(immutable, oversized),
            "nested_markup": inject_hf_window(immutable, b'<script>window.huggingface={variables:{"x":"<b>"}};</script>'),
            "extra_script": inject_hf_window(immutable, fixture + b"<script>extra()</script>"),
            "extra_byte": inject_hf_window(immutable, fixture + b"x"),
            "bad_terminator": inject_hf_window(immutable, fixture.replace(b";</script>", b" </script>")),
        }
        for label, candidate in invalid.items():
            with self.subTest(label=label), self.assertRaises(RuntimeError):
                normalize_public_static_index(candidate, immutable)

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
            side_effect=(5.0, 5.0, 5.0),
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

    def test_immutable_hf_redirects_are_constrained(self) -> None:
        expected_path = f"/spaces/{HF_REPO}/resolve/{TARGET_SHA}/index.html"
        cache_path = (
            f"/api/resolve-cache/spaces/{HF_REPO}/{TARGET_SHA}/index.html"
        )
        cache_query = urllib.parse.urlencode(
            [(expected_path, ""), ("etag", '"' + "d" * 64 + '"')]
        )
        _validate_readback_url(
            "https://huggingface.co" + cache_path + "?" + cache_query,
            allowed_origins=frozenset({"https://huggingface.co"}),
            expected_path=expected_path,
            expected_query="",
            allow_hf_resolve_redirects=True,
            redirect_step=1,
        )
        _validate_readback_url(
            (
                "https://cdn-lfs.hf.co/repos/object?Expires=1&"
                "Signature=s&Key-Pair-Id=k"
            ),
            allowed_origins=frozenset({"https://huggingface.co"}),
            expected_path=expected_path,
            expected_query="",
            allow_hf_resolve_redirects=True,
            redirect_step=2,
        )
        _validate_readback_url(
            (
                "https://cdn-lfs-us-1.hf.co/repos/object?Policy=p&"
                "Signature=s&Key-Pair-Id=k"
            ),
            allowed_origins=frozenset({"https://huggingface.co"}),
            expected_path=expected_path,
            expected_query="",
            allow_hf_resolve_redirects=True,
            redirect_step=2,
        )

        rejected = (
            "https://huggingface.co"
            + cache_path.replace(TARGET_SHA, PARENT_SHA)
            + "?"
            + cache_query,
            "https://cdn-lfs.hf.co/repos/object",
            "https://example.test/object?Signature=s",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaisesRegex(
                RuntimeError, "unapproved immutable HF redirect"
            ):
                _validate_readback_url(
                    url,
                    allowed_origins=frozenset({"https://huggingface.co"}),
                    expected_path=expected_path,
                    expected_query="",
                    allow_hf_resolve_redirects=True,
                    redirect_step=1,
                )

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
                _wait_for_exact_running(
                    TARGET_SHA,
                    PARENT_SHA,
                    deadline=10.0,
                ),
                "RUNNING",
            )
        self.assertEqual(request_json.call_count, 2)

        unrelated = "d" * 40
        with mock.patch(
            "scripts.deploy_hf_space._request_json_retry",
            return_value={"sha": unrelated, "runtime": {"stage": "RUNNING"}},
        ), mock.patch(
            "scripts.deploy_hf_space.time.monotonic", return_value=0.0
        ), mock.patch(
            "scripts.deploy_hf_space.time.sleep"
        ) as sleep, self.assertRaisesRegex(RuntimeError, "unrelated revision"):
            _wait_for_exact_running(
                TARGET_SHA,
                PARENT_SHA,
                deadline=10.0,
            )
        sleep.assert_not_called()

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
                        "previous_hf_revision": PARENT_SHA,
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
            child_environment: dict[str, str] = {}
            environment = {
                "HF_TOKEN": "test-hf-token",
                "GOVERNANCE_TOKEN": "test-governance-token",
            }
            def hanging_child(_command, *, entered_marker, mutation_state, **_kwargs):
                child_environment.update(_kwargs["environment"])
                entered_marker.write_text("entered", encoding="utf-8")
                mutation_state["upload_call_entered"] = True
                raise TimeoutError("transport reset")

            with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                return_value={"status": "AUTHORIZED"},
            ), mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                return_value={"sha": PARENT_SHA},
            ), mock.patch(
                "scripts.deploy_hf_space._run_killable_child",
                side_effect=hanging_child,
            ), mock.patch(
                "scripts.deploy_hf_space._recover_authoritative_revision",
                side_effect=RetryExhausted("parent persisted"),
            ), self.assertRaises(RetryExhausted):
                deploy_bundle(bundle, SOURCE_SHA, result, state)

            self.assertTrue(state["upload_call_entered"])
            self.assertTrue(state["authoritative_readback_attempted"])
            self.assertIsNone(state["known_hf_revision"])
            self.assertEqual(child_environment["HF_TOKEN"], "test-hf-token")
            self.assertNotIn("GOVERNANCE_TOKEN", child_environment)
            boundary = json.loads(result.read_text(encoding="utf-8"))
            self.assertEqual(boundary["status"], "MUTATION_BOUNDARY_CROSSED")
            self.assertEqual(boundary["previous_hf_revision"], PARENT_SHA)
            self.assertIsNone(boundary["hf_revision"])

            failure = Path(temporary) / "unknown.json"
            write_failure_evidence(
                failure, SOURCE_SHA, TimeoutError("transport reset"), result, state
            )
            unknown = json.loads(failure.read_text(encoding="utf-8"))
            self.assertEqual(unknown["status"], "MUTATION_OUTCOME_UNKNOWN")
            self.assertIsNone(unknown["hf_revision"])

            durable_failure = Path(temporary) / "durable-unknown.json"
            write_failure_evidence(
                durable_failure,
                SOURCE_SHA,
                TimeoutError("process restarted"),
                result,
                None,
            )
            durable = json.loads(durable_failure.read_text(encoding="utf-8"))
            self.assertEqual(durable["status"], "MUTATION_OUTCOME_UNKNOWN")
            self.assertTrue(durable["upload_call_entered"])

            precondition_state: dict[str, object] = {}
            precondition_result = Path(temporary) / "precondition-result.json"
            with mock.patch(
                "scripts.deploy_hf_space.require_governed_main",
                side_effect=RuntimeError("governance unavailable"),
            ), self.assertRaises(RuntimeError):
                deploy_bundle(
                    bundle,
                    SOURCE_SHA,
                    precondition_result,
                    precondition_state,
                )
            before = Path(temporary) / "before.json"
            write_failure_evidence(
                before,
                SOURCE_SHA,
                RuntimeError("governance unavailable"),
                precondition_result,
                precondition_state,
            )
            self.assertEqual(
                json.loads(before.read_text(encoding="utf-8"))["status"],
                "FAILED_BEFORE_MUTATION",
            )

    def test_real_hanging_child_is_killed_with_bounded_unknown_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "entered"
            result = root / "result.json"
            result.write_bytes(canonical_json({
                "schema": "szl.hf-deploy-result/v1",
                "status": "MUTATION_BOUNDARY_CROSSED",
                "source_revision": SOURCE_SHA,
                "previous_hf_revision": PARENT_SHA,
                "hf_revision": None,
                "bundle_sha256": "d" * 64,
                "target": HF_REPO,
            }))
            command = [
                sys.executable,
                "-I",
                "-P",
                "-c",
                "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('entered'); time.sleep(60)",
                str(marker),
            ]
            state: dict[str, object] = {}
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                _run_killable_child(
                    command,
                    deadline=time.monotonic() + 0.25,
                    entered_marker=marker,
                    mutation_state=state,
                    environment=dict(os.environ),
                )
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertTrue(state["upload_call_entered"])
            failure = root / "failure.json"
            write_failure_evidence(failure, SOURCE_SHA, TimeoutError("child timeout"), result, state)
            evidence = json.loads(failure.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "MUTATION_OUTCOME_UNKNOWN")
            self.assertFalse(evidence["receipt_minted"])

    def test_upload_child_deadline_and_exception_paths_are_killed_and_reaped(self) -> None:
        marker = Path("entered-marker")
        command = [sys.executable, "-c", "pass"]
        state: dict[str, object] = {}
        with mock.patch(
            "scripts.deploy_hf_space._remaining_timeout",
            side_effect=RetryExhausted("deadline expired before spawn"),
        ), mock.patch("scripts.deploy_hf_space.subprocess.Popen") as popen, self.assertRaises(
            RetryExhausted
        ):
            _run_killable_child(
                command,
                deadline=0.0,
                entered_marker=marker,
                mutation_state=state,
            )
        popen.assert_not_called()

        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch(
            "scripts.deploy_hf_space._remaining_timeout",
            side_effect=[1.0, RetryExhausted("deadline expired after spawn")],
        ), mock.patch(
            "scripts.deploy_hf_space.subprocess.Popen", return_value=process
        ), self.assertRaises(RetryExhausted):
            _run_killable_child(
                command,
                deadline=1.0,
                entered_marker=marker,
                mutation_state={},
            )
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=1)

        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [RuntimeError("wait failed"), 0]
        with mock.patch(
            "scripts.deploy_hf_space._remaining_timeout",
            side_effect=[1.0, 1.0],
        ), mock.patch(
            "scripts.deploy_hf_space.subprocess.Popen", return_value=process
        ), self.assertRaisesRegex(RuntimeError, "wait failed"):
            _run_killable_child(
                command,
                deadline=1.0,
                entered_marker=marker,
                mutation_state={},
            )
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_args_list[-1], mock.call(timeout=1))

    def test_upload_child_environment_contains_only_the_hf_publication_token(self) -> None:
        parent_environment = {
            "HF_TOKEN": "hf-publication-token",
            "GOVERNANCE_TOKEN": "governance-token",
            "GITHUB_TOKEN": "github-token",
            "GH_TOKEN": "gh-token",
            "ACTIONS_RUNTIME_TOKEN": "actions-runtime-token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/oidc",
            "RUNNER_TEMP": "/tmp/runner",
        }
        with mock.patch.dict(os.environ, parent_environment, clear=True):
            child_environment = _hf_upload_child_environment()
        self.assertEqual(child_environment, {"HF_TOKEN": "hf-publication-token"})

        with mock.patch.dict(os.environ, {"GOVERNANCE_TOKEN": "governance-token"}, clear=True), self.assertRaisesRegex(
            RuntimeError, "HF_TOKEN is required"
        ):
            _hf_upload_child_environment()

        deployer = (
            Path(__file__).resolve().parents[1] / "scripts" / "deploy_hf_space.py"
        ).read_text(encoding="utf-8")
        self.assertIn("environment=child_environment", deployer)
        self.assertNotIn("environment=dict(os.environ)", deployer)

    def test_ambiguous_recovery_waits_for_parent_then_accepts_only_exact_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            manifest = build_bundle(bundle, SOURCE_SHA)
            with mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                side_effect=[{"sha": PARENT_SHA}, {"sha": PARENT_SHA}, {"sha": TARGET_SHA}],
            ), mock.patch(
                "scripts.deploy_hf_space._verify_exact_hf_revision",
                return_value=[],
            ) as verify, mock.patch("scripts.deploy_hf_space.time.sleep"):
                recovered = _recover_authoritative_revision(
                    bundle, manifest, PARENT_SHA, deadline=float("inf")
                )
            self.assertEqual(recovered, TARGET_SHA)
            verify.assert_called_once_with(
                bundle, manifest, TARGET_SHA, deadline=float("inf"), retry_byte_mismatch=False
            )

            with mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                return_value={"sha": TARGET_SHA},
            ), mock.patch(
                "scripts.deploy_hf_space._verify_exact_hf_revision",
                side_effect=RuntimeError("unrelated bytes"),
            ), self.assertRaisesRegex(RuntimeError, "ambiguous mutation conflict"):
                _recover_authoritative_revision(
                    bundle, manifest, PARENT_SHA, deadline=float("inf")
                )

    def test_attested_candidate_is_promoted_without_mutation_and_metadata_is_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = root / "result.json"
            measurement = root / "measurement.json"
            candidate = root / "candidate" / "hf-canonical-success-receipt.json"
            output = root / "hf-canonical-success-receipt.json"
            envelope_path = root / "hf-oidc-attestation-envelope.json"
            bundle = root / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            manifest = validate_bundle(bundle, SOURCE_SHA)
            attestation_bundle = root / "attestation.jsonl"
            attestation_bundle.write_bytes(b"signed-attestation-bundle\n")
            deployment_result = {
                "schema": "szl.hf-deploy-result/v1",
                "source_revision": SOURCE_SHA,
                "target": HF_REPO,
                "hf_revision": TARGET_SHA,
                "bundle_sha256": manifest["bundle_sha256"],
            }
            result.write_bytes(canonical_json(deployment_result))
            immutable_index = (bundle / "index.html").read_bytes()
            injection = LIVE_INJECTION_FIXTURE.read_bytes().rstrip(b"\r\n")
            public_index = normalize_public_static_index(
                inject_hf_window(immutable_index, injection),
                immutable_index,
            )
            measured = {
                "schema": "szl.hf-live-attestation/v2",
                "status": "MEASURED",
                "source": {"repository": SOURCE_REPO, "revision": SOURCE_SHA, "relation": SOURCE_RELATION},
                "source_revision": SOURCE_SHA,
                "hf_revision": TARGET_SHA,
                "target": HF_REPO,
                "runtime_stage": "RUNNING",
                "bundle_sha256": manifest["bundle_sha256"],
                "file_count": manifest["file_count"],
                "tree_sha256": "e" * 64,
                "public_index": public_index,
                "public_provenance": {
                    "verified": True,
                    "source_repository": SOURCE_REPO,
                    "source_revision": SOURCE_SHA,
                    "relation": SOURCE_RELATION,
                },
                "post_publication_main": {
                    "status": "AUTHORIZED_EXACT_PROTECTED_MAIN",
                    "source_revision": SOURCE_SHA,
                    "ruleset_ids": [GOVERNED_RULESET_ID],
                },
                "receipt_minted": False,
                "deployment_success": False,
            }
            measurement.write_bytes(canonical_json(measured))
            receipt = synthesize_candidate_receipt(
                candidate,
                SOURCE_SHA,
                bundle,
                result,
                measurement,
            )
            attested_bytes = candidate.read_bytes()
            self.assertTrue(receipt["receipt_minted"])
            self.assertTrue(receipt["deployment_success"])
            self.assertEqual(receipt["source"], measured["source"])
            self.assertEqual(receipt["hf_revision"], TARGET_SHA)
            self.assertEqual(receipt["runtime_stage"], "RUNNING")
            self.assertNotIn("attestation", receipt)

            envelope = finalize_attested_receipt(
                candidate,
                output,
                envelope_path,
                SOURCE_SHA,
                bundle,
                result,
                measurement,
                attestation_id="attestation-id",
                attestation_url="https://github.com/attestations/attestation-id",
                bundle_path=str(attestation_bundle),
            )
            self.assertFalse(candidate.exists())
            self.assertEqual(output.read_bytes(), attested_bytes)
            self.assertEqual(
                envelope["canonical_receipt"]["sha256"],
                hashlib.sha256(attested_bytes).hexdigest(),
            )
            self.assertEqual(
                envelope["attestation"]["bundle"]["sha256"],
                hashlib.sha256(attestation_bundle.read_bytes()).hexdigest(),
            )
            self.assertNotIn("attestation", json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual(envelope_path.read_bytes(), canonical_json(envelope))

            for field in ("receipt_minted", "deployment_success"):
                invalid = dict(measured)
                invalid[field] = True
                measurement.write_bytes(canonical_json(invalid))
                rejected = root / f"rejected-{field}.json"
                with self.assertRaisesRegex(RuntimeError, "not exactly source-bound and complete"):
                    synthesize_candidate_receipt(
                        rejected,
                        SOURCE_SHA,
                        bundle,
                        result,
                        measurement,
                    )
                self.assertFalse(rejected.exists())

            contradictions = {
                "public-index-digest": lambda value: value["public_index"].update(
                    {"normalized_sha256": "not-a-digest"}
                ),
                "public-index-wrong-normalized-digest": lambda value: value[
                    "public_index"
                ].update({"normalized_sha256": "f" * 64}),
                "public-index-wrong-normalized-bytes": lambda value: value[
                    "public_index"
                ].update({"normalized_bytes": value["public_index"]["normalized_bytes"] + 1}),
                "public-index-missing-field": lambda value: value["public_index"].pop(
                    "injection_bytes"
                ),
                "public-index-extra-field": lambda value: value["public_index"].update(
                    {"verified": True}
                ),
                "public-index-oversized-injection": lambda value: value[
                    "public_index"
                ].update({"injection_bytes": HF_WINDOW_MAX_INJECTION_BYTES + 1}),
                "post-main-status": lambda value: value["post_publication_main"].update(
                    {"status": "UNAUTHORIZED"}
                ),
                "post-main-revision": lambda value: value[
                    "post_publication_main"
                ].update({"source_revision": "f" * 40}),
                "post-main-ruleset": lambda value: value[
                    "post_publication_main"
                ].update({"ruleset_ids": []}),
                "post-main-extra-field": lambda value: value[
                    "post_publication_main"
                ].update({"protected": True}),
                "provenance-repository": lambda value: value[
                    "public_provenance"
                ].update({"source_repository": "szl-holdings/wrong"}),
                "provenance-revision": lambda value: value[
                    "public_provenance"
                ].update({"source_revision": "f" * 40}),
                "provenance-relation": lambda value: value[
                    "public_provenance"
                ].update({"relation": "UNRELATED"}),
            }
            for label, mutate in contradictions.items():
                invalid = json.loads(json.dumps(measured))
                mutate(invalid)
                measurement.write_bytes(canonical_json(invalid))
                rejected = root / f"rejected-{label}.json"
                with self.assertRaisesRegex(
                    RuntimeError, "not exactly source-bound and complete"
                ):
                    synthesize_candidate_receipt(
                        rejected,
                        SOURCE_SHA,
                        bundle,
                        result,
                        measurement,
                    )
                self.assertFalse(rejected.exists())

            measurement.write_bytes(canonical_json(measured))
            contradicted_result = dict(deployment_result)
            contradicted_result["bundle_sha256"] = "f" * 64
            result.write_bytes(canonical_json(contradicted_result))
            rejected = root / "rejected-bundle-mismatch.json"
            with self.assertRaisesRegex(RuntimeError, "cross.bundle_sha256"):
                synthesize_candidate_receipt(
                    rejected,
                    SOURCE_SHA,
                    bundle,
                    result,
                    measurement,
                )
            self.assertFalse(rejected.exists())
            result.write_bytes(canonical_json(deployment_result))

    def test_receipt_failure_upload_retry_is_enforced_and_oidc_failure_is_terminal(self) -> None:
        require_receipt_failure_artifact(True, "failure", "success")
        with self.assertRaisesRegex(RuntimeError, "was not preserved"):
            require_receipt_failure_artifact(True, "failure", "failure")

        outcomes = {
            "publish_outcome": "success",
            "artifact_outcome": "success",
            "candidate_receipt_outcome": "success",
            "oidc_outcome": "failure",
            "finalize_receipt_outcome": "skipped",
            "terminal_artifact_outcome": "skipped",
            "failure_synthesis_outcome": "success",
            "failure_artifact_primary_outcome": "failure",
            "failure_artifact_retry_outcome": "success",
            "deployment_failure_artifact_primary_outcome": "skipped",
            "deployment_failure_artifact_retry_outcome": "skipped",
        }
        with self.assertRaisesRegex(RuntimeError, "terminal publication evidence is incomplete"):
            enforce_terminal_evidence(**outcomes)
        outcomes["failure_artifact_retry_outcome"] = "failure"
        with self.assertRaisesRegex(RuntimeError, "was not preserved"):
            enforce_terminal_evidence(**outcomes)

    def test_complete_terminal_outcome_graph_and_unknowns_fail_closed(self) -> None:
        outcomes = {
            "publish_outcome": "success",
            "artifact_outcome": "success",
            "candidate_receipt_outcome": "success",
            "oidc_outcome": "success",
            "finalize_receipt_outcome": "success",
            "terminal_artifact_outcome": "success",
            "failure_synthesis_outcome": "skipped",
            "failure_artifact_primary_outcome": "skipped",
            "failure_artifact_retry_outcome": "skipped",
            "deployment_failure_receipt_outcome": "skipped",
            "deployment_failure_artifact_primary_outcome": "skipped",
            "deployment_failure_artifact_retry_outcome": "skipped",
        }
        self.assertEqual(
            enforce_terminal_evidence(**outcomes)["status"],
            "TERMINAL_PUBLICATION_EVIDENCE_COMPLETE",
        )

        for failed_stage in (
            "artifact_outcome",
            "candidate_receipt_outcome",
            "oidc_outcome",
            "finalize_receipt_outcome",
            "terminal_artifact_outcome",
        ):
            failed = dict(outcomes)
            failed[failed_stage] = "failure"
            failed["failure_synthesis_outcome"] = "success"
            failed["failure_artifact_primary_outcome"] = "success"
            with self.subTest(failed_stage=failed_stage), self.assertRaisesRegex(
                RuntimeError, "terminal publication evidence is incomplete"
            ):
                enforce_terminal_evidence(**failed)

        primary = dict(outcomes)
        primary["oidc_outcome"] = "failure"
        primary["failure_synthesis_outcome"] = "success"
        primary["failure_artifact_primary_outcome"] = "success"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            enforce_terminal_evidence(**primary)

        synthesis_failed = dict(primary)
        synthesis_failed["failure_synthesis_outcome"] = "failure"
        with self.assertRaisesRegex(RuntimeError, "synthesis did not succeed"):
            enforce_terminal_evidence(**synthesis_failed)

        publish_failed = dict(outcomes)
        publish_failed["publish_outcome"] = "failure"
        publish_failed["deployment_failure_receipt_outcome"] = "success"
        publish_failed["deployment_failure_artifact_primary_outcome"] = "success"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            enforce_terminal_evidence(**publish_failed)

        deployment_evidence_missing = dict(publish_failed)
        deployment_evidence_missing["deployment_failure_artifact_primary_outcome"] = "failure"
        deployment_evidence_missing["deployment_failure_artifact_retry_outcome"] = "failure"
        with self.assertRaisesRegex(RuntimeError, "failed-deployment evidence was not preserved"):
            enforce_terminal_evidence(**deployment_evidence_missing)

        for outcome_name in outcomes:
            malformed = dict(outcomes)
            malformed[outcome_name] = "unknown-provider-state"
            with self.subTest(outcome_name=outcome_name), self.assertRaisesRegex(
                RuntimeError, "outcome is malformed"
            ):
                enforce_terminal_evidence(**malformed)

    def test_failed_deployment_requires_valid_receipt_not_existing_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = root / "hf-deploy-result.json"
            result.write_bytes(canonical_json({"status": "MUTATION_BOUNDARY_CROSSED"}))
            failure = root / "hf-deploy-failure.json"

            with self.assertRaisesRegex(RuntimeError, "missing or unreadable"):
                validate_deployment_failure_receipt(failure, SOURCE_SHA)
            failure.write_bytes(b"")
            with self.assertRaisesRegex(RuntimeError, "empty"):
                validate_deployment_failure_receipt(failure, SOURCE_SHA)
            failure.write_bytes(canonical_json({"schema": "szl.hf-deploy-failure/v2"}))
            with self.assertRaisesRegex(RuntimeError, "fields are not exact"):
                validate_deployment_failure_receipt(failure, SOURCE_SHA)

            write_failure_evidence(
                failure,
                SOURCE_SHA,
                RuntimeError("publication failed"),
                result,
                {"upload_call_entered": False},
            )
            receipt = validate_deployment_failure_receipt(failure, SOURCE_SHA)
            self.assertEqual(receipt["status"], "FAILED_BEFORE_MUTATION")

            outcomes = {
                "publish_outcome": "failure",
                "artifact_outcome": "skipped",
                "candidate_receipt_outcome": "skipped",
                "oidc_outcome": "skipped",
                "finalize_receipt_outcome": "skipped",
                "terminal_artifact_outcome": "skipped",
                "failure_synthesis_outcome": "skipped",
                "failure_artifact_primary_outcome": "skipped",
                "failure_artifact_retry_outcome": "skipped",
                "deployment_failure_receipt_outcome": "failure",
                "deployment_failure_artifact_primary_outcome": "success",
                "deployment_failure_artifact_retry_outcome": "skipped",
            }
            with self.assertRaisesRegex(RuntimeError, "validation did not succeed"):
                enforce_terminal_evidence(**outcomes)

    def test_failure_receipt_rejects_all_status_marker_contradictions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failure = root / "failure.json"

            write_failure_evidence(
                failure,
                SOURCE_SHA,
                RuntimeError("post-mutation failure"),
                root / "missing-result.json",
                {
                    "upload_call_entered": True,
                    "authoritative_readback_attempted": False,
                    "known_hf_revision": TARGET_SHA,
                },
            )
            partial = validate_deployment_failure_receipt(failure, SOURCE_SHA)
            self.assertEqual(partial["status"], "PARTIAL_AFTER_MUTATION")
            partial["upload_call_entered"] = False
            failure.write_bytes(canonical_json(partial))
            with self.assertRaisesRegex(RuntimeError, "lacks its mutation marker"):
                validate_deployment_failure_receipt(failure, SOURCE_SHA)

            write_failure_evidence(
                failure,
                SOURCE_SHA,
                TimeoutError("mutation result unknown"),
                root / "missing-result.json",
                {
                    "upload_call_entered": True,
                    "authoritative_readback_attempted": True,
                    "known_hf_revision": None,
                },
            )
            unknown = validate_deployment_failure_receipt(failure, SOURCE_SHA)
            self.assertEqual(unknown["status"], "MUTATION_OUTCOME_UNKNOWN")
            unknown["authoritative_readback_attempted"] = False
            failure.write_bytes(canonical_json(unknown))
            with self.assertRaisesRegex(RuntimeError, "lacks authoritative readback"):
                validate_deployment_failure_receipt(failure, SOURCE_SHA)

    def test_bounded_external_action_is_killed_and_reaped_at_deadline(self) -> None:
        command = [sys.executable, "-I", "-P", "-c", "import time; time.sleep(60)"]
        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, "absolute deadline"):
            _run_bounded_process(
                command,
                deadline=time.monotonic() + 0.25,
                max_seconds=30,
                environment=dict(os.environ),
            )
        self.assertLess(time.monotonic() - started, 2.0)

    def test_terminal_cleanup_is_behavioral_and_nonrecursive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = [root / "candidate", root / "receipt", root / "envelope"]
            for path in files:
                path.write_bytes(b"terminal-looking-bytes")
            self.assertTrue(cleanup_terminal_success_files(files))
            self.assertTrue(all(not path.exists() for path in files))
            directory = root / "directory"
            directory.mkdir()
            self.assertFalse(cleanup_terminal_success_files([directory]))
            self.assertTrue(directory.is_dir())

    def test_workflow_stage_failure_is_machine_readable_and_never_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = root / "result.json"
            receipt = root / "receipt.json"
            output = root / "failure.json"
            result.write_bytes(
                canonical_json(
                    {
                        "schema": "szl.hf-deploy-result/v1",
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "hf_revision": TARGET_SHA,
                        "bundle_sha256": "d" * 64,
                    }
                )
            )
            receipt.write_bytes(
                canonical_json(
                    {
                    "schema": "szl.hf-live-attestation/v2",
                    "status": "MEASURED",
                        "source_revision": SOURCE_SHA,
                        "hf_revision": TARGET_SHA,
                        "target": HF_REPO,
                        "source": {
                            "repository": SOURCE_REPO,
                            "revision": SOURCE_SHA,
                            "relation": SOURCE_RELATION,
                        },
                        "runtime_stage": "RUNNING",
                        "bundle_sha256": "d" * 64,
                        "tree_sha256": "e" * 64,
                        "file_count": 10,
                        "public_index": {
                            "transformation": "HF_WINDOW_HUGGINGFACE_HEAD_INJECTION_V1",
                            "normalized_bytes": 128,
                            "normalized_sha256": "8" * 64,
                            "injection_bytes": 64,
                            "injection_sha256": "9" * 64,
                        },
                        "public_provenance": {
                            "verified": True,
                            "source_repository": SOURCE_REPO,
                            "source_revision": SOURCE_SHA,
                            "relation": SOURCE_RELATION,
                        },
                        "post_publication_main": {
                            "status": "AUTHORIZED_EXACT_PROTECTED_MAIN",
                            "source_revision": SOURCE_SHA,
                            "ruleset_ids": [GOVERNED_RULESET_ID],
                        },
                        "receipt_minted": False,
                        "deployment_success": False,
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
                candidate_receipt_outcome="success",
                oidc_outcome="failure",
            )
            self.assertEqual(
                evidence["status"], "FAILED_AFTER_LOCAL_MEASUREMENT"
            )
            self.assertEqual(evidence["hf_revision"], TARGET_SHA)
            self.assertFalse(evidence["receipt_minted"])
            self.assertFalse(evidence["deployment_success"])
            self.assertEqual(evidence["candidate_receipt_outcome"], "success")
            self.assertEqual(
                output.read_bytes(), canonical_json(evidence)
            )

    def test_workflow_stage_failure_always_writes_sanitized_minimal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                ("missing", root / "missing-result", root / "missing-measurement"),
                ("invalid", root / "invalid-result", root / "invalid-measurement"),
            )
            cases[1][1].write_bytes(b"{not-json HF_TOKEN=secret")
            cases[1][2].write_bytes(b"[]")
            for label, result, measurement in cases:
                output = root / f"{label}-failure.json"
                evidence = write_workflow_stage_failure(
                    output,
                    SOURCE_SHA,
                    result,
                    measurement,
                    failure_stage="CANDIDATE_RECEIPT_SYNTHESIS",
                    artifact_outcome="success",
                    candidate_receipt_outcome="failure",
                    oidc_outcome="skipped",
                )
                self.assertEqual(evidence["status"], "WORKFLOW_STAGE_FAILURE")
                self.assertFalse(evidence["local_measurement_contract_valid"])
                self.assertNotIn("hf_revision", evidence)
                self.assertNotIn("local_measured_receipt_sha256", evidence)
                self.assertNotIn("HF_TOKEN", output.read_text(encoding="utf-8"))
                self.assertEqual(output.read_bytes(), canonical_json(evidence))

            unreadable_result = root / "unreadable-result"
            unreadable_measurement = root / "unreadable-measurement"
            output = root / "unreadable-failure.json"
            original_read_bytes = Path.read_bytes

            def fail_reads(path: Path) -> bytes:
                if path in {unreadable_result, unreadable_measurement}:
                    raise PermissionError("HF_TOKEN=secret")
                return original_read_bytes(path)

            with mock.patch.object(Path, "read_bytes", fail_reads):
                evidence = write_workflow_stage_failure(
                    output,
                    SOURCE_SHA,
                    unreadable_result,
                    unreadable_measurement,
                    failure_stage="CANDIDATE_RECEIPT_SYNTHESIS",
                    artifact_outcome="success",
                    candidate_receipt_outcome="failure",
                    oidc_outcome="skipped",
                )
            self.assertEqual(evidence["result_input_status"], "UNREADABLE")
            self.assertEqual(evidence["measurement_input_status"], "UNREADABLE")
            self.assertNotIn("HF_TOKEN", output.read_text(encoding="utf-8"))

class TerminalEvidenceEnvelopeContractTests(unittest.TestCase):
    def test_job_envelope_exports_one_absolute_deadline_with_explicit_slack(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "hf-space-deploy.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("timeout-minutes: 60", workflow)
        self.assertIn("HF_TERMINAL_DEADLINE_EPOCH", workflow)
        self.assertIn("$((started_at + 3300))", workflow)
        self.assertIn("HF_TERMINAL_DEADLINE_EPOCH - 600", workflow)
        self.assertIn("max_pre_mutation_seconds=900", workflow)
        self.assertIn("operation_remaining", workflow)
        self.assertIn("operation_remaining < 1800", workflow)
        self.assertIn("10m terminal-evidence, and 5m runner slack", workflow)
        mutation = workflow.index("Publish and measure exact protected-main bundle")
        terminal = workflow[mutation:]
        self.assertNotIn("uses: actions/attest-build-provenance@", terminal)
        self.assertNotIn("uses: actions/upload-artifact@", terminal)
        self.assertIn("bounded-action", terminal)
        self.assertIn("--action attest --reserve-seconds 300", terminal)
        self.assertIn("--action upload --reserve-seconds 300", terminal)
        self.assertIn("--action upload --reserve-seconds 60", terminal)
        self.assertIn("Fetch pinned bounded attestation action before mutation", workflow)
        self.assertIn("Fetch pinned bounded artifact action before mutation", workflow)
        self.assertIn("59d89421af93a897026c735860bf21b6eb4f7b26", workflow)
        self.assertIn("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)
        self.assertIn(
            "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
            workflow,
        )
        self.assertIn('node-version: "24.19.0"', workflow)

    def test_exact_failure_receipt_is_required_before_both_upload_attempts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "hf-space-deploy.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("id: deployment-failure-receipt", workflow)
        self.assertIn("validate-deployment-failure", workflow)
        self.assertEqual(
            workflow.count("steps.deployment-failure-receipt.outcome == 'success'"),
            2,
        )
        self.assertIn("hf-space-deployment-failure-receipt-primary", workflow)
        self.assertIn("hf-space-deployment-failure-receipt-retry", workflow)
        self.assertIn("hf-space-deployment-failure-supporting", workflow)
        preflight = workflow.index("id: deployment-failure-receipt")
        primary = workflow.index("id: deployment-failure-artifact-primary")
        retry = workflow.index("id: deployment-failure-artifact-retry")
        self.assertLess(preflight, primary)
        self.assertLess(primary, retry)

if __name__ == "__main__":
    unittest.main()
    normalize_public_static_index,
    synthesize_oidc_receipt,
