from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "github_governed_merge.py"
SPEC = importlib.util.spec_from_file_location("kernel_github_governed_merge", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
GOVERNANCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GOVERNANCE
SPEC.loader.exec_module(GOVERNANCE)

SOURCE_REPOSITORY = "szl-holdings/szl-kernels-live"
SOURCE_SHA = "a" * 40
PARENT_SHA = "b" * 40
PR_HEAD_SHA = "c" * 40
RELEASE_RUN_ID = 98
BOUNDARY_RUN_ID = 99


def governed_merge_evidence(source_sha: str = SOURCE_SHA) -> dict:
    return {
        "schema": "szl.github-governed-merge/v3",
        "status": GOVERNANCE.GOVERNED_MAIN_STATUS,
        "source_revision": source_sha,
        "repository": {
            "default_branch": "main",
            "full_name": SOURCE_REPOSITORY,
            "id": GOVERNANCE.REPOSITORY_ID,
        },
        "push": {"before": PARENT_SHA, "after": source_sha},
        "pull_request": {
            "base_revision": PARENT_SHA,
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "merge_revision": source_sha,
            "merged_at": "2026-08-10T00:00:00Z",
            "merged_by": "solo-owner",
            "number": 7,
        },
        "required_checks": [
            {
                "app_id": GOVERNANCE.GITHUB_ACTIONS_INTEGRATION_ID,
                "check_run_id": index + 10,
                "conclusion": "success",
                "head_revision": PR_HEAD_SHA,
                "job_id": index + 10,
                "name": name,
                "workflow_run_attempt": 1,
                "workflow_run_id": RELEASE_RUN_ID,
            }
            for index, name in enumerate(sorted(GOVERNANCE.REQUIRED_STATUS_CONTEXTS))
        ],
        "release_workflow": {
            "base_revision": PARENT_SHA,
            "conclusion": "success",
            "event": "pull_request",
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "name": GOVERNANCE.RELEASE_WORKFLOW_NAME,
            "path": GOVERNANCE.RELEASE_WORKFLOW_PATH,
            "pull_request_number": 7,
            "repository_id": GOVERNANCE.REPOSITORY_ID,
            "run_attempt": 1,
            "run_id": RELEASE_RUN_ID,
            "status": "completed",
            "workflow_id": GOVERNANCE.RELEASE_WORKFLOW_ID,
            "jobs": [
                {
                    "conclusion": "success",
                    "head_revision": PR_HEAD_SHA,
                    "job_id": index + 10,
                    "name": name,
                    "run_attempt": 1,
                    "run_id": RELEASE_RUN_ID,
                    "status": "completed",
                }
                for index, name in enumerate(sorted(GOVERNANCE.REQUIRED_STATUS_CONTEXTS))
            ],
        },
        "required_workflow": {
            "base_revision": PARENT_SHA,
            "conclusion": "success",
            "event": "pull_request",
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "name": GOVERNANCE.REQUIRED_WORKFLOW_NAME,
            "path": GOVERNANCE.REQUIRED_WORKFLOW_PATH,
            "pull_request_number": 7,
            "repository_id": GOVERNANCE.REPOSITORY_ID,
            "run_attempt": 1,
            "run_id": BOUNDARY_RUN_ID,
            "status": "completed",
            "workflow_id": GOVERNANCE.REQUIRED_WORKFLOW_ID,
            "jobs": [
                {
                    "conclusion": "success",
                    "head_revision": PR_HEAD_SHA,
                    "job_id": 20,
                    "name": "external-release-boundary",
                    "run_attempt": 1,
                    "run_id": BOUNDARY_RUN_ID,
                    "status": "completed",
                }
            ],
        },
        "associated_pull_request_inventory": {
            "candidate_count": 1,
            "pages": 1,
            "total_count": 1,
        },
    }


def write_push_event(path: Path, before: str = PARENT_SHA) -> None:
    path.write_text(
        json.dumps(
            {
                "after": SOURCE_SHA,
                "before": before,
                "ref": "refs/heads/main",
                "repository": {
                    "default_branch": "main",
                    "full_name": SOURCE_REPOSITORY,
                    "id": GOVERNANCE.REPOSITORY_ID,
                },
            }
        ),
        encoding="utf-8",
    )


def run_pull(number: int = 7) -> dict:
    return {
        "base": {
            "ref": "main",
            "sha": PARENT_SHA,
            "repo": {"full_name": SOURCE_REPOSITORY, "id": GOVERNANCE.REPOSITORY_ID},
        },
        "head": {
            "ref": "release-candidate",
            "sha": PR_HEAD_SHA,
            "repo": {"full_name": SOURCE_REPOSITORY, "id": GOVERNANCE.REPOSITORY_ID},
        },
        "number": number,
        "url": f"https://api.github.test/repos/{SOURCE_REPOSITORY}/pulls/{number}",
    }


def guard_responder(
    *,
    boundary_conclusion: str = "success",
    check_app_id: int | None = None,
    release_conclusion: str = "success",
    stale_boundary_success: bool = False,
    stale_check_success: bool = False,
    misbound_boundary: bool = False,
    omit_check: bool = False,
    release_attempt: int = 1,
    release_job_attempt: int | None = None,
    omit_release_job: bool = False,
    job_url_mismatch: bool = False,
    required_job_total_delta: int = 0,
):
    app_id = (
        GOVERNANCE.GITHUB_ACTIONS_INTEGRATION_ID
        if check_app_id is None
        else check_app_id
    )
    pull = {
        "id": 70,
        "number": 7,
        "state": "closed",
        "merged": True,
        "merged_at": "2026-08-10T00:00:00Z",
        "merge_commit_sha": SOURCE_SHA,
        "merged_by": {"login": "solo-owner"},
        "base": {
            "ref": "main",
            "sha": PARENT_SHA,
            "repo": {"full_name": SOURCE_REPOSITORY, "id": GOVERNANCE.REPOSITORY_ID},
        },
        "head": {
            "ref": "release-candidate",
            "sha": PR_HEAD_SHA,
            "repo": {"full_name": SOURCE_REPOSITORY, "id": GOVERNANCE.REPOSITORY_ID},
        },
    }

    def workflow_run(
        run_id: int,
        workflow_id: int,
        name: str,
        path: str,
        conclusion: str,
        *,
        pull_number: int = 7,
        run_attempt: int = 1,
    ) -> dict:
        return {
            "id": run_id,
            "workflow_id": workflow_id,
            "name": name,
            "path": path,
            "event": "pull_request",
            "head_sha": PR_HEAD_SHA,
            "status": "completed",
            "conclusion": conclusion,
            "run_attempt": run_attempt,
            "repository": {
                "full_name": SOURCE_REPOSITORY,
                "id": GOVERNANCE.REPOSITORY_ID,
            },
            "pull_requests": [run_pull(pull_number)],
        }

    def respond(url: str, token: str = "", _timeout: float = 30.0) -> object:
        if token != "github-test-token":
            raise AssertionError("guard omitted its GitHub credential")
        if url.endswith(f"/repos/{SOURCE_REPOSITORY}"):
            return {
                "id": GOVERNANCE.REPOSITORY_ID,
                "full_name": SOURCE_REPOSITORY,
                "default_branch": "main",
            }
        if url.endswith(f"/repos/{SOURCE_REPOSITORY}/branches/main"):
            return {"commit": {"sha": SOURCE_SHA}, "protected": True}
        if urllib.parse.urlparse(url).path.endswith(
            f"/repos/{SOURCE_REPOSITORY}/commits/{SOURCE_SHA}/pulls"
        ):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            if query.get("per_page") != ["100"] or query.get("page") != ["1"]:
                raise AssertionError("associated PR query is not bounded and paginated")
            return [pull]
        if url.endswith(f"/repos/{SOURCE_REPOSITORY}/pulls/7"):
            return pull
        if f"/repos/{SOURCE_REPOSITORY}/actions/runs?" in url:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            if query.get("head_sha") != [PR_HEAD_SHA] or query.get("event") != [
                "pull_request"
            ]:
                raise AssertionError("workflow query is not exact")
            runs = [
                workflow_run(
                    RELEASE_RUN_ID,
                    GOVERNANCE.RELEASE_WORKFLOW_ID,
                    GOVERNANCE.RELEASE_WORKFLOW_NAME,
                    GOVERNANCE.RELEASE_WORKFLOW_PATH,
                    release_conclusion,
                    run_attempt=release_attempt,
                )
            ]
            boundary_run_id = BOUNDARY_RUN_ID
            if stale_boundary_success:
                runs.append(
                    workflow_run(
                        BOUNDARY_RUN_ID,
                        GOVERNANCE.REQUIRED_WORKFLOW_ID,
                        GOVERNANCE.REQUIRED_WORKFLOW_NAME,
                        GOVERNANCE.REQUIRED_WORKFLOW_PATH,
                        "success",
                    )
                )
                boundary_run_id += 100
            runs.append(
                workflow_run(
                    boundary_run_id,
                    GOVERNANCE.REQUIRED_WORKFLOW_ID,
                    GOVERNANCE.REQUIRED_WORKFLOW_NAME,
                    GOVERNANCE.REQUIRED_WORKFLOW_PATH,
                    boundary_conclusion,
                    pull_number=8 if misbound_boundary else 7,
                )
            )
            return {"total_count": len(runs), "workflow_runs": runs}
        if f"/actions/runs/{RELEASE_RUN_ID}/attempts/{release_attempt}/jobs" in url:
            attempt = release_attempt if release_job_attempt is None else release_job_attempt
            names = sorted(GOVERNANCE.REQUIRED_STATUS_CONTEXTS)
            if omit_release_job:
                names = names[:-1]
            jobs = [
                {
                    "id": index + 10,
                    "name": name,
                    "run_id": RELEASE_RUN_ID,
                    "run_attempt": attempt,
                    "head_sha": PR_HEAD_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": (
                        f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/"
                        f"{RELEASE_RUN_ID}/job/{index + 10 + (100 if job_url_mismatch else 0)}"
                    ),
                }
                for index, name in enumerate(names)
            ]
            return {"total_count": len(jobs), "jobs": jobs}
        if f"/actions/runs/{BOUNDARY_RUN_ID}/attempts/1/jobs" in url:
            jobs = [
                {
                    "id": 20,
                    "name": "external-release-boundary",
                    "run_id": BOUNDARY_RUN_ID,
                    "run_attempt": 1,
                    "head_sha": PR_HEAD_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": (
                        f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/"
                        f"{BOUNDARY_RUN_ID}/job/20"
                    ),
                }
            ]
            return {"total_count": len(jobs) + required_job_total_delta, "jobs": jobs}
        if url.endswith(
            f"/repos/{SOURCE_REPOSITORY}/commits/{PR_HEAD_SHA}/check-runs?per_page=100"
        ):
            checks = []
            names = sorted(GOVERNANCE.REQUIRED_STATUS_CONTEXTS)
            if omit_check:
                names = names[:-1]
            for index, name in enumerate(names):
                check_id = index + 10
                checks.append(
                    {
                        "id": check_id,
                        "name": name,
                        "head_sha": PR_HEAD_SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "app": {"id": app_id},
                        "details_url": (
                            f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/"
                            f"{RELEASE_RUN_ID}/job/{check_id}"
                        ),
                    }
                )
                if stale_check_success:
                    latest_id = check_id + 100
                    checks.append(
                        {
                            "id": latest_id,
                            "name": name,
                            "head_sha": PR_HEAD_SHA,
                            "status": "completed",
                            "conclusion": "failure",
                            "app": {"id": app_id},
                            "details_url": (
                                f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/"
                                f"{RELEASE_RUN_ID}/job/{latest_id}"
                            ),
                        }
                    )
            return {"total_count": len(checks), "check_runs": checks}
        raise AssertionError(f"unexpected guard URL: {url}")

    return respond


class GovernedMergeContractTests(unittest.TestCase):
    def test_canonical_receipt_is_exact_and_source_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authorization.json"
            receipt = governed_merge_evidence()
            path.write_bytes(GOVERNANCE.canonical_json(receipt))
            self.assertEqual(GOVERNANCE.load_governed_merge(path, SOURCE_SHA), receipt)

            path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(GOVERNANCE.GovernanceError, "not canonical"):
                GOVERNANCE.load_governed_merge(path, SOURCE_SHA)

            path.write_bytes(
                GOVERNANCE.canonical_json(governed_merge_evidence("d" * 40))
            )
            with self.assertRaises(GOVERNANCE.GovernanceError):
                GOVERNANCE.load_governed_merge(path, SOURCE_SHA)

            spoofed = governed_merge_evidence()
            spoofed["required_workflow"]["workflow_id"] += 1
            path.write_bytes(GOVERNANCE.canonical_json(spoofed))
            with self.assertRaises(GOVERNANCE.GovernanceError):
                GOVERNANCE.load_governed_merge(path, SOURCE_SHA)

            incomplete = governed_merge_evidence()
            incomplete["required_checks"] = incomplete["required_checks"][:-1]
            path.write_bytes(GOVERNANCE.canonical_json(incomplete))
            with self.assertRaises(GOVERNANCE.GovernanceError):
                GOVERNANCE.load_governed_merge(path, SOURCE_SHA)

            missing_attempt = governed_merge_evidence()
            missing_attempt["required_checks"][0].pop("workflow_run_attempt")
            path.write_bytes(GOVERNANCE.canonical_json(missing_attempt))
            with self.assertRaises(GOVERNANCE.GovernanceError):
                GOVERNANCE.load_governed_merge(path, SOURCE_SHA)

            duplicate_job = governed_merge_evidence()
            duplicate_job["release_workflow"]["jobs"].append(
                dict(duplicate_job["release_workflow"]["jobs"][0])
            )
            path.write_bytes(GOVERNANCE.canonical_json(duplicate_job))
            with self.assertRaises(GOVERNANCE.GovernanceError):
                GOVERNANCE.load_governed_merge(path, SOURCE_SHA)

    def test_guard_authorizes_only_the_exact_merged_pr_tuple(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            output_path = root / "governed-merge.json"
            failure_path = root / "failure.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    GOVERNANCE, "_request_json", side_effect=guard_responder()
                ):
                    result = GOVERNANCE.require_governed_main(
                        SOURCE_SHA,
                        event_path,
                        output_path,
                        failure_output_path=failure_path,
                    )
            self.assertEqual(result, governed_merge_evidence())
            self.assertEqual(output_path.read_bytes(), GOVERNANCE.canonical_json(result))
            self.assertFalse(failure_path.exists())

    def test_guard_rejects_direct_stale_spoofed_and_incomplete_evidence(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        variants = (
            ("failed-boundary", guard_responder(boundary_conclusion="failure")),
            (
                "stale-boundary-success",
                guard_responder(
                    boundary_conclusion="failure", stale_boundary_success=True
                ),
            ),
            ("stale-check-success", guard_responder(stale_check_success=True)),
            ("misbound-boundary", guard_responder(misbound_boundary=True)),
            ("failed-release", guard_responder(release_conclusion="failure")),
            ("spoofed-check-app", guard_responder(check_app_id=99)),
            ("incomplete-check-inventory", guard_responder(omit_check=True)),
            (
                "mixed-attempt-jobs",
                guard_responder(release_attempt=2, release_job_attempt=1),
            ),
            ("missing-release-job", guard_responder(omit_release_job=True)),
            ("job-url-mismatch", guard_responder(job_url_mismatch=True)),
            (
                "incomplete-required-job-inventory",
                guard_responder(required_job_total_delta=1),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                for label, responder in variants:
                    with self.subTest(label=label):
                        output = root / f"{label}.json"
                        failure = root / f"{label}-failure.json"
                        with mock.patch.object(
                            GOVERNANCE, "_request_json", side_effect=responder
                        ):
                            with self.assertRaises(GOVERNANCE.GovernanceError):
                                GOVERNANCE.require_governed_main(
                                    SOURCE_SHA,
                                    event_path,
                                    output,
                                    failure_output_path=failure,
                                )
                        self.assertFalse(output.exists())
                        self.assertTrue(failure.is_file())

            write_push_event(event_path, before="e" * 40)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    GOVERNANCE, "_request_json", side_effect=guard_responder()
                ):
                    with self.assertRaises(GOVERNANCE.GovernanceError):
                        GOVERNANCE.require_governed_main(
                            SOURCE_SHA,
                            event_path,
                            root / "direct.json",
                            failure_output_path=root / "direct-failure.json",
                        )

    def test_missing_token_fails_before_any_api_request(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(GOVERNANCE, "_request_json") as request_json:
                    with self.assertRaisesRegex(
                        GOVERNANCE.GovernanceError, "GITHUB_TOKEN is required"
                    ):
                        GOVERNANCE.require_governed_main(
                            SOURCE_SHA, event_path, root / "authorization.json"
                        )
            request_json.assert_not_called()

    def test_associated_pr_pagination_is_complete_and_ambiguous_fails_closed(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        base = guard_responder()
        candidate = base(
            f"https://api.github.test/repos/{SOURCE_REPOSITORY}/pulls/7",
            "github-test-token",
        )
        non_candidates = [
            {"id": 1000 + index, "number": 1000 + index, "state": "open"}
            for index in range(100)
        ]

        def responder(mode: str):
            def respond(url: str, token: str = "", timeout: float = 30.0):
                parsed = urllib.parse.urlparse(url)
                if parsed.path.endswith(f"/commits/{SOURCE_SHA}/pulls"):
                    page = urllib.parse.parse_qs(parsed.query).get("page")
                    if page == ["1"]:
                        return non_candidates
                    if page == ["2"]:
                        if mode == "success":
                            return [candidate]
                        second = json.loads(json.dumps(candidate))
                        second["id"] = 71
                        second["number"] = 8
                        return [candidate, second]
                    raise AssertionError("unexpected associated PR page")
                return base(url, token, timeout)

            return respond

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            write_push_event(event)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    GOVERNANCE, "_request_json", side_effect=responder("success")
                ):
                    evidence = GOVERNANCE.require_governed_main(
                        SOURCE_SHA, event, root / "success.json"
                    )
                self.assertEqual(
                    evidence["associated_pull_request_inventory"],
                    {"candidate_count": 1, "pages": 2, "total_count": 101},
                )
                with mock.patch.object(
                    GOVERNANCE, "_request_json", side_effect=responder("ambiguous")
                ):
                    with self.assertRaisesRegex(
                        GOVERNANCE.GovernanceError, "unambiguous"
                    ):
                        GOVERNANCE.require_governed_main(
                            SOURCE_SHA, event, root / "ambiguous.json"
                        )

    def test_associated_pr_page_cap_fails_closed(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        base = guard_responder()

        def respond(url: str, token: str = "", timeout: float = 30.0):
            parsed = urllib.parse.urlparse(url)
            if parsed.path.endswith(f"/commits/{SOURCE_SHA}/pulls"):
                page = int(urllib.parse.parse_qs(parsed.query)["page"][0])
                return [
                    {"id": page * 1000 + index, "number": page * 1000 + index, "state": "open"}
                    for index in range(100)
                ]
            return base(url, token, timeout)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            write_push_event(event)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(GOVERNANCE, "_request_json", side_effect=respond):
                    with self.assertRaisesRegex(
                        GOVERNANCE.GovernanceError, "page bound"
                    ):
                        GOVERNANCE.require_governed_main(
                            SOURCE_SHA, event, root / "bounded.json"
                        )

    def test_associated_pr_inventory_drift_fails_closed(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        for drift_read in (2, 3):
            base = guard_responder()
            associated_reads = 0

            def respond(url: str, token: str = "", timeout: float = 30.0):
                nonlocal associated_reads
                if urllib.parse.urlparse(url).path.endswith(
                    f"/commits/{SOURCE_SHA}/pulls"
                ):
                    associated_reads += 1
                    rows = base(url, token, timeout)
                    if associated_reads == drift_read:
                        return [*rows, {"id": 999, "number": 999, "state": "open"}]
                    return rows
                return base(url, token, timeout)

            with self.subTest(drift_read=drift_read), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                event = root / "event.json"
                write_push_event(event)
                with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                    GOVERNANCE, "_request_json", side_effect=respond
                ):
                    with self.assertRaisesRegex(GOVERNANCE.GovernanceError, "inventory drifted"):
                        GOVERNANCE.require_governed_main(
                            SOURCE_SHA, event, root / "drifted.json"
                        )

    def test_final_protected_main_drift_fails_closed(self) -> None:
        environment = {
            "GITHUB_REPOSITORY": SOURCE_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        base = guard_responder()
        branch_reads = 0

        def respond(url: str, token: str = "", timeout: float = 30.0):
            nonlocal branch_reads
            if url.endswith(f"/repos/{SOURCE_REPOSITORY}/branches/main"):
                branch_reads += 1
                if branch_reads == 2:
                    return {"commit": {"sha": "f" * 40}, "protected": True}
            return base(url, token, timeout)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            write_push_event(event)
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                GOVERNANCE, "_request_json", side_effect=respond
            ):
                with self.assertRaisesRegex(GOVERNANCE.GovernanceError, "main drifted"):
                    GOVERNANCE.require_governed_main(
                        SOURCE_SHA, event, root / "stale.json"
                    )

    def test_workflows_enforce_four_non_overlapping_privilege_domains(self) -> None:
        release = (ROOT / ".github" / "workflows" / "hf-space-deploy.yml").read_text(
            encoding="utf-8"
        )
        contracts = (ROOT / ".github" / "workflows" / "kernel-contracts.yml").read_text(
            encoding="utf-8"
        )

        def job(text: str, name: str, next_name: str | None) -> str:
            start = text.index(f"  {name}:\n")
            if next_name is None:
                return text[start:]
            return text[start : text.index(f"  {next_name}:\n", start)]

        authorize = job(release, "authorize", "deploy")
        deploy = job(release, "deploy", "measure")
        measure = job(release, "measure", "attest")
        attest = job(release, "attest", None)
        self.assertNotIn("secrets.HF_TOKEN", authorize)
        self.assertIn('HF_TOKEN: ""', authorize)
        self.assertIn("permissions: {}", deploy)
        self.assertIn("HF_TOKEN:", deploy)
        self.assertIn("secrets.HF_TOKEN", deploy)
        self.assertIn('GITHUB_TOKEN: ""', deploy)
        self.assertIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN: ""', deploy)
        self.assertIn('HF_TOKEN: ""', measure)
        self.assertIn("actions: read", measure)
        self.assertNotIn("secrets.HF_TOKEN", measure)
        self.assertIn("id-token: write", attest)
        self.assertIn("attestations: write", attest)
        self.assertIn('HF_TOKEN: ""', attest)
        self.assertNotIn("secrets.HF_TOKEN", attest)
        self.assertNotIn(".terminal-actions", release)
        self.assertIn("terminal-actions/attest/dist/index.js", release)
        self.assertIn("authorized-input-manifest.json", release)
        self.assertIn("input_manifest_sha256", release)
        self.assertIn("Verify sealed authorized input", release)
        self.assertLess(
            deploy.index("Verify sealed authorized input"),
            deploy.index("Create isolated hash-closed HF publisher"),
        )
        self.assertLess(
            deploy.index("Create isolated hash-closed HF publisher"),
            deploy.index("secrets.HF_TOKEN"),
        )
        for credential in (
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_RUNTIME_URL",
            "ACTIONS_RESULTS_URL",
            "ACTIONS_CACHE_URL",
        ):
            self.assertIn(f'{credential}: ""', deploy)
            self.assertIn(f'{credential}: ""', measure)
        self.assertIn("github.run_attempt", release)
        self.assertIn("--publisher-artifact-outcome", attest)
        self.assertIn("--measurement-artifact-outcome", attest)
        self.assertNotIn("/rulesets", release)
        publisher = (ROOT / "scripts" / "deploy_hf_space.py").read_text(encoding="utf-8")
        self.assertNotIn("/rulesets", publisher)
        contracts_offline = job(contracts, "offline-contracts", "live-integrity")
        self.assertNotIn("requirements/hf-publisher.lock", contracts_offline)
        self.assertNotIn("pip install", contracts_offline)
        self.assertIn('python-version: "3.12.13"', contracts)
        self.assertIn("python -I -P scripts/verify_kernel_registry.py", contracts)
        for line in release.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                reference = stripped.split("uses:", 1)[1].split("#", 1)[0].strip()
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
