from __future__ import annotations
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import hashlib
import io
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
    ACTIONS_RUNTIME_CREDENTIALS,
    AUTHORIZED_INPUT_SCHEMA,
    BOUNDED_ACTIONS,
    GITHUB_API_CREDENTIALS,
    HF_WINDOW_MAX_INJECTION_BYTES,
    HF_REPO,
    OIDC_CREDENTIALS,
    PUBLIC_MAIN_SCHEMA,
    RetryExhausted,
    SOURCE_RELATION,
    SOURCE_REPO,
    _fetch_public_index,
    _hf_upload_child_environment,
    _recover_authoritative_revision,
    _require_public_main_revision,
    _require_authorization_privilege_domain,
    _require_measurement_privilege_domain,
    _require_publisher_privilege_domain,
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
    classify_terminal_failure_stage,
    deploy_bundle,
    enforce_terminal_evidence,
    finalize_attested_receipt,
    normalize_public_static_index,
    require_receipt_failure_artifact,
    run_bounded_action,
    seal_authorized_input,
    synthesize_candidate_receipt,
    validate_deployment_failure_receipt,
    validate_bundle,
    validate_authorized_input,
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







# Shared exact governed-merge evidence for direct pipeline tests.
_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "kernel_contract_test_fixture",
    Path(__file__).with_name("test_github_governed_merge.py"),
)
if _CONTRACT_SPEC is None or _CONTRACT_SPEC.loader is None:
    raise RuntimeError("cannot load governed-merge contract fixture")
CONTRACT_FIXTURE = importlib.util.module_from_spec(_CONTRACT_SPEC)
sys.modules[_CONTRACT_SPEC.name] = CONTRACT_FIXTURE
_CONTRACT_SPEC.loader.exec_module(CONTRACT_FIXTURE)
GOVERNANCE = CONTRACT_FIXTURE.GOVERNANCE
_governed_merge_evidence = CONTRACT_FIXTURE.governed_merge_evidence
_GOVERNANCE_TEMP = tempfile.TemporaryDirectory(prefix="kernel-governance-tests-")
_GOVERNANCE_ROOT = Path(_GOVERNANCE_TEMP.name)
GOVERNANCE_EVENT_PATH = _GOVERNANCE_ROOT / "event.json"
AUTHORIZATION_PATH = _GOVERNANCE_ROOT / "authorization.json"
POST_AUTHORIZATION_PATH = _GOVERNANCE_ROOT / "post-authorization.json"
POST_AUTHORIZATION_FAILURE_PATH = _GOVERNANCE_ROOT / "post-authorization-failure.json"
_exact_authorization = _governed_merge_evidence(SOURCE_SHA)
GOVERNANCE_EVENT_PATH.write_text(
    json.dumps(
        {
            "after": SOURCE_SHA,
            "before": _exact_authorization["push"]["before"],
            "ref": "refs/heads/main",
            "repository": _exact_authorization["repository"],
        }
    ),
    encoding="utf-8",
)
AUTHORIZATION_PATH.write_bytes(GOVERNANCE.canonical_json(_exact_authorization))

AUTHORIZED_INPUT_MANIFEST_SHA256 = "7" * 64


def public_main_evidence(source_sha: str = SOURCE_SHA) -> dict[str, object]:
    return {
        "schema": PUBLIC_MAIN_SCHEMA,
        "transport": "UNAUTHENTICATED_PUBLIC_GITHUB_API",
        "repository": SOURCE_REPO,
        "ref": "refs/heads/main",
        "revision": source_sha,
        "protected": True,
    }

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


    def test_public_provenance_rejects_terminal_nonmatching_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            result = Path(temporary) / "result.json"
            result.write_bytes(
                canonical_json(
                    {
                        "schema": "szl.hf-deploy-result/v3",
                        "status": "PUBLISHED_AWAITING_ATTESTATION",
                        "authorized_input_manifest_sha256": AUTHORIZED_INPUT_MANIFEST_SHA256,
                        "pre_mutation_main": public_main_evidence(),
                        "post_mutation_main": public_main_evidence(),
                        "status": "PUBLISHED_AWAITING_ATTESTATION",
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "previous_hf_revision": PARENT_SHA,
                        "hf_revision": TARGET_SHA,
                        "bundle_sha256": validate_bundle(bundle, SOURCE_SHA)["bundle_sha256"],
                        "upload_transport": "RETURNED_AUTHORITATIVE_REVISION",
                        "authorization": _governed_merge_evidence(SOURCE_SHA),
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
                    authorization_path=AUTHORIZATION_PATH,
                    event_path=GOVERNANCE_EVENT_PATH,
                    authorization_output_path=POST_AUTHORIZATION_PATH,
                    authorization_failure_output_path=POST_AUTHORIZATION_FAILURE_PATH,
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
                        "schema": "szl.hf-deploy-result/v3",
                        "status": "PUBLISHED_AWAITING_ATTESTATION",
                        "authorized_input_manifest_sha256": AUTHORIZED_INPUT_MANIFEST_SHA256,
                        "pre_mutation_main": public_main_evidence(),
                        "post_mutation_main": public_main_evidence(),
                        "status": "PUBLISHED_AWAITING_ATTESTATION",
                        "source_revision": SOURCE_SHA,
                        "target": HF_REPO,
                        "previous_hf_revision": PARENT_SHA,
                        "hf_revision": TARGET_SHA,
                        "bundle_sha256": validate_bundle(bundle, SOURCE_SHA)["bundle_sha256"],
                        "upload_transport": "RETURNED_AUTHORITATIVE_REVISION",
                        "authorization": _governed_merge_evidence(SOURCE_SHA),
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
                "scripts.deploy_hf_space.GOVERNANCE.require_governed_main",
                side_effect=RuntimeError("baseline governance weakened"),
            ), self.assertRaisesRegex(
                RuntimeError, "baseline governance weakened"
            ) as caught:
                attest_publication(
                    bundle, SOURCE_SHA, result, attestation, timeout=1,
                    authorization_path=AUTHORIZATION_PATH,
                    event_path=GOVERNANCE_EVENT_PATH,
                    authorization_output_path=POST_AUTHORIZATION_PATH,
                    authorization_failure_output_path=POST_AUTHORIZATION_FAILURE_PATH,
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
            }
            def hanging_child(_command, *, entered_marker, mutation_state, **_kwargs):
                child_environment.update(_kwargs["environment"])
                entered_marker.write_bytes(b"UPLOAD_CALL_ENTERED\n")
                mutation_state["upload_call_entered"] = True
                raise TimeoutError("transport reset")

            with mock.patch.dict("os.environ", environment, clear=True), mock.patch(
                "scripts.deploy_hf_space.GOVERNANCE.require_governed_main",
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
                deploy_bundle(bundle, SOURCE_SHA, result, state, authorization_path=AUTHORIZATION_PATH)

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
                "scripts.deploy_hf_space.GOVERNANCE.require_governed_main",
                side_effect=RuntimeError("governance unavailable"),
            ), self.assertRaises(RuntimeError):
                deploy_bundle(
                    bundle,
                    SOURCE_SHA,
                    precondition_result,
                    precondition_state,
                 authorization_path=AUTHORIZATION_PATH)
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

    def test_pre_entry_child_failure_never_attempts_authoritative_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            result = root / "result.json"
            state: dict[str, object] = {}
            with mock.patch.dict(
                os.environ, {"HF_TOKEN": "test-hf-token"}, clear=True
            ), mock.patch(
                "scripts.deploy_hf_space.GOVERNANCE.require_governed_main",
                return_value={"status": "AUTHORIZED"},
            ), mock.patch(
                "scripts.deploy_hf_space._request_json_retry",
                return_value={"sha": PARENT_SHA},
            ), mock.patch(
                "scripts.deploy_hf_space._run_killable_child",
                side_effect=RuntimeError("child import failed before upload"),
            ), mock.patch(
                "scripts.deploy_hf_space._recover_authoritative_revision"
            ) as recover, self.assertRaisesRegex(
                RuntimeError, "child import failed before upload"
            ) as caught:
                deploy_bundle(bundle, SOURCE_SHA, result, state, authorization_path=AUTHORIZATION_PATH)

            recover.assert_not_called()
            self.assertFalse(state["upload_call_entered"])
            self.assertFalse(state["authoritative_readback_attempted"])
            self.assertIsNone(state["known_hf_revision"])
            self.assertEqual(
                json.loads(result.read_text(encoding="utf-8"))["status"],
                "MUTATION_CHILD_PREPARED",
            )
            failure = root / "failure.json"
            write_failure_evidence(
                failure, SOURCE_SHA, caught.exception, result, state
            )
            receipt = validate_deployment_failure_receipt(failure, SOURCE_SHA)
            self.assertEqual(receipt["status"], "FAILED_BEFORE_MUTATION")
            self.assertFalse(receipt["upload_call_entered"])
            self.assertFalse(receipt["authoritative_readback_attempted"])

    def test_real_hanging_child_is_killed_with_bounded_unknown_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "entered"
            result = root / "result.json"
            result.write_bytes(canonical_json({
                "schema": "szl.hf-deploy-result/v3",
                "status": "PUBLISHED_AWAITING_ATTESTATION",
                "authorized_input_manifest_sha256": AUTHORIZED_INPUT_MANIFEST_SHA256,
                "pre_mutation_main": public_main_evidence(),
                "post_mutation_main": public_main_evidence(),
                "authorization": _governed_merge_evidence(SOURCE_SHA),
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
                "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_bytes(b'UPLOAD_CALL_ENTERED\\n'); time.sleep(60)",
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
            failure.write_bytes(canonical_json({"schema": "szl.hf-deploy-failure/v3"}))
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
                RuntimeError("pre-mutation failure"),
                root / "missing-result.json",
                {
                    "upload_call_entered": False,
                    "authoritative_readback_attempted": False,
                    "known_hf_revision": None,
                },
            )
            before_mutation = validate_deployment_failure_receipt(failure, SOURCE_SHA)
            self.assertEqual(before_mutation["status"], "FAILED_BEFORE_MUTATION")
            before_mutation["authoritative_readback_attempted"] = True
            failure.write_bytes(canonical_json(before_mutation))
            with self.assertRaisesRegex(RuntimeError, "contradicts authoritative readback"):
                validate_deployment_failure_receipt(failure, SOURCE_SHA)

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

    def test_bounded_actions_receive_exact_wrapper_and_upload_runtime_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            captured: dict[str, dict[str, str]] = {}

            def invoke(action: str, declared: dict[str, str]) -> dict[str, str]:
                descriptor = BOUNDED_ACTIONS[action]
                entry = workspace / descriptor["entry"]
                entry.parent.mkdir(parents=True, exist_ok=True)
                entry.write_bytes(b"pinned runtime")
                digests = {entry.resolve(): descriptor["sha256"]}
                contract_relative = descriptor.get("contract")
                if contract_relative is not None:
                    contract = workspace / contract_relative
                    contract.parent.mkdir(parents=True, exist_ok=True)
                    contract.write_bytes(b"pinned wrapper contract")
                    digests[contract.resolve()] = descriptor["contract_sha256"]

                environment = {
                    "GITHUB_WORKSPACE": str(workspace),
                    "HF_TERMINAL_DEADLINE_EPOCH": str(int(time.time()) + 600),
                    "HF_TOKEN": "must-not-reach-action",
                    "GOVERNANCE_TOKEN": "must-not-reach-action",
                    **declared,
                }

                def capture(_command, *, environment, **_kwargs):
                    captured[action] = environment

                with mock.patch.dict(os.environ, environment, clear=True), mock.patch(
                    "scripts.deploy_hf_space.sha256_file",
                    side_effect=lambda path: digests[path.resolve()],
                ), mock.patch(
                    "scripts.deploy_hf_space.shutil.which", return_value="/exact/node"
                ), mock.patch(
                    "scripts.deploy_hf_space.subprocess.run",
                    return_value=types.SimpleNamespace(stdout="24.19.0"),
                ), mock.patch(
                    "scripts.deploy_hf_space._run_bounded_process",
                    side_effect=capture,
                ):
                    run_bounded_action(action, reserve_seconds=60, max_seconds=30)
                return captured[action]

            upload = invoke(
                "upload",
                {
                    "DEADLINE_ACTION_INPUT_NAME": "evidence",
                    "DEADLINE_ACTION_INPUT_PATH": "evidence.json",
                    "DEADLINE_ACTION_INPUT_IF_NO_FILES_FOUND": "error",
                    "DEADLINE_ACTION_INPUT_RETENTION_DAYS": "90",
                    "DEADLINE_ACTION_INPUT_COMPRESSION_LEVEL": "6",
                    "DEADLINE_ACTION_INPUT_OVERWRITE": "false",
                    "DEADLINE_ACTION_INPUT_INCLUDE_HIDDEN_FILES": "false",
                    "DEADLINE_ACTION_INPUT_ARCHIVE": "true",
                },
            )
            for name, value in BOUNDED_ACTIONS["upload"]["defaults"].items():
                self.assertEqual(upload[f"INPUT_{name.upper()}"], value)

            attest = invoke(
                "attest-build-provenance",
                {
                    "DEADLINE_ACTION_INPUT_SUBJECT_PATH": "canonical-receipt.json",
                    "DEADLINE_ACTION_INPUT_SUBJECT_DIGEST": "",
                    "DEADLINE_ACTION_INPUT_SUBJECT_NAME": "",
                    "DEADLINE_ACTION_INPUT_SUBJECT_CHECKSUMS": "",
                    "DEADLINE_ACTION_INPUT_PREDICATE_TYPE": "",
                    "DEADLINE_ACTION_INPUT_PREDICATE": "",
                    "DEADLINE_ACTION_INPUT_PREDICATE_PATH": "",
                    "DEADLINE_ACTION_INPUT_PUSH_TO_REGISTRY": "false",
                    "DEADLINE_ACTION_INPUT_CREATE_STORAGE_RECORD": "true",
                    "DEADLINE_ACTION_INPUT_SHOW_SUMMARY": "true",
                    "DEADLINE_ACTION_GITHUB_CREDENTIAL": "github-token",
                },
            )
            self.assertEqual(
                attest["INPUT_SUBJECT-PATH"], "canonical-receipt.json"
            )
            for name, value in BOUNDED_ACTIONS["attest-build-provenance"][
                "defaults"
            ].items():
                self.assertEqual(attest[f"INPUT_{name.upper()}"], value)
            self.assertEqual(attest["INPUT_GITHUB-TOKEN"], "github-token")
            for environment in (upload, attest):
                self.assertNotIn("HF_TOKEN", environment)
                self.assertNotIn("GOVERNANCE_TOKEN", environment)
                self.assertFalse(
                    any(name.startswith("DEADLINE_ACTION_") for name in environment)
                )

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
    def test_authorized_input_manifest_closes_exact_nonhidden_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "kernel-authorized-input"
            (root / "scripts").mkdir(parents=True)
            (root / "terminal-actions" / "attest" / "dist").mkdir(parents=True)
            (root / "scripts" / "deploy_hf_space.py").write_bytes(b"publisher\n")
            (root / "terminal-actions" / "attest" / "dist" / "index.js").write_bytes(
                b"runtime\n"
            )
            manifest_path = root / "authorized-input-manifest.json"
            manifest = seal_authorized_input(root, SOURCE_SHA, manifest_path)
            digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            self.assertEqual(manifest["schema"], AUTHORIZED_INPUT_SCHEMA)
            self.assertEqual(
                validate_authorized_input(root, SOURCE_SHA, digest), manifest
            )

            (root / "scripts" / "deploy_hf_space.py").write_bytes(b"tamperedd\n")
            with self.assertRaisesRegex(RuntimeError, "digest differs"):
                validate_authorized_input(root, SOURCE_SHA, digest)

        with tempfile.TemporaryDirectory() as temporary:
            hidden = Path(temporary) / "input"
            (hidden / ".terminal-actions").mkdir(parents=True)
            (hidden / ".terminal-actions" / "index.js").write_bytes(b"runtime")
            with self.assertRaisesRegex(RuntimeError, "unsafe path"):
                seal_authorized_input(
                    hidden,
                    SOURCE_SHA,
                    hidden / "authorized-input-manifest.json",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "input"
            root.mkdir()
            (root / "publisher.py").write_bytes(b"publisher")
            manifest_path = root / "authorized-input-manifest.json"
            seal_authorized_input(root, SOURCE_SHA, manifest_path)
            digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            (root / "unlisted.txt").write_bytes(b"unlisted")
            with self.assertRaisesRegex(RuntimeError, "not closed"):
                validate_authorized_input(root, SOURCE_SHA, digest)

    def test_privilege_domains_reject_every_cross_domain_credential(self) -> None:
        for name in sorted(GITHUB_API_CREDENTIALS | OIDC_CREDENTIALS | ACTIONS_RUNTIME_CREDENTIALS):
            with self.subTest(domain="publisher", credential=name):
                with mock.patch.dict(os.environ, {name: "credential"}, clear=True):
                    with self.assertRaises(RuntimeError):
                        _require_publisher_privilege_domain()
        for name in sorted(frozenset({"HF_TOKEN"}) | OIDC_CREDENTIALS | ACTIONS_RUNTIME_CREDENTIALS):
            with self.subTest(domain="measurement", credential=name):
                with mock.patch.dict(os.environ, {name: "credential"}, clear=True):
                    with self.assertRaises(RuntimeError):
                        _require_measurement_privilege_domain()
            with self.subTest(domain="authorization", credential=name):
                with mock.patch.dict(os.environ, {name: "credential"}, clear=True):
                    with self.assertRaises(RuntimeError):
                        _require_authorization_privilege_domain()
        with mock.patch.dict(os.environ, {"HF_TOKEN": "publisher"}, clear=True):
            _require_publisher_privilege_domain()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "reader"}, clear=True):
            _require_measurement_privilege_domain()
            _require_authorization_privilege_domain()

    def test_authorized_input_manifest_rejects_structural_contradictions(self) -> None:
        mutations = {
            "absolute": lambda value: value["files"][0].update({"path": "/escape"}),
            "parent": lambda value: value["files"][0].update({"path": "../escape"}),
            "bytes": lambda value: value["files"][0].update(
                {"bytes": value["files"][0]["bytes"] + 1}
            ),
            "digest": lambda value: value["files"][0].update({"sha256": "f" * 64}),
            "duplicate": lambda value: (
                value["files"].append(dict(value["files"][0])),
                value.update({"file_count": len(value["files"])}),
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "input"
                root.mkdir()
                (root / "publisher.py").write_bytes(b"publisher")
                manifest_path = root / "authorized-input-manifest.json"
                seal_authorized_input(root, SOURCE_SHA, manifest_path)
                value = json.loads(manifest_path.read_bytes())
                mutate(value)
                value["tree_sha256"] = hashlib.sha256(
                    canonical_json(value["files"])
                ).hexdigest()
                manifest_path.write_bytes(canonical_json(value))
                digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                with self.assertRaises(RuntimeError):
                    validate_authorized_input(root, SOURCE_SHA, digest)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "input"
            root.mkdir()
            (root / "publisher.py").write_bytes(b"publisher")
            manifest_path = root / "authorized-input-manifest.json"
            value = seal_authorized_input(root, SOURCE_SHA, manifest_path)
            manifest_path.write_text(json.dumps(value, indent=2), encoding="utf-8")
            digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(RuntimeError, "contract is not exact"):
                validate_authorized_input(root, SOURCE_SHA, digest)
            with self.assertRaisesRegex(RuntimeError, "digest differs"):
                validate_authorized_input(root, SOURCE_SHA, "0" * 64)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "input"
            root.mkdir()
            target = root / "publisher.py"
            target.write_bytes(b"publisher")
            link = root / "publisher-link.py"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable in this environment")
            with self.assertRaisesRegex(RuntimeError, "symbolic path"):
                seal_authorized_input(
                    root,
                    SOURCE_SHA,
                    root / "authorized-input-manifest.json",
                )

    def test_terminal_failure_classification_is_first_failure_exact(self) -> None:
        names = (
            "publish_outcome",
            "publisher_artifact_outcome",
            "measurement_outcome",
            "measurement_artifact_outcome",
            "candidate_receipt_outcome",
            "oidc_outcome",
            "finalize_receipt_outcome",
            "terminal_artifact_outcome",
        )
        stages = (
            "PUBLISHER_MUTATION",
            "PUBLISHER_EVIDENCE_TRANSPORT",
            "PUBLIC_MEASUREMENT",
            "MEASUREMENT_EVIDENCE_TRANSPORT",
            "CANDIDATE_RECEIPT_SYNTHESIS",
            "OIDC_RECEIPT_ATTESTATION",
            "FINAL_RECEIPT_PROMOTION",
            "TERMINAL_SUCCESS_ARTIFACT",
        )
        for index, stage in enumerate(stages):
            outcomes = {name: "success" for name in names}
            outcomes[names[index]] = "failure"
            with self.subTest(stage=stage):
                self.assertEqual(
                    classify_terminal_failure_stage(**outcomes), stage
                )
        self.assertIsNone(
            classify_terminal_failure_stage(**{name: "success" for name in names})
        )

    def test_terminal_success_requires_both_artifact_aggregates(self) -> None:
        outcomes = {
            "publish_outcome": "success",
            "publisher_artifact_outcome": "success",
            "measurement_outcome": "success",
            "measurement_artifact_outcome": "success",
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
        for field in ("publisher_artifact_outcome", "measurement_artifact_outcome"):
            contradicted = dict(outcomes)
            contradicted[field] = "failure"
            contradicted["failure_synthesis_outcome"] = "success"
            contradicted["failure_artifact_primary_outcome"] = "success"
            with self.subTest(field=field):
                with self.assertRaisesRegex(RuntimeError, "incomplete"):
                    enforce_terminal_evidence(**contradicted)

    def test_stale_public_main_is_rejected_before_mutation_evidence(self) -> None:
        class Response(io.BytesIO):
            status = 200

            def geturl(self) -> str:
                return "https://api.github.com/repos/szl-holdings/szl-kernels-live/branches/main"

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        payload = json.dumps(
            {"protected": True, "commit": {"sha": "f" * 40}}
        ).encode("utf-8")
        opener = mock.Mock()
        opener.open.return_value = Response(payload)
        with mock.patch(
            "scripts.deploy_hf_space.urllib.request.build_opener",
            return_value=opener,
        ):
            with self.assertRaisesRegex(RuntimeError, "differs from source"):
                _require_public_main_revision(SOURCE_SHA, deadline=float("inf"))

    def test_post_mutation_main_change_is_partial_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failure = root / "failure.json"
            write_failure_evidence(
                failure,
                SOURCE_SHA,
                RuntimeError("current public main changed after mutation"),
                root / "missing-result.json",
                {
                    "upload_call_entered": True,
                    "authoritative_readback_attempted": True,
                    "known_hf_revision": TARGET_SHA,
                    "pre_mutation_main": public_main_evidence(),
                    "post_mutation_main": None,
                },
            )
            evidence = validate_deployment_failure_receipt(failure, SOURCE_SHA)
            self.assertEqual(evidence["schema"], "szl.hf-deploy-failure/v3")
            self.assertEqual(evidence["status"], "PARTIAL_AFTER_MUTATION")
            self.assertEqual(evidence["hf_revision"], TARGET_SHA)
            self.assertEqual(evidence["pre_mutation_main"], public_main_evidence())
            self.assertIsNone(evidence["post_mutation_main"])
            self.assertFalse(evidence["deployment_success"])

    def test_attested_candidate_v4_is_promoted_without_byte_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            build_bundle(bundle, SOURCE_SHA)
            manifest = validate_bundle(bundle, SOURCE_SHA)
            result_path = root / "result.json"
            measurement_path = root / "measurement.json"
            candidate = root / "candidate" / "hf-canonical-success-receipt.json"
            output = root / "hf-canonical-success-receipt.json"
            envelope_path = root / "hf-oidc-attestation-envelope.json"
            attestation_bundle = root / "attestation.jsonl"
            attestation_bundle.write_bytes(b"signed-attestation-bundle\n")
            authorization = _governed_merge_evidence(SOURCE_SHA)
            result = {
                "schema": "szl.hf-deploy-result/v3",
                "status": "PUBLISHED_AWAITING_ATTESTATION",
                "source_revision": SOURCE_SHA,
                "previous_hf_revision": PARENT_SHA,
                "hf_revision": TARGET_SHA,
                "bundle_sha256": manifest["bundle_sha256"],
                "target": HF_REPO,
                "authorization": authorization,
                "authorized_input_manifest_sha256": AUTHORIZED_INPUT_MANIFEST_SHA256,
                "pre_mutation_main": public_main_evidence(),
                "post_mutation_main": public_main_evidence(),
            }
            result_path.write_bytes(canonical_json(result))
            immutable_index = (bundle / "index.html").read_bytes()
            public_index = normalize_public_static_index(
                inject_hf_window(immutable_index), immutable_index
            )
            manifest_bytes = (bundle / "hf-deploy-manifest.json").read_bytes()
            tree = [dict(row) for row in manifest["files"]]
            tree.append(
                {
                    "path": "hf-deploy-manifest.json",
                    "bytes": len(manifest_bytes),
                    "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                }
            )
            tree.sort(key=lambda row: row["path"])
            measurement = {
                "schema": "szl.hf-live-attestation/v4",
                "status": "MEASURED",
                "source": {
                    "repository": SOURCE_REPO,
                    "revision": SOURCE_SHA,
                    "relation": SOURCE_RELATION,
                },
                "source_revision": SOURCE_SHA,
                "hf_revision": TARGET_SHA,
                "target": HF_REPO,
                "runtime_stage": "RUNNING",
                "bundle_sha256": manifest["bundle_sha256"],
                "file_count": len(tree),
                "tree_sha256": hashlib.sha256(canonical_json(tree)).hexdigest(),
                "public_index": public_index,
                "public_provenance": {
                    "verified": True,
                    "schema": "szl.space-provenance/v1",
                    "source_repository": SOURCE_REPO,
                    "source_revision": SOURCE_SHA,
                    "relation": SOURCE_RELATION,
                },
                "authorization": authorization,
                "authorized_input_manifest_sha256": AUTHORIZED_INPUT_MANIFEST_SHA256,
                "pre_mutation_main": public_main_evidence(),
                "post_mutation_main": public_main_evidence(),
                "post_publication_main": authorization,
                "receipt_minted": False,
                "deployment_success": False,
            }
            measurement_path.write_bytes(canonical_json(measurement))
            receipt = synthesize_candidate_receipt(
                candidate,
                SOURCE_SHA,
                bundle,
                result_path,
                measurement_path,
            )
            attested_bytes = candidate.read_bytes()
            self.assertEqual(receipt["schema"], "szl.hf-oidc-receipt/v4")
            envelope = finalize_attested_receipt(
                candidate,
                output,
                envelope_path,
                SOURCE_SHA,
                bundle,
                result_path,
                measurement_path,
                attestation_id="attestation-id",
                attestation_url="https://github.com/attestations/attestation-id",
                bundle_path=str(attestation_bundle),
            )
            self.assertEqual(output.read_bytes(), attested_bytes)
            self.assertEqual(
                envelope["canonical_receipt"]["sha256"],
                hashlib.sha256(attested_bytes).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
    normalize_public_static_index,
    synthesize_oidc_receipt,

def _load_frontier_deploy_contract() -> dict[str, object]:
    import runpy
    from pathlib import Path

    return runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "deploy_hf_space.py"
        )
    )


def test_manifest_tree_contract_includes_exact_self_manifest_bytes(tmp_path) -> None:
    import json

    contract = _load_frontier_deploy_contract()
    manifest_bytes = (
        b'{"file_count":1,"files":['
        b'{"bytes":3,"path":"app.py","sha256":"'
        + (b"0" * 64)
        + b'"}]}'
    )
    manifest = json.loads(manifest_bytes)
    manifest_path = tmp_path / "hf-deploy-manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    tree_without_manifest = contract["_manifest_tree_sha256"](manifest)
    tree_with_manifest = contract["_manifest_tree_sha256"](
        manifest,
        bundle=tmp_path,
    )

    assert tree_with_manifest != tree_without_manifest
    assert contract["_manifest_contract_file_count"](
        manifest,
        bundle=tmp_path,
    ) == 2

    manifest_path.write_bytes(manifest_bytes + b"\n")
    assert contract["_manifest_tree_sha256"](
        manifest,
        bundle=tmp_path,
    ) != tree_with_manifest


def test_bounded_attestation_mode_is_exact_build_provenance() -> None:
    contract = _load_frontier_deploy_contract()
    descriptor = contract["BOUNDED_ACTIONS"]["attest-build-provenance"]

    assert descriptor["mode"] == "build-provenance"
    assert descriptor["defaults"]["predicate-type"] == ""
    assert descriptor["defaults"]["predicate"] == ""
    assert descriptor["defaults"]["predicate-path"] == ""
    OIDC_CREDENTIALS,
    PUBLIC_MAIN_SCHEMA,
