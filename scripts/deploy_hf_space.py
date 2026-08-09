#!/usr/bin/env python3
"""Atomically deploy a prebuilt bundle to the governed SZL Kernels Space."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
import time
import urllib.error
import urllib.parse
import urllib.request


HF_REPO = "SZLHOLDINGS/szl-kernels-live"
SOURCE_REPO = "szl-holdings/szl-kernels-live"
SOURCE_RELATION = "source-bound-release-bundle"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_RULE_TYPES = {"pull_request", "non_fast_forward", "required_linear_history"}
GOVERNED_RULESET_ID = 17630223
GOVERNED_RULESET_NAME = "org-default-branch-protection"
GOVERNED_RULESET_SOURCE = "szl-holdings"
GOVERNED_RULESET_SOURCE_TYPE = "Organization"
GOVERNED_REPOSITORY_ID = 1295941334
TERMINAL_STAGES = {"BUILD_ERROR", "CONFIG_ERROR", "RUNTIME_ERROR"}
PENDING_STAGES = {"BUILDING", "APP_STARTING", "STARTING", "RUNNING_BUILDING"}
TRANSIENT_HTTP_STATUS = frozenset({429, *range(500, 600)})
ATTEST_TIMEOUT_SECONDS = 600
MUTATION_READBACK_SECONDS = 30
MUTATION_TIMEOUT_SECONDS = 300
RETRY_DELAY_SECONDS = 2
UA = "szl-kernels-live-deployer/1.0"
HF_WINDOW_PREFIX = b"<script>window.huggingface="
HF_WINDOW_TERMINATOR = b";</script>"
HF_WINDOW_MAX_INJECTION_BYTES = 4096
HTML_HEAD_BOUNDARY = b"<head>"


class TransientReadError(RuntimeError):
    """A sanitized transport condition that may be retried until the deadline."""


class RetryExhausted(RuntimeError):
    """A bounded readback exhausted only retryable transport failures."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _parse_hf_window_object(payload: bytes) -> dict[str, object]:
    if b"<" in payload or b">" in payload or b"\x00" in payload:
        raise RuntimeError("Hugging Face window payload contains markup")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("Hugging Face window payload is not UTF-8") from error
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.fullmatch(r"\{variables:(\{.*\})\}", text, re.DOTALL)
        if not match:
            raise RuntimeError("Hugging Face window payload is not an object") from None
        try:
            variables = json.loads(match.group(1))
        except json.JSONDecodeError as error:
            raise RuntimeError("Hugging Face window variables are not JSON") from error
        if not isinstance(variables, dict):
            raise RuntimeError("Hugging Face window variables are not an object")
        value = {"variables": variables}
    if not isinstance(value, dict):
        raise RuntimeError("Hugging Face window payload is not an object")
    return value


def normalize_public_static_index(
    observed_bytes: bytes,
    immutable_bytes: bytes,
) -> dict[str, object]:
    """Close the one deterministic Hugging Face Static HTML transformation."""
    if immutable_bytes.count(HTML_HEAD_BOUNDARY) != 1:
        raise RuntimeError("bundled index does not have one exact head boundary")
    if b"window.huggingface" in immutable_bytes:
        raise RuntimeError("bundled index already contains platform injection")
    boundary = immutable_bytes.index(HTML_HEAD_BOUNDARY) + len(HTML_HEAD_BOUNDARY)
    if observed_bytes[:boundary] != immutable_bytes[:boundary]:
        raise RuntimeError("public platform injection is at the wrong head boundary")
    if not observed_bytes.startswith(HF_WINDOW_PREFIX, boundary):
        raise RuntimeError("public index omitted the exact window.huggingface injection")
    payload_start = boundary + len(HF_WINDOW_PREFIX)
    terminator = observed_bytes.find(HF_WINDOW_TERMINATOR, payload_start)
    if terminator < 0:
        raise RuntimeError("public platform injection has no strict script terminator")
    injection_end = terminator + len(HF_WINDOW_TERMINATOR)
    injection = observed_bytes[boundary:injection_end]
    if len(injection) > HF_WINDOW_MAX_INJECTION_BYTES:
        raise RuntimeError("public platform injection exceeds the size limit")
    if observed_bytes.count(b"window.huggingface") != 1:
        raise RuntimeError("public index contains multiple platform injections")
    _parse_hf_window_object(observed_bytes[payload_start:terminator])
    normalized = observed_bytes[:boundary] + observed_bytes[injection_end:]
    if normalized != immutable_bytes:
        raise RuntimeError("public index has bytes outside the one platform injection")
    return {
        "transformation": "HF_WINDOW_HUGGINGFACE_HEAD_INJECTION_V1",
        "normalized_bytes": len(normalized),
        "normalized_sha256": sha256_bytes(normalized),
        "injection_bytes": len(injection),
        "injection_sha256": sha256_bytes(injection),
    }


def exact_sha(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if not HEX40.fullmatch(normalized):
        raise RuntimeError(f"{label} must be an exact lowercase 40-character SHA")
    return normalized


def _retry_transient(operation, *, deadline: float, label: str):
    while True:
        if time.monotonic() >= deadline:
            raise RetryExhausted(f"{label} transient readback deadline expired")
        try:
            return operation()
        except urllib.error.HTTPError as error:
            if error.code not in TRANSIENT_HTTP_STATUS:
                raise
            condition = f"HTTP {error.code}"
        except TransientReadError as error:
            condition = str(error)
        except (TimeoutError, ConnectionError, urllib.error.URLError) as error:
            condition = type(error).__name__
        now = time.monotonic()
        if now >= deadline:
            raise RetryExhausted(
                f"{label} transient readback exhausted ({condition})"
            ) from None
        time.sleep(min(RETRY_DELAY_SECONDS, max(0.0, deadline - now)))


def _remaining_timeout(deadline: float, cap: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RetryExhausted("readback deadline expired")
    return max(0.001, min(cap, remaining))


def _request_json(url: str, token: str = "", timeout: float = 30) -> object:
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _request_json_retry(url: str, *, deadline: float, label: str) -> object:
    return _retry_transient(
        lambda: _request_json(url, timeout=_remaining_timeout(deadline, 30)),
        deadline=deadline,
        label=label,
    )


def _exact_pull_request_parameters() -> dict[str, object]:
    return {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": True,
        "required_reviewers": [],
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": True,
        "allowed_merge_methods": ["squash", "rebase"],
    }


def _exact_baseline_detail(detail: object) -> bool:
    if not isinstance(detail, dict):
        return False
    if any(
        (
            detail.get("id") != GOVERNED_RULESET_ID,
            detail.get("name") != GOVERNED_RULESET_NAME,
            detail.get("target") != "branch",
            detail.get("source") != GOVERNED_RULESET_SOURCE,
            detail.get("source_type") != GOVERNED_RULESET_SOURCE_TYPE,
            detail.get("enforcement") != "active",
            detail.get("bypass_actors") != [],
            detail.get("conditions")
            != {
                "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
                "repository_name": {"exclude": [], "include": ["~ALL"]},
            },
        )
    ):
        return False
    rules = detail.get("rules")
    if not isinstance(rules, list) or len(rules) != 3:
        return False
    indexed = {
        row.get("type"): row
        for row in rules
        if isinstance(row, dict) and isinstance(row.get("type"), str)
    }
    return indexed == {
        "pull_request": {
            "type": "pull_request",
            "parameters": _exact_pull_request_parameters(),
        },
        "non_fast_forward": {"type": "non_fast_forward"},
        "required_linear_history": {"type": "required_linear_history"},
    }


def evaluate_effective_rulesets(
    summaries: object,
    details: dict[int, object],
    effective_rules: object,
) -> tuple[list[int], list[str]]:
    """Prove the exact inherited baseline while permitting additional stronger rulesets."""
    if not isinstance(summaries, list):
        raise RuntimeError("repository ruleset inventory is unavailable")
    if not isinstance(effective_rules, list):
        raise RuntimeError("effective default-branch rules are unavailable")
    diagnostics: list[str] = []
    inventory = [
        row
        for row in summaries
        if isinstance(row, dict) and row.get("id") == GOVERNED_RULESET_ID
    ]
    if len(inventory) != 1:
        diagnostics.append(
            f"ruleset {GOVERNED_RULESET_ID}: exact inventory row is not unique"
        )
        return [], diagnostics

    summary = inventory[0]
    if summary.get("name") != GOVERNED_RULESET_NAME:
        diagnostics.append("inventory name is not org-default-branch-protection")
    if summary.get("target") != "branch":
        diagnostics.append("inventory target is not branch")
    if summary.get("enforcement") != "active":
        diagnostics.append("inventory enforcement is not active")
    if summary.get("source") != GOVERNED_RULESET_SOURCE:
        diagnostics.append("inventory source is not szl-holdings")
    if summary.get("source_type") != GOVERNED_RULESET_SOURCE_TYPE:
        diagnostics.append("inventory source_type is not Organization")

    detail = details.get(GOVERNED_RULESET_ID)
    if not _exact_baseline_detail(detail):
        diagnostics.append("baseline ruleset detail is not exact")

    observed_types: set[object] = set()
    baseline_rows = [
        (index, row)
        for index, row in enumerate(effective_rules, start=1)
        if isinstance(row, dict) and row.get("ruleset_id") == GOVERNED_RULESET_ID
    ]
    if not baseline_rows:
        diagnostics.append("no effective baseline rule rows were disclosed")
    for index, row in baseline_rows:
        if not isinstance(row, dict):
            diagnostics.append(f"effective row {index} is not an object")
            continue
        if row.get("ruleset_source") != GOVERNED_RULESET_SOURCE:
            diagnostics.append(f"effective row {index} has a mixed or missing source")
        if row.get("ruleset_source_type") != GOVERNED_RULESET_SOURCE_TYPE:
            diagnostics.append(
                f"effective row {index} has a mixed or missing source_type"
            )
        observed_types.add(row.get("type"))
    missing_types = sorted(REQUIRED_RULE_TYPES - observed_types)
    if missing_types:
        diagnostics.append("missing effective rules: " + ", ".join(missing_types))
    if len(baseline_rows) != len(REQUIRED_RULE_TYPES):
        diagnostics.append("effective baseline rows are not an exact three-rule projection")
    pull_rows = [row for _, row in baseline_rows if row.get("type") == "pull_request"]
    if len(pull_rows) != 1 or pull_rows[0].get("parameters") != _exact_pull_request_parameters():
        diagnostics.append("effective pull request parameters are not exact")

    if diagnostics:
        return [], [
            f"ruleset {GOVERNED_RULESET_ID}: " + "; ".join(diagnostics)
        ]
    return [GOVERNED_RULESET_ID], []


def require_governed_main(source_sha: str) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_ref = os.environ.get("GITHUB_REF", "")
    token = os.environ.get("GOVERNANCE_TOKEN", "")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if repository != SOURCE_REPO:
        raise RuntimeError(f"unexpected GitHub repository: {repository!r}")
    if source_ref != "refs/heads/main":
        raise RuntimeError(f"refusing production release from {source_ref!r}")
    if not token:
        raise RuntimeError(
            "GOVERNANCE_TOKEN is required for protected-main reauthorization"
        )

    metadata = _request_json(f"{api_root}/repos/{repository}", token)
    if not isinstance(metadata, dict) or (
        metadata.get("id") != GOVERNED_REPOSITORY_ID
        or metadata.get("full_name") != SOURCE_REPO
        or metadata.get("default_branch") != "main"
    ):
        raise RuntimeError("repository identity/default branch is not exact")
    branch = _request_json(f"{api_root}/repos/{repository}/branches/main", token)
    if not isinstance(branch, dict) or branch.get("protected") is not True:
        raise RuntimeError("repository main branch is not protected")
    live_sha = exact_sha(
        ((branch if isinstance(branch, dict) else {}).get("commit") or {}).get("sha"),
        "current protected-main revision",
    )
    if live_sha != source_sha:
        raise RuntimeError(
            f"refusing stale release: current main {live_sha} != source {source_sha}"
        )

    summaries = _request_json(
        f"{api_root}/repos/{repository}/rulesets?includes_parents=true", token
    )
    effective_rules = _request_json(
        f"{api_root}/repos/{repository}/rules/branches/main", token
    )
    details: dict[int, object] = {}
    try:
        details[GOVERNED_RULESET_ID] = _request_json(
            f"{api_root}/repos/{repository}/rulesets/{GOVERNED_RULESET_ID}", token
        )
    except Exception as error:
        details[GOVERNED_RULESET_ID] = {
            "_retrieval_error": type(error).__name__
        }
    accepted, diagnostics = evaluate_effective_rulesets(
        summaries,
        details,
        effective_rules,
    )
    if not accepted:
        raise RuntimeError(
            "default branch policy could not be proven; "
            + " | ".join(diagnostics or ["no ruleset candidates were disclosed"])
        )
    return {
        "status": "AUTHORIZED_EXACT_PROTECTED_MAIN",
        "source_revision": source_sha,
        "ruleset_ids": accepted,
    }


def validate_bundle(bundle: Path, source_sha: str) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    if not bundle.is_dir():
        raise RuntimeError("bundle directory does not exist")

    manifest_path = bundle / "hf-deploy-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_keys = {
        "schema",
        "source_repository",
        "source_revision",
        "target",
        "file_count",
        "files",
        "self_manifest",
        "bundle_sha256",
    }
    if set(manifest) != expected_keys:
        raise RuntimeError("bundle manifest fields do not match the v2 contract")
    if manifest.get("schema") != "szl.hf-deploy-manifest/v2":
        raise RuntimeError("bundle manifest schema is not supported")
    if manifest.get("source_repository") != SOURCE_REPO:
        raise RuntimeError("bundle source repository does not match")
    if manifest.get("source_revision") != source_sha:
        raise RuntimeError("bundle source revision does not match workflow source")
    if manifest.get("target") != HF_REPO:
        raise RuntimeError("bundle target does not match the governed Space")
    if manifest.get("self_manifest") != {
        "path": "hf-deploy-manifest.json",
        "included_in_files": False,
        "reason": "self-digest would be recursive; exact bytes are bound by GitHub OIDC attestation",
    }:
        raise RuntimeError("bundle self-manifest exclusion does not match the contract")

    entries = manifest.get("files")
    if not isinstance(entries, list) or manifest.get("file_count") != len(entries):
        raise RuntimeError("bundle manifest file count does not match its entries")
    listed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise RuntimeError("bundle manifest file entry is malformed")
        relative = PurePosixPath(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) in listed:
            raise RuntimeError("bundle manifest contains an unsafe or duplicate path")
        listed.add(str(relative))
        path = bundle.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"bundle file is missing or symbolic: {relative}")
        if entry["bytes"] != path.stat().st_size:
            raise RuntimeError(f"bundle byte count does not match: {relative}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry["sha256"])):
            raise RuntimeError(f"bundle digest is malformed: {relative}")
        if entry["sha256"] != sha256_file(path):
            raise RuntimeError(f"bundle digest does not match: {relative}")

    actual = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    if actual != listed | {"hf-deploy-manifest.json"}:
        raise RuntimeError("bundle tree is not closed by the manifest")
    manifest_core = {
        key: value for key, value in manifest.items() if key != "bundle_sha256"
    }
    if (
        manifest["bundle_sha256"]
        != hashlib.sha256(canonical_json(manifest_core)).hexdigest()
    ):
        raise RuntimeError("bundle aggregate digest does not match")
    return manifest


def _recover_authoritative_revision(
    bundle: Path,
    manifest: dict[str, object],
    previous_sha: str,
    *,
    deadline: float,
) -> str:
    """Return a post-exception revision only after authoritative exact-byte closure."""
    previous_sha = exact_sha(previous_sha, "observed Hugging Face parent revision")
    while True:
        if time.monotonic() >= deadline:
            raise RetryExhausted(
                "ambiguous mutation remained at the exact recorded parent"
            )
        info = _request_json_retry(
            f"https://huggingface.co/api/spaces/{HF_REPO}",
            deadline=deadline,
            label="ambiguous-mutation authoritative revision readback",
        )
        if not isinstance(info, dict):
            raise RuntimeError("authoritative Hugging Face response is malformed")
        candidate = exact_sha(info.get("sha"), "authoritative Hugging Face revision")
        if candidate == previous_sha:
            time.sleep(min(RETRY_DELAY_SECONDS, max(0.0, deadline - time.monotonic())))
            continue
        try:
            _verify_exact_hf_revision(
                bundle,
                manifest,
                candidate,
                deadline=deadline,
                retry_byte_mismatch=False,
            )
        except Exception as error:
            raise RuntimeError(
                f"ambiguous mutation conflict at unrelated revision {candidate}"
            ) from error
        return candidate


def _run_killable_child(
    command: list[str],
    *,
    deadline: float,
    entered_marker: Path,
    mutation_state: dict[str, object],
    environment: dict[str, str] | None = None,
) -> None:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=os.name != "nt",
    )
    try:
        process.wait(timeout=_remaining_timeout(deadline, max(0.001, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        mutation_state["upload_call_entered"] = entered_marker.is_file()
        process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        raise TimeoutError("Hugging Face upload child exceeded its wall-clock deadline") from None
    finally:
        if entered_marker.is_file():
            mutation_state["upload_call_entered"] = True
    if process.returncode != 0:
        raise RuntimeError("Hugging Face upload child failed")


def upload_child_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--entered-marker", type=Path, required=True)
    parser.add_argument("--child-result", type=Path, required=True)
    args = parser.parse_args(argv)
    source_sha = exact_sha(args.source_sha, "workflow source")
    parent_sha = exact_sha(args.parent_sha, "observed Hugging Face parent revision")
    manifest = validate_bundle(args.bundle, source_sha)
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise RuntimeError("HF_TOKEN is required in the approved secret store")
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    args.entered_marker.parent.mkdir(parents=True, exist_ok=True)
    with args.entered_marker.open("xb") as handle:
        handle.write(b"UPLOAD_CALL_ENTERED\n")
    commit = api.upload_folder(
        repo_id=HF_REPO,
        repo_type="space",
        folder_path=args.bundle,
        token=token,
        parent_commit=parent_sha,
        delete_patterns="*",
        commit_message=f"Deploy GitHub source {source_sha[:12]}",
        commit_description=(
            f"Source: https://github.com/{SOURCE_REPO}/commit/{source_sha}\n"
            f"Bundle: {manifest['bundle_sha256']}"
        ),
    )
    target_sha = exact_sha(commit.oid, "published Hugging Face revision")
    with args.child_result.open("xb") as handle:
        handle.write(canonical_json({"hf_revision": target_sha}))
    return 0


def deploy_bundle(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    mutation_state: dict[str, object] | None = None,
    *,
    mutation_timeout: float = MUTATION_TIMEOUT_SECONDS,
) -> dict[str, object]:
    if mutation_state is None:
        mutation_state = {}
    mutation_state.update(
        {
            "upload_call_entered": False,
            "authoritative_readback_attempted": False,
            "known_hf_revision": None,
        }
    )
    source_sha = exact_sha(source_sha, "workflow source")
    manifest = validate_bundle(bundle, source_sha)
    authorization = require_governed_main(source_sha)

    token = os.environ.get("HF_TOKEN")
    if not token:
        raise RuntimeError("HF_TOKEN is required in the approved secret store")
    mutation_deadline = time.monotonic() + mutation_timeout
    before = _request_json_retry(
        f"https://huggingface.co/api/spaces/{HF_REPO}",
        deadline=mutation_deadline,
        label="pre-mutation Hugging Face parent readback",
    )
    if not isinstance(before, dict):
        raise RuntimeError("pre-mutation Hugging Face response is malformed")
    before_sha = exact_sha(before.get("sha"), "observed Hugging Face parent revision")

    mutation_authorization = require_governed_main(source_sha)
    if mutation_authorization != authorization:
        raise RuntimeError("protected-main authorization changed before publication")
    mutation_boundary = {
        "schema": "szl.hf-deploy-result/v1",
        "status": "MUTATION_CHILD_PREPARED",
        "source_revision": source_sha,
        "previous_hf_revision": before_sha,
        "hf_revision": None,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": HF_REPO,
        "authorization": mutation_authorization,
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("xb") as handle:
        handle.write(canonical_json(mutation_boundary))
    nonce = f"{os.getpid()}-{time.monotonic_ns()}"
    entered_marker = result_path.parent / f".hf-upload-entered-{nonce}"
    child_result = result_path.parent / f".hf-upload-result-{nonce}.json"
    remaining = mutation_deadline - time.monotonic()
    recovery_reserve = min(MUTATION_READBACK_SECONDS, max(0.1, remaining / 4))
    upload_deadline = mutation_deadline - recovery_reserve
    child_command = [
        sys.executable,
        "-I",
        "-P",
        str(Path(__file__).resolve()),
        "upload-child",
        "--bundle",
        str(bundle.resolve()),
        "--source-sha",
        source_sha,
        "--parent-sha",
        before_sha,
        "--entered-marker",
        str(entered_marker.resolve()),
        "--child-result",
        str(child_result.resolve()),
    ]
    try:
        _run_killable_child(
            child_command,
            deadline=upload_deadline,
            entered_marker=entered_marker,
            mutation_state=mutation_state,
            environment=dict(os.environ),
        )
        child_value = json.loads(child_result.read_text(encoding="utf-8"))
        target_sha = exact_sha(
            child_value.get("hf_revision") if isinstance(child_value, dict) else None,
            "published Hugging Face revision",
        )
    except Exception as upload_error:
        if mutation_state.get("upload_call_entered") is True:
            mutation_boundary["status"] = "MUTATION_BOUNDARY_CROSSED"
            result_path.write_bytes(canonical_json(mutation_boundary))
        mutation_state["authoritative_readback_attempted"] = True
        try:
            target_sha = _recover_authoritative_revision(
                bundle,
                manifest,
                before_sha,
                deadline=mutation_deadline,
            )
        except Exception as recovery_error:
            mutation_state["known_hf_revision"] = None
            raise recovery_error from upload_error
    finally:
        entered_marker.unlink(missing_ok=True)
        child_result.unlink(missing_ok=True)
    if mutation_state.get("upload_call_entered") is True:
        mutation_boundary["status"] = "MUTATION_BOUNDARY_CROSSED"
        result_path.write_bytes(canonical_json(mutation_boundary))
    mutation_state["known_hf_revision"] = target_sha
    result = {
        "schema": "szl.hf-deploy-result/v1",
        "status": "PUBLISHED_AWAITING_ATTESTATION",
        "source_revision": source_sha,
        "previous_hf_revision": before_sha,
        "hf_revision": target_sha,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": HF_REPO,
        "authorization": mutation_authorization,
    }
    result_path.write_bytes(canonical_json(result))
    return result


def _origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError("public readback URL must use an exact HTTPS origin")
    return f"https://{parsed.netloc.lower()}"


def _hf_resolve_cache_url_is_valid(
    parsed: urllib.parse.SplitResult,
    *,
    expected_path: str,
) -> bool:
    if parsed.scheme != "https" or parsed.netloc.lower() != "huggingface.co":
        return False
    if "/resolve/" not in expected_path or not expected_path.startswith("/spaces/"):
        return False
    expected_cache_path = "/api/resolve-cache" + expected_path.replace(
        "/resolve/", "/", 1
    )
    if parsed.path != expected_cache_path:
        return False
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError:
        return False
    if len(pairs) != 2 or len({key for key, _ in pairs}) != 2:
        return False
    values = dict(pairs)
    etag = values.get("etag")
    return (
        values.get(expected_path) == ""
        and isinstance(etag, str)
        and re.fullmatch(r'"(?:[0-9a-f]{40}|[0-9a-f]{64})"', etag) is not None
    )


def _signed_hf_cdn_url_is_valid(parsed: urllib.parse.SplitResult) -> bool:
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return False
    try:
        if parsed.port not in {None, 443}:
            return False
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not (
        host == "cdn-lfs.hf.co"
        or re.fullmatch(r"cdn-lfs-[a-z0-9-]+\.hf\.co", host)
        or host == "cas-bridge.xethub.hf.co"
    ):
        return False
    if not parsed.path or parsed.path == "/":
        return False
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError:
        return False
    if not pairs or len(pairs) != len({key for key, _ in pairs}):
        return False
    keys = {key for key, _ in pairs}
    cloudfront_canned = {"Expires", "Signature", "Key-Pair-Id"}
    cloudfront_custom = {"Policy", "Signature", "Key-Pair-Id"}
    aws_v4 = {
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
    }
    xet = {"X-Xet-Cas-Uid", "X-Xet-Cas-Token", "X-Xet-Cas-Url"}
    return (
        cloudfront_canned <= keys
        or cloudfront_custom <= keys
        or aws_v4 <= keys
        or xet <= keys
    )


def _validate_readback_url(
    url: str,
    *,
    allowed_origins: frozenset[str],
    expected_path: str,
    expected_query: str,
    allow_hf_resolve_redirects: bool = False,
    redirect_step: int = 0,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.fragment:
        raise RuntimeError("public readback redirect added a fragment")
    if (
        _origin(url) in allowed_origins
        and parsed.path == expected_path
        and parsed.query == expected_query
    ):
        return
    if allow_hf_resolve_redirects and redirect_step > 0:
        if _hf_resolve_cache_url_is_valid(parsed, expected_path=expected_path):
            return
        if _signed_hf_cdn_url_is_valid(parsed):
            return
        raise RuntimeError("public readback used an unapproved immutable HF redirect")
    if _origin(url) not in allowed_origins:
        raise RuntimeError("public readback redirect changed to an unapproved origin")
    if parsed.path != expected_path:
        raise RuntimeError("public readback redirect changed the requested path")
    if parsed.query != expected_query:
        raise RuntimeError("public readback redirect changed the requested query")


def _public_bytes_once(
    url: str,
    *,
    allowed_origins: frozenset[str],
    expected_path: str,
    expected_query: str,
    max_redirects: int,
    allow_hf_resolve_redirects: bool = False,
    timeout: float = 45,
) -> tuple[int, bytes, str, int]:
    opener = urllib.request.build_opener(_NoRedirects())
    current = url
    redirects = 0
    while True:
        _validate_readback_url(
            current,
            allowed_origins=allowed_origins,
            expected_path=expected_path,
            expected_query=expected_query,
            allow_hf_resolve_redirects=allow_hf_resolve_redirects,
            redirect_step=redirects,
        )
        request = urllib.request.Request(current, headers={"User-Agent": UA})
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                if status in TRANSIENT_HTTP_STATUS:
                    raise TransientReadError(f"HTTP {status}")
                final_url = response.geturl()
                _validate_readback_url(
                    final_url,
                    allowed_origins=allowed_origins,
                    expected_path=expected_path,
                    expected_query=expected_query,
                    allow_hf_resolve_redirects=allow_hf_resolve_redirects,
                    redirect_step=redirects,
                )
                return status, response.read(), final_url, redirects
        except urllib.error.HTTPError as error:
            if error.code in TRANSIENT_HTTP_STATUS:
                raise TransientReadError(f"HTTP {error.code}") from None
            if error.code in {301, 302, 303, 307, 308}:
                if redirects >= max_redirects:
                    raise RuntimeError("public readback redirect limit exceeded")
                location = error.headers.get("Location")
                if not location:
                    raise RuntimeError("public readback redirect omitted Location")
                current = urllib.parse.urljoin(current, location)
                redirects += 1
                continue
            return error.code, error.read(), current, redirects


def _public_bytes(
    url: str,
    *,
    deadline: float,
    label: str,
    allowed_origins: frozenset[str],
    expected_path: str,
    expected_query: str,
    max_redirects: int,
    allow_hf_resolve_redirects: bool = False,
) -> tuple[int, bytes, str, int]:
    return _retry_transient(
        lambda: _public_bytes_once(
            url,
            allowed_origins=allowed_origins,
            expected_path=expected_path,
            expected_query=expected_query,
            max_redirects=max_redirects,
            allow_hf_resolve_redirects=allow_hf_resolve_redirects,
            timeout=_remaining_timeout(deadline, 45),
        ),
        deadline=deadline,
        label=label,
    )


def _public_response_once(
    url: str,
    *,
    allowed_origins: frozenset[str],
    expected_path: str,
    expected_query: str,
    timeout: float,
) -> tuple[int, bytes, str | None]:
    _validate_readback_url(
        url,
        allowed_origins=allowed_origins,
        expected_path=expected_path,
        expected_query=expected_query,
    )
    opener = urllib.request.build_opener(_NoRedirects())
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            if status in TRANSIENT_HTTP_STATUS:
                raise TransientReadError(f"HTTP {status}")
            _validate_readback_url(
                response.geturl(),
                allowed_origins=allowed_origins,
                expected_path=expected_path,
                expected_query=expected_query,
            )
            return status, response.read(), response.headers.get("Location")
    except urllib.error.HTTPError as error:
        if error.code in TRANSIENT_HTTP_STATUS:
            raise TransientReadError(f"HTTP {error.code}") from None
        return error.code, error.read(), error.headers.get("Location")


def _public_response(
    url: str,
    *,
    deadline: float,
    label: str,
    allowed_origins: frozenset[str],
    expected_path: str,
    expected_query: str,
) -> tuple[int, bytes, str | None]:
    return _retry_transient(
        lambda: _public_response_once(
            url,
            allowed_origins=allowed_origins,
            expected_path=expected_path,
            expected_query=expected_query,
            timeout=_remaining_timeout(deadline, 45),
        ),
        deadline=deadline,
        label=label,
    )


def _fetch_public_index(
    origin: str,
    source_sha: str,
    expected_bytes: bytes,
    *,
    deadline: float,
) -> dict[str, object]:
    query = urllib.parse.urlencode({"source": exact_sha(source_sha, "workflow source")})
    root_url = origin + "/?" + query
    status, _, location = _public_response(
        root_url,
        deadline=deadline,
        label="public root redirect readback",
        allowed_origins=frozenset({origin}),
        expected_path="/",
        expected_query=query,
    )
    if status != 302 or not location:
        raise RuntimeError("public root must return exactly one 302 redirect")
    terminal_url = urllib.parse.urljoin(root_url, location)
    _validate_readback_url(
        terminal_url,
        allowed_origins=frozenset({origin}),
        expected_path="/index.html",
        expected_query=query,
    )
    def read_terminal() -> tuple[int, bytes, str | None]:
        response = _public_response(
            terminal_url,
            deadline=deadline,
            label="public index terminal readback",
            allowed_origins=frozenset({origin}),
            expected_path="/index.html",
            expected_query=query,
        )
        if response[0] != 200 or response[2] is not None:
            raise RuntimeError(
                "public index must terminate at one redirect with status 200"
            )
        return response

    while True:
        _, terminal_body, _ = read_terminal()
        try:
            return normalize_public_static_index(terminal_body, expected_bytes)
        except RuntimeError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(RETRY_DELAY_SECONDS, remaining))


def _static_origin() -> str:
    owner, name = HF_REPO.split("/", 1)
    slug = re.sub(r"[^a-z0-9-]+", "-", f"{owner}-{name}".lower()).strip("-")
    return f"https://{slug}.static.hf.space"


def _wait_for_exact_running(
    target_sha: str,
    previous_sha: str,
    *,
    deadline: float,
) -> str:
    target_sha = exact_sha(target_sha, "target Hugging Face revision")
    previous_sha = exact_sha(previous_sha, "previous Hugging Face revision")
    last_stage: object = None
    last_revision: str | None = None
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Space did not reach exact RUNNING revision {target_sha}; "
                f"last revision={last_revision!r}; last stage={last_stage!r}"
            )
        info = _request_json_retry(
            f"https://huggingface.co/api/spaces/{HF_REPO}",
            deadline=deadline,
            label="runtime readback",
        )
        if not isinstance(info, dict) or not isinstance(info.get("runtime"), dict):
            raise RuntimeError("Space runtime response is malformed")
        last_revision = exact_sha(info.get("sha"), "runtime Hugging Face revision")
        last_stage = info["runtime"].get("stage")
        if last_revision != target_sha:
            if last_revision != previous_sha:
                raise RuntimeError(
                    "Space runtime advanced to an unrelated revision: "
                    f"{last_revision}"
                )
            time.sleep(min(10, max(0.0, deadline - time.monotonic())))
            continue
        if last_stage == "RUNNING":
            return "RUNNING"
        if last_stage in TERMINAL_STAGES:
            raise RuntimeError(f"Space reached {last_stage} at {target_sha}")
        if last_stage not in PENDING_STAGES:
            raise RuntimeError(f"Space runtime stage is unsupported: {last_stage!r}")
        time.sleep(min(10, max(0.0, deadline - time.monotonic())))


def _retry_exact_read(
    read_once,
    matches,
    *,
    deadline: float,
    mismatch_message: str,
):
    while True:
        observed = read_once()
        if matches(observed):
            return observed
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(mismatch_message)
        time.sleep(min(2, remaining))


def _verify_exact_hf_revision(
    bundle: Path,
    manifest: dict[str, object],
    target_sha: str,
    *,
    deadline: float,
    retry_byte_mismatch: bool = True,
) -> list[dict[str, object]]:
    target_sha = exact_sha(target_sha, "Hugging Face revision")
    tree = _request_json_retry(
        f"https://huggingface.co/api/spaces/{HF_REPO}/tree/{target_sha}"
        "?recursive=true&expand=false",
        deadline=deadline,
        label="exact-tree readback",
    )
    if not isinstance(tree, list):
        raise RuntimeError("Hugging Face tree response is malformed")
    live_paths = {
        row["path"]
        for row in tree
        if isinstance(row, dict)
        and row.get("type") == "file"
        and isinstance(row.get("path"), str)
    }
    expected_paths = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    extras = live_paths - expected_paths
    if extras - {".gitattributes"}:
        raise RuntimeError(f"unmanaged files remain in live Space: {sorted(extras)}")
    if expected_paths - live_paths:
        raise RuntimeError(
            f"live Space is missing files: {sorted(expected_paths - live_paths)}"
        )

    expected = {
        row["path"]: row
        for row in manifest["files"]
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    manifest_bytes = (bundle / "hf-deploy-manifest.json").read_bytes()
    expected["hf-deploy-manifest.json"] = {
        "bytes": len(manifest_bytes),
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    verified_tree: list[dict[str, object]] = []
    for relative in sorted(expected_paths):
        url = (
            f"https://huggingface.co/spaces/{HF_REPO}/resolve/{target_sha}/"
            f"{urllib.parse.quote(relative, safe='/')}"
        )
        parsed = urllib.parse.urlsplit(url)
        row = expected[relative]

        def read_file() -> tuple[int, bytes, str, int]:
            response = _public_bytes(
                url,
                deadline=deadline,
                label=f"exact-tree file {relative}",
                allowed_origins=frozenset({"https://huggingface.co"}),
                expected_path=parsed.path,
                expected_query=parsed.query,
                max_redirects=3,
                allow_hf_resolve_redirects=True,
            )
            if response[0] != 200:
                raise RuntimeError(
                    f"public live file returned HTTP {response[0]}: {relative}"
                )
            return response

        if retry_byte_mismatch:
            _, data, _, _ = _retry_exact_read(
                read_file,
                lambda response: (
                    len(response[1]) == row["bytes"]
                    and hashlib.sha256(response[1]).hexdigest() == row["sha256"]
                ),
                deadline=deadline,
                mismatch_message=f"public live bytes differ: {relative}",
            )
        else:
            _, data, _, _ = read_file()
            if len(data) != row["bytes"] or sha256_bytes(data) != row["sha256"]:
                raise RuntimeError(f"public live bytes differ: {relative}")
        verified_tree.append(
            {
                "path": relative,
                "bytes": row["bytes"],
                "sha256": row["sha256"],
            }
        )
    return verified_tree


def validate_public_provenance(provenance: object, source_sha: str) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    if not isinstance(provenance, dict):
        raise RuntimeError("public static source identity is not an object")
    source = provenance.get("source")
    if not isinstance(source, dict):
        raise RuntimeError("public static source identity source is not an object")
    if (
        provenance.get("schema") != "szl.deployment-source/v3"
        or source.get("repository") != SOURCE_REPO
        or source.get("commit") != source_sha
        or source.get("relation") != SOURCE_RELATION
    ):
        raise RuntimeError("public static source identity did not close")
    return provenance


def attest_publication(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    attestation_path: Path,
    *,
    timeout: int = ATTEST_TIMEOUT_SECONDS,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    manifest = validate_bundle(bundle, source_sha)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("source_revision") != source_sha or result.get("target") != HF_REPO:
        raise RuntimeError("deployment result is not bound to this source and target")
    target_sha = exact_sha(result.get("hf_revision"), "deployment result revision")
    previous_sha = exact_sha(
        result.get("previous_hf_revision"),
        "deployment result previous revision",
    )

    deadline = time.monotonic() + timeout
    runtime_stage = _wait_for_exact_running(
        target_sha,
        previous_sha,
        deadline=deadline,
    )
    verified_tree = _verify_exact_hf_revision(
        bundle,
        manifest,
        target_sha,
        deadline=deadline,
    )

    origin = _static_origin()
    query = urllib.parse.urlencode({"source": source_sha})
    public_index = _fetch_public_index(
        origin,
        source_sha,
        (bundle / "index.html").read_bytes(),
        deadline=deadline,
    )

    bundled_provenance_bytes = (bundle / "SPACE_PROVENANCE.json").read_bytes()
    try:
        bundled_provenance = json.loads(bundled_provenance_bytes)
    except json.JSONDecodeError as error:
        raise RuntimeError("bundled provenance JSON is malformed") from error
    canonical_provenance_bytes = canonical_json(bundled_provenance)
    if bundled_provenance_bytes != canonical_provenance_bytes:
        raise RuntimeError("bundled provenance is not canonical JSON")
    provenance_url = origin + "/SPACE_PROVENANCE.json?" + query
    def read_provenance() -> tuple[int, bytes, str | None]:
        response = _public_response(
            provenance_url,
            deadline=deadline,
            label="public provenance readback",
            allowed_origins=frozenset({origin}),
            expected_path="/SPACE_PROVENANCE.json",
            expected_query=query,
        )
        if response[0] != 200 or response[2] is not None:
            raise RuntimeError(
                "public provenance must terminate without redirect at status 200"
            )
        return response

    _, provenance_body, _ = _retry_exact_read(
        read_provenance,
        lambda response: response[1] == canonical_provenance_bytes,
        deadline=deadline,
        mismatch_message="public provenance bytes differ from the canonical bundle",
    )
    provenance = validate_public_provenance(
        json.loads(provenance_body),
        source_sha,
    )

    post_publication_main = require_governed_main(source_sha)

    attestation = {
        "schema": "szl.hf-live-attestation/v2",
        "status": "MEASURED",
        "receipt_minted": False,
        "deployment_success": False,
        "source_revision": source_sha,
        "hf_revision": target_sha,
        "runtime_stage": runtime_stage,
        "bundle_sha256": manifest["bundle_sha256"],
        "file_count": len(verified_tree),
        "tree_sha256": hashlib.sha256(canonical_json(verified_tree)).hexdigest(),
        "source": {
            "repository": SOURCE_REPO,
            "revision": source_sha,
            "relation": SOURCE_RELATION,
        },
        "public_index": public_index,
        "public_provenance": {
            "schema": provenance["schema"],
            "source_repository": provenance["source"]["repository"],
            "source_revision": provenance["source"]["commit"],
            "relation": provenance["source"]["relation"],
            "verified": True,
        },
        "post_publication_main": post_publication_main,
        "target": HF_REPO,
    }
    attestation_path.write_bytes(canonical_json(attestation))
    return attestation


def write_failure_evidence(
    path: Path,
    source_sha: str,
    error: Exception,
    result_path: Path,
    mutation_state: dict[str, object] | None = None,
) -> None:
    upload_call_entered = bool(
        mutation_state and mutation_state.get("upload_call_entered") is True
    )
    authoritative_readback_attempted = bool(
        mutation_state
        and mutation_state.get("authoritative_readback_attempted") is True
    )
    published_revision = (
        mutation_state.get("known_hf_revision") if mutation_state else None
    )
    if not (isinstance(published_revision, str) and HEX40.fullmatch(published_revision)):
        published_revision = None
    if result_path.is_file():
        try:
            persisted = json.loads(result_path.read_text(encoding="utf-8"))
            if (
                isinstance(persisted, dict)
                and persisted.get("schema") == "szl.hf-deploy-result/v1"
                and persisted.get("source_revision") == source_sha
                and persisted.get("target") == HF_REPO
            ):
                candidate = persisted.get("hf_revision")
                if isinstance(candidate, str) and HEX40.fullmatch(candidate):
                    published_revision = candidate
                    upload_call_entered = True
                elif (
                    persisted.get("status") == "MUTATION_BOUNDARY_CROSSED"
                    and candidate is None
                    and isinstance(persisted.get("previous_hf_revision"), str)
                    and HEX40.fullmatch(persisted["previous_hf_revision"])
                    and isinstance(persisted.get("bundle_sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", persisted["bundle_sha256"])
                ):
                    upload_call_entered = True
        except (OSError, json.JSONDecodeError):
            pass
    if published_revision:
        status = "PARTIAL_AFTER_MUTATION"
    elif upload_call_entered:
        status = "MUTATION_OUTCOME_UNKNOWN"
    else:
        status = "FAILED_BEFORE_MUTATION"
    message = re.sub(r"hf_[A-Za-z0-9]+", "[REDACTED]", str(error))[:1000]
    path.write_bytes(
        canonical_json(
            {
                "schema": "szl.hf-deploy-failure/v2",
                "status": status,
                "receipt_minted": False,
                "measured": False,
                "deployment_success": False,
                "upload_call_entered": upload_call_entered,
                "authoritative_readback_attempted": authoritative_readback_attempted,
                "source_repository": SOURCE_REPO,
                "source_revision": source_sha,
                "source_relation": SOURCE_RELATION,
                "hf_revision": published_revision,
                "error_type": type(error).__name__,
                "error": message,
                "target": HF_REPO,
            }
        )
    )


def write_workflow_stage_failure(
    path: Path,
    source_sha: str,
    result_path: Path,
    receipt_path: Path,
    *,
    failure_stage: str,
    artifact_outcome: str,
    candidate_receipt_outcome: str,
    oidc_outcome: str,
    finalize_receipt_outcome: str = "skipped",
    terminal_artifact_outcome: str = "skipped",
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    if failure_stage not in {
        "SUCCESS_ARTIFACT_UPLOAD",
        "CANDIDATE_RECEIPT_SYNTHESIS",
        "OIDC_RECEIPT_ATTESTATION",
        "FINAL_RECEIPT_PROMOTION",
        "TERMINAL_SUCCESS_ARTIFACT",
    }:
        raise RuntimeError("workflow receipt failure stage is not supported")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    hf_revision = exact_sha(result.get("hf_revision"), "deployment result revision")
    measurement_valid = (
        result.get("source_revision") != source_sha
        or result.get("target") != HF_REPO
        or receipt.get("status") != "MEASURED"
        or receipt.get("source_revision") != source_sha
        or receipt.get("hf_revision") != hf_revision
        or receipt.get("target") != HF_REPO
        or receipt.get("source")
        != {
            "repository": SOURCE_REPO,
            "revision": source_sha,
            "relation": SOURCE_RELATION,
        }
        or receipt.get("receipt_minted") is not False
        or receipt.get("deployment_success") is not False
    ) is False
    if result.get("source_revision") != source_sha or result.get("target") != HF_REPO:
        raise RuntimeError("deployment result is not exactly source-bound")
    evidence = {
        "schema": "szl.hf-receipt-stage-failure/v2",
        "status": "FAILED_AFTER_LOCAL_MEASUREMENT",
        "failure_stage": failure_stage,
        "deployment_success": False,
        "receipt_minted": False,
        "source_repository": SOURCE_REPO,
        "source_revision": source_sha,
        "source_relation": SOURCE_RELATION,
        "hf_revision": hf_revision,
        "target": HF_REPO,
        "artifact_upload_outcome": artifact_outcome,
        "candidate_receipt_outcome": candidate_receipt_outcome,
        "oidc_attestation_outcome": oidc_outcome,
        "finalize_receipt_outcome": finalize_receipt_outcome,
        "terminal_artifact_outcome": terminal_artifact_outcome,
        "local_measurement_contract_valid": measurement_valid,
        "local_measured_receipt_sha256": hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest(),
    }
    path.write_bytes(canonical_json(evidence))
    return evidence


def _canonical_success_receipt(
    source_sha: str,
    result_path: Path,
    measurement_path: Path,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    measurement_bytes = measurement_path.read_bytes()
    measurement = json.loads(measurement_bytes)
    hf_revision = exact_sha(result.get("hf_revision"), "deployment result revision")
    expected_source = {
        "repository": SOURCE_REPO,
        "revision": source_sha,
        "relation": SOURCE_RELATION,
    }
    if (
        result.get("source_revision") != source_sha
        or result.get("target") != HF_REPO
        or measurement_bytes != canonical_json(measurement)
        or measurement.get("schema") != "szl.hf-live-attestation/v2"
        or measurement.get("status") != "MEASURED"
        or measurement.get("source") != expected_source
        or measurement.get("source_revision") != source_sha
        or measurement.get("hf_revision") != hf_revision
        or measurement.get("target") != HF_REPO
        or measurement.get("receipt_minted") is not False
        or measurement.get("deployment_success") is not False
        or measurement.get("runtime_stage") != "RUNNING"
        or not isinstance(measurement.get("file_count"), int)
        or isinstance(measurement.get("file_count"), bool)
        or measurement.get("file_count", 0) <= 0
        or not isinstance(measurement.get("public_index"), dict)
        or not isinstance(measurement.get("post_publication_main"), dict)
        or not isinstance(measurement.get("public_provenance"), dict)
        or measurement["public_provenance"].get("verified") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(measurement.get("bundle_sha256", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(measurement.get("tree_sha256", "")))
    ):
        raise RuntimeError("local measured evidence is not exactly source-bound and complete")
    receipt = dict(measurement)
    receipt.update(
        {
            "schema": "szl.hf-oidc-receipt/v2",
            "status": "OIDC_ATTESTED_DEPLOYMENT",
            "measurement": {
                "path": measurement_path.name,
                "schema": measurement["schema"],
                "sha256": sha256_bytes(measurement_bytes),
            },
            "receipt_minted": True,
            "deployment_success": True,
        }
    )
    return receipt


def synthesize_candidate_receipt(
    output_path: Path,
    source_sha: str,
    result_path: Path,
    measurement_path: Path,
) -> dict[str, object]:
    receipt = _canonical_success_receipt(source_sha, result_path, measurement_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as handle:
        handle.write(canonical_json(receipt))
    return receipt


def finalize_attested_receipt(
    candidate_path: Path,
    output_path: Path,
    envelope_path: Path,
    source_sha: str,
    result_path: Path,
    measurement_path: Path,
    *,
    attestation_id: str,
    attestation_url: str,
    bundle_path: str,
) -> dict[str, object]:
    expected_receipt = _canonical_success_receipt(
        source_sha, result_path, measurement_path
    )
    candidate_bytes = candidate_path.read_bytes()
    if candidate_bytes != canonical_json(expected_receipt):
        raise RuntimeError("attested candidate receipt bytes are not canonical and exact")
    outputs = (attestation_id, attestation_url, bundle_path)
    if any(not isinstance(value, str) or not value or len(value) > 4096 for value in outputs):
        raise RuntimeError("OIDC attestation outputs are incomplete")
    parsed_url = urllib.parse.urlsplit(attestation_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise RuntimeError("OIDC attestation URL is not HTTPS")
    bundle = Path(bundle_path)
    bundle_bytes = bundle.read_bytes()
    if not bundle_bytes:
        raise RuntimeError("OIDC attestation bundle is empty")
    if output_path.exists() or envelope_path.exists():
        raise RuntimeError("terminal receipt or attestation envelope already exists")
    envelope = {
        "schema": "szl.hf-oidc-attestation-envelope/v1",
        "status": "ATTESTATION_METADATA_BOUND",
        "source": expected_receipt["source"],
        "source_revision": expected_receipt["source_revision"],
        "hf_revision": expected_receipt["hf_revision"],
        "target": HF_REPO,
        "canonical_receipt": {
            "name": output_path.name,
            "sha256": sha256_bytes(candidate_bytes),
        },
        "attestation": {
            "id": attestation_id,
            "url": attestation_url,
            "bundle": {
                "name": bundle.name,
                "sha256": sha256_bytes(bundle_bytes),
            },
        },
    }
    with envelope_path.open("xb") as handle:
        handle.write(canonical_json(envelope))
    candidate_path.replace(output_path)
    if sha256_file(output_path) != envelope["canonical_receipt"]["sha256"]:
        raise RuntimeError("promoted receipt bytes changed after OIDC attestation")
    return envelope


STEP_OUTCOMES = {"success", "failure", "skipped", "cancelled"}


def require_receipt_failure_artifact(
    required: bool,
    primary_outcome: str,
    retry_outcome: str,
) -> None:
    if not required:
        return
    if primary_outcome not in STEP_OUTCOMES or retry_outcome not in STEP_OUTCOMES:
        raise RuntimeError("receipt-stage artifact outcome is malformed")
    if primary_outcome != "success" and retry_outcome != "success":
        raise RuntimeError("receipt-stage failure evidence was not preserved")


def enforce_terminal_evidence(
    *,
    publish_outcome: str,
    artifact_outcome: str,
    candidate_receipt_outcome: str,
    oidc_outcome: str,
    finalize_receipt_outcome: str,
    terminal_artifact_outcome: str,
    failure_synthesis_outcome: str,
    failure_artifact_primary_outcome: str,
    failure_artifact_retry_outcome: str,
) -> dict[str, object]:
    success_path = {
        "publish": publish_outcome,
        "local_artifact": artifact_outcome,
        "candidate_receipt": candidate_receipt_outcome,
        "oidc_attestation": oidc_outcome,
        "receipt_promotion": finalize_receipt_outcome,
        "terminal_artifact": terminal_artifact_outcome,
    }
    if any(outcome not in STEP_OUTCOMES for outcome in success_path.values()):
        raise RuntimeError("terminal publication outcome is malformed")
    receipt_failure_required = publish_outcome == "success" and any(
        outcome != "success"
        for name, outcome in success_path.items()
        if name != "publish"
    )
    if receipt_failure_required and failure_synthesis_outcome != "success":
        raise RuntimeError("receipt-stage failure evidence synthesis did not succeed")
    require_receipt_failure_artifact(
        receipt_failure_required,
        failure_artifact_primary_outcome,
        failure_artifact_retry_outcome,
    )
    failed = [name for name, outcome in success_path.items() if outcome != "success"]
    if failed:
        raise RuntimeError(f"terminal publication evidence is incomplete: {failed}")
    return {"status": "TERMINAL_PUBLICATION_EVIDENCE_COMPLETE"}


def stage_failure_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    parser.add_argument("--failure-stage", required=True)
    parser.add_argument("--artifact-outcome", required=True)
    parser.add_argument("--candidate-receipt-outcome", required=True)
    parser.add_argument("--oidc-outcome", required=True)
    parser.add_argument("--finalize-receipt-outcome", required=True)
    parser.add_argument("--terminal-artifact-outcome", required=True)
    args = parser.parse_args(argv)
    evidence = write_workflow_stage_failure(
        args.failure_evidence,
        args.source_sha,
        args.result,
        args.receipt,
        failure_stage=args.failure_stage,
        artifact_outcome=args.artifact_outcome,
        candidate_receipt_outcome=args.candidate_receipt_outcome,
        oidc_outcome=args.oidc_outcome,
        finalize_receipt_outcome=args.finalize_receipt_outcome,
        terminal_artifact_outcome=args.terminal_artifact_outcome,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


def candidate_receipt_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = synthesize_candidate_receipt(
        args.output,
        args.source_sha,
        args.result,
        args.measurement,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


def finalize_receipt_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--attestation-id", required=True)
    parser.add_argument("--attestation-url", required=True)
    parser.add_argument("--bundle-path", required=True)
    args = parser.parse_args(argv)
    envelope = finalize_attested_receipt(
        args.candidate,
        args.output,
        args.envelope,
        args.source_sha,
        args.result,
        args.measurement,
        attestation_id=args.attestation_id,
        attestation_url=args.attestation_url,
        bundle_path=args.bundle_path,
    )
    print(json.dumps(envelope, sort_keys=True))
    return 0


def enforce_terminal_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish-outcome", required=True)
    parser.add_argument("--artifact-outcome", required=True)
    parser.add_argument("--candidate-receipt-outcome", required=True)
    parser.add_argument("--oidc-outcome", required=True)
    parser.add_argument("--finalize-receipt-outcome", required=True)
    parser.add_argument("--terminal-artifact-outcome", required=True)
    parser.add_argument("--failure-synthesis-outcome", required=True)
    parser.add_argument("--failure-artifact-primary-outcome", required=True)
    parser.add_argument("--failure-artifact-retry-outcome", required=True)
    args = parser.parse_args(argv)
    result = enforce_terminal_evidence(**vars(args))
    print(json.dumps(result, sort_keys=True))
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "upload-child":
        return upload_child_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "stage-failure":
        return stage_failure_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "candidate-receipt":
        return candidate_receipt_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "finalize-receipt":
        return finalize_receipt_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "enforce-terminal":
        return enforce_terminal_main(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    args = parser.parse_args()
    source_sha = exact_sha(args.source_sha, "workflow source")
    mutation_state: dict[str, object] = {}
    try:
        deploy_bundle(args.bundle, source_sha, args.result, mutation_state)
        attestation = attest_publication(
            args.bundle,
            source_sha,
            args.result,
            args.attestation,
        )
    except Exception as error:
        write_failure_evidence(
            args.failure_evidence,
            source_sha,
            error,
            args.result,
            mutation_state,
        )
        raise
    print(json.dumps(attestation, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
