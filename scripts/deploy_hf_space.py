#!/usr/bin/env python3
"""Atomically deploy a prebuilt bundle to the governed SZL Kernels Space."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
RETRY_DELAY_SECONDS = 2
UA = "szl-kernels-live-deployer/1.0"


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
) -> str | None:
    """Return a post-exception revision only after authoritative exact-byte closure."""
    info = _request_json_retry(
        f"https://huggingface.co/api/spaces/{HF_REPO}",
        deadline=deadline,
        label="ambiguous-mutation authoritative revision readback",
    )
    if not isinstance(info, dict):
        return None
    candidate = exact_sha(info.get("sha"), "authoritative Hugging Face revision")
    if candidate == previous_sha:
        return None
    _verify_exact_hf_revision(bundle, manifest, candidate, deadline=deadline)
    return candidate


def deploy_bundle(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    mutation_state: dict[str, object] | None = None,
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
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    before = api.space_info(HF_REPO, token=token)
    before_sha = exact_sha(before.sha, "observed Hugging Face parent revision")

    mutation_authorization = require_governed_main(source_sha)
    if mutation_authorization != authorization:
        raise RuntimeError("protected-main authorization changed before publication")
    mutation_state["upload_call_entered"] = True
    try:
        commit = api.upload_folder(
            repo_id=HF_REPO,
            repo_type="space",
            folder_path=bundle,
            token=token,
            parent_commit=before_sha,
            delete_patterns="*",
            commit_message=f"Deploy GitHub source {source_sha[:12]}",
            commit_description=(
                f"Source: https://github.com/{SOURCE_REPO}/commit/{source_sha}\n"
                f"Bundle: {manifest['bundle_sha256']}"
            ),
        )
    except Exception:
        mutation_state["authoritative_readback_attempted"] = True
        try:
            recovered = _recover_authoritative_revision(
                bundle,
                manifest,
                before_sha,
                deadline=time.monotonic() + MUTATION_READBACK_SECONDS,
            )
        except Exception:
            recovered = None
        mutation_state["known_hf_revision"] = recovered
        raise
    target_sha = exact_sha(commit.oid, "published Hugging Face revision")
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


def _validate_readback_url(
    url: str,
    *,
    allowed_origins: frozenset[str],
    expected_path: str,
    expected_query: str,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.fragment:
        raise RuntimeError("public readback redirect added a fragment")
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
) -> tuple[int, bytes, str, int]:
    return _retry_transient(
        lambda: _public_bytes_once(
            url,
            allowed_origins=allowed_origins,
            expected_path=expected_path,
            expected_query=expected_query,
            max_redirects=max_redirects,
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
) -> bytes:
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
    terminal_status, terminal_body, second_location = _public_response(
        terminal_url,
        deadline=deadline,
        label="public index terminal readback",
        allowed_origins=frozenset({origin}),
        expected_path="/index.html",
        expected_query=query,
    )
    if terminal_status != 200 or second_location is not None:
        raise RuntimeError("public index must terminate at one redirect with status 200")
    if terminal_body != expected_bytes:
        raise RuntimeError("public index bytes differ from the bundled index")
    return terminal_body


def _static_origin() -> str:
    owner, name = HF_REPO.split("/", 1)
    slug = re.sub(r"[^a-z0-9-]+", "-", f"{owner}-{name}".lower()).strip("-")
    return f"https://{slug}.static.hf.space"


def _wait_for_exact_running(target_sha: str, *, deadline: float) -> str:
    target_sha = exact_sha(target_sha, "target Hugging Face revision")
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
            time.sleep(min(10, max(0.0, deadline - time.monotonic())))
            continue
        if last_stage == "RUNNING":
            return "RUNNING"
        if last_stage in TERMINAL_STAGES:
            raise RuntimeError(f"Space reached {last_stage} at {target_sha}")
        if last_stage not in PENDING_STAGES:
            raise RuntimeError(f"Space runtime stage is unsupported: {last_stage!r}")
        time.sleep(min(10, max(0.0, deadline - time.monotonic())))


def _verify_exact_hf_revision(
    bundle: Path,
    manifest: dict[str, object],
    target_sha: str,
    *,
    deadline: float,
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
        status, data, _, _ = _public_bytes(
            url,
            deadline=deadline,
            label=f"exact-tree file {relative}",
            allowed_origins=frozenset({"https://huggingface.co"}),
            expected_path=parsed.path,
            expected_query=parsed.query,
            max_redirects=0,
        )
        row = expected[relative]
        if (
            status != 200
            or len(data) != row["bytes"]
            or hashlib.sha256(data).hexdigest() != row["sha256"]
        ):
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

    deadline = time.monotonic() + timeout
    runtime_stage = _wait_for_exact_running(target_sha, deadline=deadline)
    verified_tree = _verify_exact_hf_revision(
        bundle,
        manifest,
        target_sha,
        deadline=deadline,
    )

    origin = _static_origin()
    query = urllib.parse.urlencode({"source": source_sha})
    _fetch_public_index(
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
    provenance_status, provenance_body, provenance_location = _public_response(
        provenance_url,
        deadline=deadline,
        label="public provenance readback",
        allowed_origins=frozenset({origin}),
        expected_path="/SPACE_PROVENANCE.json",
        expected_query=query,
    )
    if (
        provenance_status != 200
        or provenance_location is not None
        or provenance_body != canonical_provenance_bytes
    ):
        raise RuntimeError("public provenance bytes differ from the canonical bundle")
    provenance = validate_public_provenance(
        json.loads(provenance_body),
        source_sha,
    )

    post_publication_main = require_governed_main(source_sha)

    attestation = {
        "schema": "szl.hf-live-attestation/v2",
        "status": "MEASURED",
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
    if mutation_state is None and result_path.is_file():
        try:
            candidate = json.loads(result_path.read_text(encoding="utf-8")).get(
                "hf_revision"
            )
            if isinstance(candidate, str) and HEX40.fullmatch(candidate):
                published_revision = candidate
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
    oidc_outcome: str,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    if failure_stage not in {"SUCCESS_ARTIFACT_UPLOAD", "OIDC_RECEIPT_ATTESTATION"}:
        raise RuntimeError("workflow receipt failure stage is not supported")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    hf_revision = exact_sha(result.get("hf_revision"), "deployment result revision")
    if (
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
    ):
        raise RuntimeError("local measured receipt is not exactly source-bound")
    evidence = {
        "schema": "szl.hf-receipt-stage-failure/v1",
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
        "oidc_attestation_outcome": oidc_outcome,
        "local_measured_receipt_sha256": hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest(),
    }
    path.write_bytes(canonical_json(evidence))
    return evidence


def stage_failure_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    parser.add_argument("--failure-stage", required=True)
    parser.add_argument("--artifact-outcome", required=True)
    parser.add_argument("--oidc-outcome", required=True)
    args = parser.parse_args(argv)
    evidence = write_workflow_stage_failure(
        args.failure_evidence,
        args.source_sha,
        args.result,
        args.receipt,
        failure_stage=args.failure_stage,
        artifact_outcome=args.artifact_outcome,
        oidc_outcome=args.oidc_outcome,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "stage-failure":
        return stage_failure_main(sys.argv[2:])
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
