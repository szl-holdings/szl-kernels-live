#!/usr/bin/env python3
"""Atomically deploy a prebuilt bundle to the governed SZL Kernels Space."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
GOVERNED_RULESET_SOURCE = "szl-holdings"
GOVERNED_RULESET_SOURCE_TYPE = "Organization"
TERMINAL_STAGES = {"BUILD_ERROR", "CONFIG_ERROR", "RUNTIME_ERROR"}
PENDING_STAGES = {"BUILDING", "APP_STARTING", "STARTING", "RUNNING_BUILDING"}
TRANSIENT_HTTP_STATUS = {429, 500, 502, 503, 504}
ATTEST_TIMEOUT_SECONDS = 600
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


def _request_json(url: str, token: str = "") -> object:
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _request_json_retry(url: str, *, deadline: float, label: str) -> object:
    return _retry_transient(
        lambda: _request_json(url),
        deadline=deadline,
        label=label,
    )


def evaluate_effective_rulesets(
    summaries: object,
    details: dict[int, object],
    effective_rules: object,
) -> tuple[list[int], list[str]]:
    """Prove the exact inherited organization ruleset governs every effective row."""
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
    if summary.get("enforcement") != "active":
        diagnostics.append("inventory enforcement is not active")
    if summary.get("source") != GOVERNED_RULESET_SOURCE:
        diagnostics.append("inventory source is not szl-holdings")
    if summary.get("source_type") != GOVERNED_RULESET_SOURCE_TYPE:
        diagnostics.append("inventory source_type is not Organization")

    detail = details.get(GOVERNED_RULESET_ID)
    if not isinstance(detail, dict):
        diagnostics.append("detail response is unavailable")
        detail = {}
    retrieval_error = detail.get("_retrieval_error")
    if isinstance(retrieval_error, str):
        diagnostics.append(f"detail retrieval failed ({retrieval_error})")
    bypass_actors = detail.get("bypass_actors")
    if not isinstance(bypass_actors, list):
        diagnostics.append("bypass actors were not disclosed")
    elif bypass_actors:
        diagnostics.append(f"{len(bypass_actors)} bypass actor(s) are present")

    observed_types: set[object] = set()
    if not effective_rules:
        diagnostics.append("no effective rule rows were disclosed")
    for index, row in enumerate(effective_rules, start=1):
        if not isinstance(row, dict):
            diagnostics.append(f"effective row {index} is not an object")
            continue
        if row.get("ruleset_id") != GOVERNED_RULESET_ID:
            diagnostics.append(f"effective row {index} has a mixed ruleset id")
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
    if not isinstance(metadata, dict) or metadata.get("default_branch") != "main":
        raise RuntimeError("repository default branch is not main")
    branch = _request_json(f"{api_root}/repos/{repository}/branches/main", token)
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
    if isinstance(summaries, list):
        for summary in summaries:
            ruleset_id = summary.get("id") if isinstance(summary, dict) else None
            if not isinstance(ruleset_id, int):
                continue
            try:
                details[ruleset_id] = _request_json(
                    f"{api_root}/repos/{repository}/rulesets/{ruleset_id}", token
                )
            except Exception as error:
                details[ruleset_id] = {"_retrieval_error": type(error).__name__}
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


def require_exact_main_tip(source_sha: str) -> dict[str, object]:
    """Read GitHub main after public HF readback and reject any source drift."""
    source_sha = exact_sha(source_sha, "workflow source")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GOVERNANCE_TOKEN", "")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if repository != SOURCE_REPO:
        raise RuntimeError(f"unexpected GitHub repository: {repository!r}")
    if not token:
        raise RuntimeError("GOVERNANCE_TOKEN is required for final main-tip readback")
    branch = _request_json(f"{api_root}/repos/{repository}/branches/main", token)
    live_sha = exact_sha(
        ((branch if isinstance(branch, dict) else {}).get("commit") or {}).get("sha"),
        "post-publication protected-main revision",
    )
    if live_sha != source_sha:
        raise RuntimeError(
            f"protected main drifted after publication: {live_sha} != {source_sha}"
        )
    return {
        "status": "EXACT_MAIN_CONFIRMED_AFTER_PUBLIC_READBACK",
        "source_revision": source_sha,
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


def deploy_bundle(bundle: Path, source_sha: str, result_path: Path) -> dict[str, object]:
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
    target_sha = exact_sha(commit.oid, "published Hugging Face revision")
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
            with opener.open(request, timeout=45) as response:
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
        ),
        deadline=deadline,
        label=label,
    )


def _static_origin() -> str:
    owner, name = HF_REPO.split("/", 1)
    slug = re.sub(r"[^a-z0-9-]+", "-", f"{owner}-{name}".lower()).strip("-")
    return f"https://{slug}.static.hf.space"


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
    last_stage = None
    while time.monotonic() < deadline:
        info = _request_json_retry(
            f"https://huggingface.co/api/spaces/{HF_REPO}",
            deadline=deadline,
            label="runtime readback",
        )
        if not isinstance(info, dict) or not isinstance(info.get("runtime"), dict):
            raise RuntimeError("Space runtime response is malformed")
        live_sha = exact_sha(info.get("sha"), "runtime Hugging Face revision")
        if live_sha != target_sha:
            raise RuntimeError(
                f"Space runtime revision differs: {live_sha} != {target_sha}"
            )
        last_stage = info["runtime"].get("stage")
        if last_stage == "RUNNING":
            break
        if last_stage in TERMINAL_STAGES:
            raise RuntimeError(f"Space reached {last_stage} at {target_sha}")
        if last_stage not in PENDING_STAGES:
            raise RuntimeError(f"Space runtime stage is unsupported: {last_stage!r}")
        time.sleep(min(10, max(0.0, deadline - time.monotonic())))
    else:
        raise RuntimeError(
            f"Space did not reach exact RUNNING revision {target_sha}; "
            f"last stage={last_stage!r}"
        )

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
        if isinstance(row, dict) and row.get("type") == "file"
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

    origin = _static_origin()
    query = urllib.parse.urlencode({"source": source_sha})
    ui_url = origin + "/?" + query
    ui_status, ui_body, _, _ = _public_bytes(
        ui_url,
        deadline=deadline,
        label="public index readback",
        allowed_origins=frozenset({origin}),
        expected_path="/",
        expected_query=query,
        max_redirects=1,
    )
    if ui_status != 200 or ui_body != (bundle / "index.html").read_bytes():
        raise RuntimeError("public index bytes differ from the bundled index")

    bundled_provenance_bytes = (bundle / "SPACE_PROVENANCE.json").read_bytes()
    try:
        bundled_provenance = json.loads(bundled_provenance_bytes)
    except json.JSONDecodeError as error:
        raise RuntimeError("bundled provenance JSON is malformed") from error
    canonical_provenance_bytes = canonical_json(bundled_provenance)
    if bundled_provenance_bytes != canonical_provenance_bytes:
        raise RuntimeError("bundled provenance is not canonical JSON")
    provenance_url = origin + "/SPACE_PROVENANCE.json?" + query
    provenance_status, provenance_body, _, _ = _public_bytes(
        provenance_url,
        deadline=deadline,
        label="public provenance readback",
        allowed_origins=frozenset({origin}),
        expected_path="/SPACE_PROVENANCE.json",
        expected_query=query,
        max_redirects=1,
    )
    if provenance_status != 200 or provenance_body != canonical_provenance_bytes:
        raise RuntimeError("public provenance bytes differ from the canonical bundle")
    provenance = validate_public_provenance(
        json.loads(provenance_body),
        source_sha,
    )

    post_publication_main = require_exact_main_tip(source_sha)

    attestation = {
        "schema": "szl.hf-live-attestation/v2",
        "status": "MEASURED",
        "source_revision": source_sha,
        "hf_revision": target_sha,
        "runtime_stage": "RUNNING",
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
    path: Path, source_sha: str, error: Exception, result_path: Path
) -> None:
    published_revision = None
    if result_path.is_file():
        try:
            candidate = json.loads(result_path.read_text(encoding="utf-8")).get(
                "hf_revision"
            )
            if isinstance(candidate, str) and HEX40.fullmatch(candidate):
                published_revision = candidate
        except (OSError, json.JSONDecodeError):
            pass
    message = re.sub(r"hf_[A-Za-z0-9]+", "[REDACTED]", str(error))[:1000]
    path.write_bytes(
        canonical_json(
            {
                "schema": "szl.hf-deploy-failure/v2",
                "status": (
                    "PARTIAL_AFTER_MUTATION"
                    if published_revision
                    else "FAILED_BEFORE_MUTATION"
                ),
                "receipt_minted": False,
                "measured": False,
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    args = parser.parse_args()
    source_sha = exact_sha(args.source_sha, "workflow source")
    try:
        deploy_bundle(args.bundle, source_sha, args.result)
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
        )
        raise
    print(json.dumps(attestation, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
