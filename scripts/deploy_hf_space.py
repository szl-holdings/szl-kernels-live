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
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_RULE_TYPES = {"pull_request", "non_fast_forward", "required_linear_history"}
TERMINAL_STAGES = {"BUILD_ERROR", "CONFIG_ERROR", "RUNTIME_ERROR"}
ATTEST_TIMEOUT_SECONDS = 600
UA = "szl-kernels-live-deployer/1.0"


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


def _request_json(url: str, token: str = "") -> object:
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def require_governed_main(source_sha: str) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_ref = os.environ.get("GITHUB_REF", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if repository != SOURCE_REPO:
        raise RuntimeError(f"unexpected GitHub repository: {repository!r}")
    if source_ref != "refs/heads/main":
        raise RuntimeError(f"refusing production release from {source_ref!r}")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required for protected-main reauthorization")

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
    if not isinstance(summaries, list):
        raise RuntimeError("repository ruleset inventory is unavailable")
    accepted: list[int] = []
    for summary in summaries:
        if not isinstance(summary, dict) or summary.get("enforcement") != "active":
            continue
        ruleset_id = summary.get("id")
        if not isinstance(ruleset_id, int):
            continue
        detail = _request_json(
            f"{api_root}/repos/{repository}/rulesets/{ruleset_id}", token
        )
        if not isinstance(detail, dict):
            continue
        include = ((detail.get("conditions") or {}).get("ref_name") or {}).get(
            "include", []
        )
        rule_types = {
            row.get("type")
            for row in detail.get("rules", [])
            if isinstance(row, dict)
        }
        if (
            "~DEFAULT_BRANCH" in include
            and REQUIRED_RULE_TYPES <= rule_types
            and detail.get("bypass_actors") == []
        ):
            accepted.append(ruleset_id)
    if not accepted:
        raise RuntimeError(
            "default branch lacks an active no-bypass PR, non-fast-forward, "
            "linear-history ruleset"
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


def _public_bytes(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _static_origin() -> str:
    owner, name = HF_REPO.split("/", 1)
    slug = re.sub(r"[^a-z0-9-]+", "-", f"{owner}-{name}".lower()).strip("-")
    return f"https://{slug}.static.hf.space"


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
    last_stage = last_sha = None
    while time.monotonic() < deadline:
        info = _request_json(f"https://huggingface.co/api/spaces/{HF_REPO}")
        last_sha = (info if isinstance(info, dict) else {}).get("sha")
        last_stage = ((info if isinstance(info, dict) else {}).get("runtime") or {}).get(
            "stage"
        )
        if last_sha == target_sha and last_stage == "RUNNING":
            break
        if last_sha == target_sha and last_stage in TERMINAL_STAGES:
            raise RuntimeError(f"Space reached {last_stage} at {target_sha}")
        time.sleep(10)
    else:
        raise RuntimeError(
            f"Space did not reach exact RUNNING revision {target_sha}; "
            f"last stage={last_stage!r} sha={last_sha!r}"
        )

    tree = _request_json(
        f"https://huggingface.co/api/spaces/{HF_REPO}/tree/{target_sha}"
        "?recursive=true&expand=false"
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
    for relative in sorted(expected_paths):
        url = (
            f"https://huggingface.co/spaces/{HF_REPO}/resolve/{target_sha}/"
            f"{urllib.parse.quote(relative, safe='/')}"
        )
        status, data = _public_bytes(url)
        row = expected[relative]
        if (
            status != 200
            or len(data) != row["bytes"]
            or hashlib.sha256(data).hexdigest() != row["sha256"]
        ):
            raise RuntimeError(f"public live bytes differ: {relative}")

    origin = _static_origin()
    query = urllib.parse.urlencode({"source": source_sha})
    last_error = "not attempted"
    for attempt in range(12):
        ui_status, ui_body = _public_bytes(origin + "/?" + query)
        provenance_status, provenance_body = _public_bytes(
            origin + "/SPACE_PROVENANCE.json?" + query
        )
        try:
            provenance = json.loads(provenance_body)
        except json.JSONDecodeError:
            provenance = {}
        if (
            ui_status == 200
            and ui_body
            and provenance_status == 200
            and provenance.get("schema") == "szl.deployment-source/v3"
            and (provenance.get("source") or {}).get("commit") == source_sha
        ):
            break
        last_error = (
            f"ui={ui_status}/{len(ui_body)} provenance={provenance_status}/"
            f"{(provenance.get('source') or {}).get('commit')!r}"
        )
        if attempt < 11:
            time.sleep(5)
    else:
        raise RuntimeError(f"public static source identity did not close: {last_error}")

    attestation = {
        "schema": "szl.hf-live-attestation/v1",
        "status": "MEASURED",
        "source_revision": source_sha,
        "hf_revision": target_sha,
        "runtime_stage": "RUNNING",
        "bundle_sha256": manifest["bundle_sha256"],
        "files_verified": len(expected_paths),
        "public_source_identity": True,
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
            published_revision = json.loads(result_path.read_text(encoding="utf-8")).get(
                "hf_revision"
            )
        except (OSError, json.JSONDecodeError):
            pass
    message = re.sub(r"hf_[A-Za-z0-9]+", "[REDACTED]", str(error))[:1000]
    path.write_bytes(
        canonical_json(
            {
                "schema": "szl.hf-live-attestation/v1",
                "status": "FAILED",
                "source_revision": source_sha,
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
        write_failure_evidence(args.attestation, source_sha, error, args.result)
        raise
    print(json.dumps(attestation, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
