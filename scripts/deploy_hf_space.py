#!/usr/bin/env python3
"""Atomically deploy a prebuilt bundle to the governed SZL Kernels Space."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath


HF_REPO = "SZLHOLDINGS/szl-kernels-live"
SOURCE_REPO = "szl-holdings/szl-kernels-live"


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


def validate_bundle(bundle: Path, source_sha: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise RuntimeError(
            "workflow source must be an exact lowercase 40-character SHA"
        )
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()

    manifest = validate_bundle(args.bundle, args.source_sha)

    token = os.environ.get("HF_TOKEN")
    if not token:
        raise RuntimeError("HF_TOKEN is required in the approved secret store")
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    before = api.space_info(HF_REPO, token=token)
    commit = api.upload_folder(
        repo_id=HF_REPO,
        repo_type="space",
        folder_path=args.bundle,
        token=token,
        parent_commit=before.sha,
        delete_patterns="*",
        commit_message=f"Deploy GitHub source {args.source_sha[:12]}",
        commit_description=(
            f"Source: https://github.com/szl-holdings/szl-kernels-live/commit/"
            f"{args.source_sha}\nBundle: {manifest['bundle_sha256']}"
        ),
    )
    print(
        json.dumps(
            {
                "status": "PUBLISHED",
                "source_revision": args.source_sha,
                "previous_hf_revision": before.sha,
                "hf_revision": commit.oid,
                "bundle_sha256": manifest["bundle_sha256"],
                "target": HF_REPO,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
