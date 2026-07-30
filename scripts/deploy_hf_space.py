#!/usr/bin/env python3
"""Atomically deploy a prebuilt bundle to the governed SZL Kernels Space."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from huggingface_hub import HfApi


HF_REPO = "SZLHOLDINGS/szl-kernels-live"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        raise RuntimeError("HF_TOKEN is required in the approved secret store")
    manifest_path = args.bundle / "hf-deploy-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("source_revision") != args.source_sha:
        raise RuntimeError("bundle source revision does not match workflow source")
    if manifest.get("target") != HF_REPO:
        raise RuntimeError("bundle target does not match the governed Space")

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
