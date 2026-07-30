#!/usr/bin/env python3
"""Build the reproducible, source-bound SZL Kernels Hugging Face Space bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HF_REPO = "SZLHOLDINGS/szl-kernels-live"
SOURCE_REPO = "szl-holdings/szl-kernels-live"
INCLUDE_FILES = ("LICENSE", "index.html")
INCLUDE_DIRS = ("contracts", "evidence", "registry", "schemas", "scripts", "tests")
EXCLUDED_NAMES = {"__pycache__", ".pytest_cache"}

HF_FRONT_MATTER = """---
title: SZL Kernel Operations Hub
emoji: "\U0001f9e9"
colorFrom: gray
colorTo: green
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
short_description: Evidence console for ten revision-pinned governed kernels
tags:
- governance
- provenance
- agent-safety
- evaluation
- kernels
- szl-holdings
---
"""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_tree(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        if not path.is_file() or any(part in EXCLUDED_NAMES for part in path.parts):
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def build_bundle(output: Path, source_sha: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("source_sha must be an exact lowercase 40-character Git SHA")
    if output.resolve() == ROOT.resolve() or ROOT.resolve() in output.resolve().parents:
        raise ValueError("output must be outside the source tree")

    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    for name in INCLUDE_FILES:
        shutil.copyfile(ROOT / name, output / name)
    for name in INCLUDE_DIRS:
        copy_tree(ROOT / name, output / name)

    source_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    (output / "README.md").write_text(
        HF_FRONT_MATTER + "\n" + source_readme.rstrip() + "\n",
        encoding="utf-8",
        newline="\n",
    )

    provenance = {
        "schema": "szl.deployment-source/v3",
        "source": {
            "repository": SOURCE_REPO,
            "commit": source_sha,
            "path": "",
            "relation": "source-bound-release-bundle",
            "commit_state": "OBSERVED_GITHUB_WORKFLOW_SHA",
        },
        "deployment": {
            "hf_space": HF_REPO,
            "sdk": "static",
            "current_hf_revision": None,
            "current_hf_revision_state": "NOT_EMBEDDED_STATIC_SELF_REFERENCE",
        },
        "claims": {
            "source_file_digests": "MEASURED_IN_WORKFLOW",
            "current_hf_head": "NOT_EMBEDDED",
            "runtime_quality": "NOT_INFERRED_FROM_DEPLOYMENT",
        },
    }
    (output / "SPACE_PROVENANCE.json").write_bytes(canonical_json(provenance))

    files = []
    for path in sorted(output.rglob("*")):
        if not path.is_file():
            continue
        files.append(
            {
                "path": path.relative_to(output).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    manifest_core = {
        "schema": "szl.hf-deploy-manifest/v1",
        "source_repository": SOURCE_REPO,
        "source_revision": source_sha,
        "target": HF_REPO,
        "file_count": len(files),
        "files": files,
    }
    manifest = {
        **manifest_core,
        "bundle_sha256": hashlib.sha256(canonical_json(manifest_core)).hexdigest(),
    }
    (output / "hf-deploy-manifest.json").write_bytes(canonical_json(manifest))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    manifest = build_bundle(args.output, args.source_sha)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
