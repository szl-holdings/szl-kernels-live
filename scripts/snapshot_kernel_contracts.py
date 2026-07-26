#!/usr/bin/env python3
"""Snapshot immutable Hugging Face Kernel revisions into reviewable contracts.

The pin file is deliberately hand-reviewed. This script never discovers or
advances a revision. It only resolves the exact 40-character revisions already
present in registry/kernel-pins.json and records their file digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = ROOT / "registry" / "kernel-pins.json"
CONTRACTS_DIR = ROOT / "contracts"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def get_json(url: str) -> object:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "szl-kernels-live/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def get_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "szl-kernels-live/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def load_pins() -> dict:
    pins = json.loads(PINS_PATH.read_text(encoding="utf-8"))
    kernels = pins.get("kernels")
    if not isinstance(kernels, list) or len(kernels) != 10:
        raise ValueError("pin registry must contain exactly ten kernels")
    seen: set[str] = set()
    for kernel in kernels:
        kernel_id = kernel.get("id")
        revision = kernel.get("revision")
        if not isinstance(kernel_id, str) or kernel_id in seen:
            raise ValueError(f"invalid or duplicate kernel id: {kernel_id!r}")
        if not isinstance(revision, str) or not HEX40.fullmatch(revision):
            raise ValueError(f"{kernel_id}: revision must be a full lowercase SHA")
        seen.add(kernel_id)
    return pins


def snapshot_kernel(kernel: dict, recorded_at: str) -> dict:
    kernel_id = kernel["id"]
    revision = kernel["revision"]
    detail = get_json(f"https://huggingface.co/api/kernels/{kernel_id}")
    if not isinstance(detail, dict):
        raise ValueError(f"{kernel_id}: malformed Hugging Face response")
    if detail.get("sha") != revision:
        raise ValueError(
            f"{kernel_id}: live head {detail.get('sha')} differs from reviewed pin "
            f"{revision}; review and update the pin explicitly"
        )

    tree_url = (
        f"https://huggingface.co/api/kernels/{kernel_id}/tree/{revision}/"
        "build/torch-cpu?recursive=true&expand=false"
    )
    tree = get_json(tree_url)
    if not isinstance(tree, list):
        raise ValueError(f"{kernel_id}: malformed build tree")

    files: list[dict] = []
    for entry in tree:
        if not isinstance(entry, dict) or entry.get("type") != "file":
            continue
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or not path.startswith("build/torch-cpu/")
            or ".." in Path(path).parts
        ):
            raise ValueError(f"{kernel_id}: unsafe build path {path!r}")
        content = get_bytes(
            f"https://huggingface.co/kernels/{kernel_id}/resolve/{revision}/{path}"
        )
        expected_size = entry.get("size")
        if expected_size != len(content):
            raise ValueError(
                f"{kernel_id}:{path}: API size {expected_size} != {len(content)}"
            )
        files.append(
            {
                "path": path,
                "size": len(content),
                "git_oid": entry.get("oid"),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    files.sort(key=lambda row: row["path"])
    if not files:
        raise ValueError(f"{kernel_id}: no build/torch-cpu files found")

    tree_digest = hashlib.sha256(canonical_json(files)).hexdigest()
    status = kernel["portfolio_status"]
    replacement = "SZLHOLDINGS/szl-kernels" if status == "RETAINED_COMPATIBILITY" else None
    dependencies = kernel.get("dependencies", [])
    optional_dependencies = kernel.get("optional_dependencies", [])
    package = kernel["probe"]["package"]

    return {
        "$schema": "../../schemas/kernel-contract.schema.json",
        "schema_version": "1.0.0",
        "id": kernel_id,
        "title": kernel["title"],
        "summary": kernel["summary"],
        "revision": revision,
        "recorded_at": recorded_at,
        "artifact": {
            "repo_type": "kernel",
            "build": "torch-cpu",
            "tree_url": (
                f"https://huggingface.co/kernels/{kernel_id}/tree/{revision}/"
                "build/torch-cpu"
            ),
            "files": files,
            "tree_digest_sha256": tree_digest,
        },
        "loading": {
            "method": "kernels.get_kernel",
            "trust_remote_code": True,
            "revision_required": True,
            "example": (
                "from kernels import get_kernel\n"
                f'kernel = get_kernel("{kernel_id}", '
                f'revision="{revision}", trust_remote_code=True)'
            ),
        },
        "runtime": {
            "classification": "PYTHON_GOVERNANCE_KERNEL",
            "packages": kernel["packages"],
            "dependencies": dependencies,
            "optional_dependencies": optional_dependencies,
            "python": ">=3.9",
            "artifact_build": "torch-cpu",
            "hf_declared_driver_families": [],
            "measured_compatibility": {
                "status": "MEASURED",
                "receipt": "../../evidence/kernel-selfcheck-20260726.json",
                "environment": "Windows amd64, Python 3.11, CPU execution",
            },
        },
        "probe": kernel["probe"],
        "source_binding": kernel["source_binding"],
        "limitations": kernel["limitations"],
        "deprecation": {
            "status": status,
            "replacement": replacement,
        },
        "generation": {
            "tool": "scripts/snapshot_kernel_contracts.py",
            "mode": "reviewed immutable pin; no automatic revision advancement",
            "primary_package": package,
        },
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=CONTRACTS_DIR,
        help="Contract output directory (defaults to ./contracts)",
    )
    args = parser.parse_args()
    pins = load_pins()
    contracts = [
        snapshot_kernel(kernel, pins["recorded_at"]) for kernel in pins["kernels"]
    ]

    output = args.output.resolve()
    for contract, seed in zip(contracts, pins["kernels"], strict=True):
        write_json(output / seed["slug"] / "contract.json", contract)
    index = {
        "schema_version": "1.0.0",
        "recorded_at": pins["recorded_at"],
        "doctrine": pins["doctrine"],
        "kernels": [
            {
                "id": contract["id"],
                "slug": seed["slug"],
                "title": contract["title"],
                "summary": contract["summary"],
                "revision": contract["revision"],
                "tree_digest_sha256": contract["artifact"]["tree_digest_sha256"],
                "portfolio_status": contract["deprecation"]["status"],
                "source_status": contract["source_binding"]["status"],
                "contract": f"{seed['slug']}/contract.json",
                "limitations": contract["limitations"],
            }
            for contract, seed in zip(contracts, pins["kernels"], strict=True)
        ],
    }
    write_json(output / "index.json", index)
    print(f"wrote {len(contracts)} immutable contracts to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
