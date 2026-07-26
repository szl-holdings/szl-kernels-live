#!/usr/bin/env python3
"""Fail-closed offline, live-integrity, and import checks for kernel contracts."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import tempfile
from typing import Any
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def get_json(url: str) -> object:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "szl-kernels-live/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def get_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "szl-kernels-live/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def dotted(value: object, path: str) -> object:
    current = value
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise ValueError(f"probe result has no {path!r}")
        current = current[segment]
    return current


def validate_contract(contract: dict) -> None:
    kernel_id = contract.get("id")
    revision = contract.get("revision")
    if contract.get("schema_version") != "1.0.0":
        raise ValueError(f"{kernel_id}: unsupported schema version")
    if not isinstance(kernel_id, str) or not kernel_id.startswith("SZLHOLDINGS/"):
        raise ValueError(f"invalid kernel id: {kernel_id!r}")
    if not isinstance(revision, str) or not HEX40.fullmatch(revision):
        raise ValueError(f"{kernel_id}: exact 40-character revision required")
    loading = contract.get("loading", {})
    if (
        loading.get("trust_remote_code") is not True
        or loading.get("revision_required") is not True
        or revision not in loading.get("example", "")
    ):
        raise ValueError(f"{kernel_id}: immutable trusted loading contract missing")
    artifact = contract.get("artifact", {})
    files = artifact.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError(f"{kernel_id}: empty artifact manifest")
    paths: set[str] = set()
    for row in files:
        path = row.get("path")
        if (
            not isinstance(path, str)
            or not path.startswith("build/torch-cpu/")
            or ".." in Path(path).parts
            or path in paths
        ):
            raise ValueError(f"{kernel_id}: invalid or duplicate path {path!r}")
        paths.add(path)
        if not isinstance(row.get("size"), int) or row["size"] < 0:
            raise ValueError(f"{kernel_id}:{path}: invalid size")
        if not isinstance(row.get("sha256"), str) or not HEX64.fullmatch(
            row["sha256"]
        ):
            raise ValueError(f"{kernel_id}:{path}: invalid SHA-256")
    actual_tree = hashlib.sha256(canonical_json(files)).hexdigest()
    if artifact.get("tree_digest_sha256") != actual_tree:
        raise ValueError(f"{kernel_id}: artifact tree digest mismatch")
    if contract.get("runtime", {}).get("hf_declared_driver_families") != []:
        raise ValueError(
            f"{kernel_id}: driver support cannot be inferred for this portfolio"
        )
    limitations = contract.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        raise ValueError(f"{kernel_id}: limitations are required")


def load_contracts(contracts_dir: Path) -> list[dict]:
    index = json.loads((contracts_dir / "index.json").read_text(encoding="utf-8"))
    rows = index.get("kernels")
    if not isinstance(rows, list) or len(rows) != 10:
        raise ValueError("contracts/index.json must enumerate exactly ten kernels")
    contracts: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        path = contracts_dir / row["contract"]
        contract = json.loads(path.read_text(encoding="utf-8"))
        validate_contract(contract)
        if contract["id"] in seen:
            raise ValueError(f"duplicate contract id {contract['id']}")
        if (
            row.get("id") != contract["id"]
            or row.get("revision") != contract["revision"]
            or row.get("tree_digest_sha256")
            != contract["artifact"]["tree_digest_sha256"]
        ):
            raise ValueError(f"{contract['id']}: index/contract mismatch")
        seen.add(contract["id"])
        contracts.append(contract)
    return contracts


def verify_live(contract: dict, *, check_content: bool) -> None:
    kernel_id = contract["id"]
    revision = contract["revision"]
    detail = get_json(f"https://huggingface.co/api/kernels/{kernel_id}")
    if not isinstance(detail, dict) or detail.get("sha") != revision:
        raise ValueError(
            f"{kernel_id}: live head drifted from {revision} to "
            f"{detail.get('sha') if isinstance(detail, dict) else 'UNKNOWN'}"
        )
    tree = get_json(
        f"https://huggingface.co/api/kernels/{kernel_id}/tree/{revision}/"
        "build/torch-cpu?recursive=true&expand=false"
    )
    if not isinstance(tree, list):
        raise ValueError(f"{kernel_id}: malformed live tree")
    live_files = {
        row["path"]: row
        for row in tree
        if isinstance(row, dict) and row.get("type") == "file"
    }
    expected = {row["path"]: row for row in contract["artifact"]["files"]}
    if set(live_files) != set(expected):
        raise ValueError(f"{kernel_id}: live file set differs from contract")
    for path, row in expected.items():
        live = live_files[path]
        if live.get("size") != row["size"] or live.get("oid") != row["git_oid"]:
            raise ValueError(f"{kernel_id}:{path}: live metadata differs")
        if check_content:
            content = get_bytes(
                f"https://huggingface.co/kernels/{kernel_id}/resolve/"
                f"{revision}/{path}"
            )
            if hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise ValueError(f"{kernel_id}:{path}: content digest differs")


def download_build(contract: dict, root: Path) -> Path:
    kernel_id = contract["id"]
    revision = contract["revision"]
    for row in contract["artifact"]["files"]:
        path = row["path"]
        content = get_bytes(
            f"https://huggingface.co/kernels/{kernel_id}/resolve/{revision}/{path}"
        )
        if len(content) != row["size"]:
            raise ValueError(f"{kernel_id}:{path}: downloaded size mismatch")
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise ValueError(f"{kernel_id}:{path}: downloaded SHA-256 mismatch")
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    return root / "build" / "torch-cpu"


def run_probe(contract: dict) -> dict:
    kernel_id = contract["id"]
    probe = contract["probe"]
    packages = contract["runtime"]["packages"]
    with tempfile.TemporaryDirectory(prefix="szl-kernel-") as temp:
        build = download_build(contract, Path(temp))
        sys.path.insert(0, str(build))
        try:
            imported = [importlib.import_module(name) for name in packages]
            if probe["kind"] == "selfcheck":
                module = importlib.import_module(probe["package"])
                result = getattr(module, probe["call"])(**probe.get("kwargs", {}))
                if not isinstance(result, dict):
                    raise ValueError(f"{kernel_id}: self-check did not return an object")
                for path in probe["required_truthy"]:
                    if dotted(result, path) is not True:
                        raise ValueError(
                            f"{kernel_id}: self-check assertion {path!r} failed"
                        )
                return {
                    "status": "PASS",
                    "imports": [module.__name__ for module in imported],
                    "probe": probe["kind"],
                    "assertions": probe["required_truthy"],
                    "result": result,
                }
            if probe["kind"] == "deny_default":
                module = importlib.import_module(probe["package"])
                called: list[bool] = []
                result = module.governed_call(
                    lambda: called.append(True) or "unexpected execution"
                )
                if (
                    type(result).__name__ != probe["required_result_type"]
                    or len(called) != probe["required_callable_count"]
                ):
                    raise ValueError(f"{kernel_id}: default-deny probe failed")
                return {
                    "status": "PASS",
                    "imports": [module.__name__ for module in imported],
                    "probe": probe["kind"],
                    "result_type": type(result).__name__,
                    "callable_executions": len(called),
                    "reason": result.decision.reason,
                }
            raise ValueError(f"{kernel_id}: unknown probe kind {probe['kind']!r}")
        finally:
            sys.path.remove(str(build))
            for name in list(sys.modules):
                if any(name == package or name.startswith(package + ".") for package in packages):
                    del sys.modules[name]


def write_receipt(path: Path, contracts: list[dict], results: list[dict]) -> None:
    torch_version = None
    try:
        import torch

        torch_version = torch.__version__
    except ImportError:
        pass
    receipt = {
        "schema_version": "1.0.0",
        "claim_class": "MEASURED",
        "scope": "revision-pinned CPU imports and declared probes",
        "recorded_at": "2026-07-26T03:00:00Z",
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "architecture": platform.machine(),
            "execution_device": "CPU",
            "torch": torch_version,
        },
        "summary": {
            "kernels": len(contracts),
            "passed": sum(result["status"] == "PASS" for result in results),
            "failed": sum(result["status"] != "PASS" for result in results),
        },
        "results": [
            {
                "id": contract["id"],
                "revision": contract["revision"],
                "tree_digest_sha256": contract["artifact"]["tree_digest_sha256"],
                **result,
            }
            for contract, result in zip(contracts, results, strict=True)
        ],
        "limitations": [
            "This receipt records CPU imports and functional probes, not GPU performance.",
            "No CUDA or ROCm driver family is inferred from successful torch imports.",
            "Self-check fixtures are not independent security or correctness audits.",
        ],
    }
    receipt["payload_sha256"] = hashlib.sha256(canonical_json(receipt)).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contracts", type=Path, default=CONTRACTS_DIR)
    parser.add_argument("--live", action="store_true", help="verify live head and content")
    parser.add_argument(
        "--run-imports",
        action="store_true",
        help="download exact builds, import packages, and run declared probes",
    )
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()

    contracts = load_contracts(args.contracts.resolve())
    for contract in contracts:
        if args.live:
            verify_live(contract, check_content=True)
    results: list[dict] = []
    if args.run_imports:
        for contract in contracts:
            results.append(run_probe(contract))
        if args.receipt:
            write_receipt(args.receipt.resolve(), contracts, results)
    elif args.receipt:
        raise ValueError("--receipt requires --run-imports")
    print(
        f"PASS: {len(contracts)} offline contracts"
        + ("; live heads and contents match" if args.live else "")
        + (f"; {len(results)} imports/probes passed" if results else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL-CLOSED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
