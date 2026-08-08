#!/usr/bin/env python3
"""Fail-closed offline, live-integrity, and import checks for kernel contracts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_BOUND_STATUS = "SOURCE_BOUND_AUTHORIZED_RELEASE"
CONTRADICTED_STATUS = "SOURCE_BINDING_UNVERIFIED_CONTRADICTED"


def normalize_recorded_at(value: str) -> str:
    try:
        recorded = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as error:
        raise ValueError("recorded_at must be an exact UTC timestamp ending in Z") from error
    return recorded.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def contract_recorded_at(contracts: list[dict]) -> str:
    values = {contract.get("recorded_at") for contract in contracts}
    if len(values) != 1:
        raise ValueError("all contracts must share one recorded_at timestamp")
    value = values.pop()
    if not isinstance(value, str):
        raise ValueError("contract recorded_at must be an exact UTC timestamp")
    return normalize_recorded_at(value)


def receipt_recorded_at(value: str | None, contracts: list[dict]) -> str:
    expected = contract_recorded_at(contracts)
    if value is None:
        return expected
    actual = normalize_recorded_at(value)
    if actual != expected:
        raise ValueError(
            f"receipt recorded_at {actual} does not match contract index {expected}"
        )
    return actual


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
    validate_source_binding(contract)


def validate_source_binding(contract: dict) -> list[str]:
    binding = contract.get("source_binding", {})
    mappings = binding.get("file_mapping")
    if mappings is None:
        if binding.get("status") == SOURCE_BOUND_STATUS:
            raise ValueError(
                f"{contract.get('id')}: source-bound status requires byte mappings"
            )
        return []
    if not isinstance(mappings, list) or not mappings:
        raise ValueError(f"{contract.get('id')}: source file mapping is empty")

    artifacts = {
        row["path"]: row for row in contract.get("artifact", {}).get("files", [])
    }
    mismatches: list[str] = []
    seen: set[str] = set()
    for mapping in mappings:
        source_path = mapping.get("source_path")
        artifact_path = mapping.get("artifact_path")
        if (
            not isinstance(source_path, str)
            or not isinstance(artifact_path, str)
            or artifact_path in seen
        ):
            raise ValueError(f"{contract.get('id')}: invalid source file mapping")
        seen.add(artifact_path)
        artifact = artifacts.get(artifact_path)
        if artifact is None:
            raise ValueError(
                f"{contract.get('id')}: mapped artifact is absent: {artifact_path}"
            )
        if (
            mapping.get("artifact_size") != artifact.get("size")
            or mapping.get("artifact_sha256") != artifact.get("sha256")
        ):
            raise ValueError(
                f"{contract.get('id')}: mapping differs from artifact contract: "
                f"{artifact_path}"
            )
        if not isinstance(mapping.get("source_size"), int) or not HEX64.fullmatch(
            str(mapping.get("source_sha256", ""))
        ):
            raise ValueError(
                f"{contract.get('id')}: malformed protected-source declaration"
            )
        mismatch = (
            mapping["source_size"] != mapping["artifact_size"]
            or mapping["source_sha256"] != mapping["artifact_sha256"]
        )
        expected_status = "MISMATCH" if mismatch else "MATCH"
        if mapping.get("status") != expected_status:
            raise ValueError(
                f"{contract.get('id')}: source mapping status is not recomputed"
            )
        if mismatch:
            mismatches.append(artifact_path)

    status = binding.get("status")
    if status == SOURCE_BOUND_STATUS and mismatches:
        raise ValueError(
            f"{contract.get('id')}: source-bound qualification contradicted by "
            + ", ".join(mismatches)
        )
    if status == CONTRADICTED_STATUS:
        if (
            binding.get("live_artifact_status")
            != "IMMUTABLE_BYTES_AND_CPU_PROBES_VERIFIED"
            or binding.get("source_binding_status") != "UNVERIFIED_CONTRADICTED"
            or not mismatches
        ):
            raise ValueError(
                f"{contract.get('id')}: contradicted source state is incomplete"
            )
    elif mappings and status != SOURCE_BOUND_STATUS:
        raise ValueError(f"{contract.get('id')}: unsupported mapped source status")
    return mismatches


def verify_declared_source(contract: dict) -> None:
    binding = contract.get("source_binding", {})
    mappings = binding.get("file_mapping")
    if not mappings:
        return
    mismatches = validate_source_binding(contract)
    attempt = binding.get("historical_release_attempt", {})
    publication_url = attempt.get("publication_manifest")
    if not isinstance(publication_url, str):
        raise ValueError(f"{contract['id']}: publication manifest URL is missing")
    publication = get_json(publication_url)
    if not isinstance(publication, dict):
        raise ValueError(f"{contract['id']}: publication manifest is malformed")
    source = publication.get("source", {})
    if (
        source.get("revision") != binding.get("revision")
        or source.get("artifact_tree_sha256")
        != attempt.get("declared_artifact_tree_sha256")
        or publication.get("publisher", {}).get("revision")
        != attempt.get("publisher_revision")
    ):
        raise ValueError(f"{contract['id']}: publication manifest binding differs")
    declared_files = {
        row.get("path"): row
        for row in source.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    repository = binding.get("repository")
    revision = binding.get("revision")
    if not isinstance(repository, str) or not isinstance(revision, str):
        raise ValueError(f"{contract['id']}: protected source identity is missing")
    for mapping in mappings:
        source_path = mapping["source_path"]
        declaration = declared_files.get(source_path)
        if (
            declaration is None
            or declaration.get("bytes") != mapping["source_size"]
            or declaration.get("sha256") != mapping["source_sha256"]
        ):
            raise ValueError(
                f"{contract['id']}: publication manifest differs for {source_path}"
            )
        source_url = (
            f"https://raw.githubusercontent.com/{repository}/{revision}/"
            f"{urllib.parse.quote(source_path)}"
        )
        content = get_bytes(source_url)
        if (
            len(content) != mapping["source_size"]
            or hashlib.sha256(content).hexdigest() != mapping["source_sha256"]
        ):
            raise ValueError(
                f"{contract['id']}: protected source bytes differ for {source_path}"
            )
    if binding.get("status") == SOURCE_BOUND_STATUS and mismatches:
        raise ValueError(f"{contract['id']}: exact source qualification rejected")


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


def write_receipt(
    path: Path,
    contracts: list[dict],
    results: list[dict],
    *,
    recorded_at: str | None = None,
) -> None:
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
        "recorded_at": receipt_recorded_at(recorded_at, contracts),
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
    payload = (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as error:
        if path.read_bytes() != payload:
            raise FileExistsError(
                f"refusing to overwrite non-identical receipt: {path}"
            ) from error


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
    parser.add_argument(
        "--recorded-at",
        help="exact UTC receipt timestamp; defaults to the current UTC second",
    )
    args = parser.parse_args()

    contracts = load_contracts(args.contracts.resolve())
    for contract in contracts:
        if args.live:
            verify_live(contract, check_content=True)
            verify_declared_source(contract)
    results: list[dict] = []
    if args.run_imports:
        for contract in contracts:
            results.append(run_probe(contract))
        if args.receipt:
            write_receipt(
                args.receipt.resolve(),
                contracts,
                results,
                recorded_at=args.recorded_at,
            )
    elif args.receipt:
        raise ValueError("--receipt requires --run-imports")
    elif args.recorded_at:
        raise ValueError("--recorded-at requires --receipt")
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
