#!/usr/bin/env python3
"""Atomically deploy a prebuilt bundle to the governed SZL Kernels Space."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
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
AUTHORIZED_INPUT_SCHEMA = "szl.kernel-authorized-input/v1"
PUBLIC_MAIN_SCHEMA = "szl.github-public-main-readback/v1"
PUBLIC_MAIN_URL = f"https://api.github.com/repos/{SOURCE_REPO}/branches/main"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
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
PUBLIC_INDEX_TRANSFORMATION = "HF_WINDOW_HUGGINGFACE_HEAD_INJECTION_V1"
PUBLIC_INDEX_FIELDS = frozenset(
    {
        "transformation",
        "normalized_bytes",
        "normalized_sha256",
        "injection_bytes",
        "injection_sha256",
    }
)
TERMINAL_EVIDENCE_RESERVE_SECONDS = 600
TERMINAL_DEADLINE_ENV = "HF_TERMINAL_DEADLINE_EPOCH"
DEADLINE_ACTION_INPUT_PREFIX = "DEADLINE_ACTION_INPUT_"
BOUNDED_NODE_VERSION = "24.19.0"
ACTIONS_RUNTIME_CREDENTIALS = frozenset(
    {
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
        "ACTIONS_CACHE_URL",
    }
)
OIDC_CREDENTIALS = frozenset(
    {"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"}
)
GITHUB_API_CREDENTIALS = frozenset(
    {"GITHUB_TOKEN", "GH_TOKEN", "GOVERNANCE_TOKEN"}
)
BOUNDED_ACTIONS = {
    "attest-build-provenance": {
        # The pinned wrapper delegates empty custom-predicate inputs to
        # actions/attest, whose pinned runtime selects SLSA build provenance.
        "mode": "build-provenance",
        "entry": "terminal-actions/attest/dist/index.js",
        "sha256": "b8b1ab02d45833f537b3622cccfdfbc27c5523f232de324a51c22e465e8c6353",
        "contract": "terminal-actions/attest-build-provenance/action.yml",
        "contract_sha256": "61c3292878304ea717f372f6b6b7c0b5ae6a132b91622c97529b11d02ea8da4d",
        "inputs": frozenset(
            {
                "subject-path",
                "subject-digest",
                "subject-name",
                "subject-checksums",
                "predicate-type",
                "predicate",
                "predicate-path",
                "push-to-registry",
                "create-storage-record",
                "show-summary",
                "github-token",
            }
        ),
        "defaults": {
            "subject-digest": "",
            "subject-name": "",
            "subject-checksums": "",
            "predicate-type": "",
            "predicate": "",
            "predicate-path": "",
            "push-to-registry": "false",
            "create-storage-record": "true",
            "show-summary": "true",
        },
    },
    "upload": {
        "entry": "terminal-actions/upload-artifact/dist/upload/index.js",
        "sha256": "eea594941d8ee535974e0fbc03bbdf567f3abc78194f224b93f2df9a887ee2e9",
        "inputs": frozenset(
            {
                "name",
                "path",
                "if-no-files-found",
                "retention-days",
                "compression-level",
                "overwrite",
                "include-hidden-files",
                "archive",
            }
        ),
        "defaults": {
            "compression-level": "6",
            "overwrite": "false",
            "include-hidden-files": "false",
            "archive": "true",
        },
    },
}


def _load_governance_module():
    path = Path(__file__).with_name("github_governed_merge.py")
    spec = importlib.util.spec_from_file_location("szl_kernel_governed_merge", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("governed-merge module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GOVERNANCE = _load_governance_module()
GOVERNED_MAIN_STATUS = GOVERNANCE.GOVERNED_MAIN_STATUS


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
        "transformation": PUBLIC_INDEX_TRANSFORMATION,
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
            result = operation()
            if time.monotonic() >= deadline:
                raise RetryExhausted(f"{label} shared deadline expired")
            return result
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


def _workflow_terminal_deadline(*, required: bool = True) -> float | None:
    raw_deadline = os.environ.get(TERMINAL_DEADLINE_ENV, "")
    if not raw_deadline:
        if required:
            raise RuntimeError(f"{TERMINAL_DEADLINE_ENV} is required")
        return None
    if not raw_deadline.isdigit():
        raise RuntimeError(f"{TERMINAL_DEADLINE_ENV} is malformed")
    remaining = int(raw_deadline) - time.time()
    if remaining <= 0:
        raise RetryExhausted("shared terminal-evidence deadline expired")
    return time.monotonic() + remaining


def _workflow_operation_deadline() -> float:
    terminal_deadline = _workflow_terminal_deadline()
    assert terminal_deadline is not None
    operation_deadline = terminal_deadline - TERMINAL_EVIDENCE_RESERVE_SECONDS
    _remaining_timeout(operation_deadline, max(0.001, operation_deadline - time.monotonic()))
    return operation_deadline


def _require_workflow_terminal_budget() -> None:
    terminal_deadline = _workflow_terminal_deadline(required=False)
    if terminal_deadline is not None:
        _remaining_timeout(
            terminal_deadline,
            max(0.001, terminal_deadline - time.monotonic()),
        )


def _kill_bounded_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def _run_bounded_process(
    command: list[str],
    *,
    deadline: float,
    max_seconds: float,
    environment: dict[str, str] | None = None,
) -> None:
    timeout = _remaining_timeout(deadline, max_seconds)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        env=environment,
        start_new_session=os.name != "nt",
    )
    try:
        process.wait(timeout=_remaining_timeout(deadline, timeout))
    except subprocess.TimeoutExpired:
        _kill_bounded_process(process)
        raise TimeoutError("bounded external action exceeded its absolute deadline") from None
    except BaseException:
        _kill_bounded_process(process)
        raise
    if time.monotonic() >= deadline:
        raise RetryExhausted("bounded external action returned after its absolute deadline")
    if process.returncode != 0:
        raise RuntimeError("bounded external action failed")


def run_bounded_action(
    action: str,
    *,
    reserve_seconds: int,
    max_seconds: int,
) -> None:
    if action not in BOUNDED_ACTIONS:
        raise RuntimeError("bounded external action is not allowlisted")
    if reserve_seconds < 60 or reserve_seconds > TERMINAL_EVIDENCE_RESERVE_SECONDS:
        raise RuntimeError("bounded external action reserve is invalid")
    if max_seconds < 1 or max_seconds > 300:
        raise RuntimeError("bounded external action cap is invalid")
    raw_deadline = os.environ.get(TERMINAL_DEADLINE_ENV, "")
    if not raw_deadline.isdigit():
        raise RuntimeError(f"{TERMINAL_DEADLINE_ENV} is required and must be numeric")
    remaining = int(raw_deadline) - reserve_seconds - time.time()
    if remaining <= 0:
        raise RetryExhausted("bounded external action reserve is exhausted")
    deadline = time.monotonic() + remaining

    workspace_raw = os.environ.get("GITHUB_WORKSPACE", "")
    if not workspace_raw:
        raise RuntimeError("GITHUB_WORKSPACE is required for bounded external actions")
    workspace = Path(workspace_raw).resolve()
    descriptor = BOUNDED_ACTIONS[action]
    entry = (workspace / str(descriptor["entry"])).resolve()
    expected_entry = (workspace / str(descriptor["entry"])).resolve()
    if entry != expected_entry or not entry.is_file() or entry.is_symlink():
        raise RuntimeError("bounded external action entry is missing or unsafe")
    if sha256_file(entry) != descriptor["sha256"]:
        raise RuntimeError("bounded external action entry digest differs")
    contract_relative = descriptor.get("contract")
    if contract_relative is not None:
        contract = (workspace / str(contract_relative)).resolve()
        expected_contract = (workspace / str(contract_relative)).resolve()
        if (
            contract != expected_contract
            or not contract.is_file()
            or contract.is_symlink()
        ):
            raise RuntimeError("bounded external action contract is missing or unsafe")
        if sha256_file(contract) != descriptor["contract_sha256"]:
            raise RuntimeError("bounded external action contract digest differs")
    node = shutil.which("node")
    if not node:
        raise RuntimeError("pinned runner Node runtime is unavailable")
    node_version = subprocess.run(
        [node, "-p", "process.versions.node"],
        check=True,
        capture_output=True,
        text=True,
        timeout=_remaining_timeout(deadline, 5),
    ).stdout.strip()
    if node_version != BOUNDED_NODE_VERSION:
        raise RuntimeError("bounded external action Node runtime is not exact")

    child_environment = dict(os.environ)
    inputs: dict[str, str] = {}
    for name in list(child_environment):
        if name.startswith(DEADLINE_ACTION_INPUT_PREFIX):
            suffix = name[len(DEADLINE_ACTION_INPUT_PREFIX) :]
            if not suffix or not re.fullmatch(r"[A-Z][A-Z0-9_]*", suffix):
                raise RuntimeError("bounded external action input name is malformed")
            inputs[suffix.lower().replace("_", "-")] = child_environment.pop(name)
    action_credential = child_environment.pop(
        "DEADLINE_ACTION_GITHUB_CREDENTIAL",
        None,
    )
    if action_credential is not None:
        inputs["github-token"] = action_credential
    if not inputs:
        raise RuntimeError("bounded external action has no declared inputs")
    if set(inputs) != descriptor["inputs"]:
        raise RuntimeError("bounded external action inputs are not exact")
    for name, expected in descriptor["defaults"].items():
        if inputs.get(name) != expected:
            raise RuntimeError("bounded external action defaults are not exact")
    if action == "attest-build-provenance":
        if descriptor.get("mode") != "build-provenance":
            raise RuntimeError("bounded attestation mode is not exact")
        if any(
            inputs[name]
            for name in ("predicate-type", "predicate", "predicate-path")
        ):
            raise RuntimeError(
                "bounded build provenance must use the pinned runtime default"
            )
    for name, value in inputs.items():
        child_environment[f"INPUT_{name.upper()}"] = value
    scrubbed = frozenset({"HF_TOKEN"}) | GITHUB_API_CREDENTIALS
    if action == "upload":
        scrubbed |= OIDC_CREDENTIALS
    else:
        scrubbed |= ACTIONS_RUNTIME_CREDENTIALS
    for secret_name in scrubbed:
        child_environment.pop(secret_name, None)

    _run_bounded_process(
        [node, str(entry)],
        deadline=deadline,
        max_seconds=float(max_seconds),
        environment=child_environment,
    )


def _request_json(url: str, token: str = "", timeout: float = 30) -> object:
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _request_json_retry(
    url: str,
    *,
    deadline: float,
    label: str,
    token: str = "",
) -> object:
    return _retry_transient(
        lambda: _request_json(
            url,
            token,
            timeout=_remaining_timeout(deadline, 30),
        ),
        deadline=deadline,
        label=label,
    )


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


def _safe_authorized_relative(path: str) -> PurePosixPath:
    relative = PurePosixPath(path)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(part.startswith(".") for part in relative.parts)
    ):
        raise RuntimeError("authorized input contains an unsafe path")
    return relative


def _authorized_input_entries(root: Path, manifest_path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path == manifest_path:
            continue
        if path.is_symlink():
            raise RuntimeError("authorized input contains a symbolic path")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError("authorized input contains a non-regular path")
        relative = path.relative_to(root).as_posix()
        _safe_authorized_relative(relative)
        entries.append(
            {"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    return entries


def seal_authorized_input(root: Path, source_sha: str, manifest_path: Path) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "authorized input source")
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    if not root.is_dir() or manifest_path.parent != root or manifest_path.exists():
        raise RuntimeError("authorized input seal location is not exact")
    entries = _authorized_input_entries(root, manifest_path)
    manifest = {
        "schema": AUTHORIZED_INPUT_SCHEMA,
        "source_revision": source_sha,
        "file_count": len(entries),
        "files": entries,
        "tree_sha256": sha256_bytes(canonical_json(entries)),
    }
    manifest_path.write_bytes(canonical_json(manifest))
    return manifest


def validate_authorized_input(
    root: Path,
    source_sha: str,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "authorized input source")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256):
        raise RuntimeError("authorized input manifest digest is malformed")
    root = root.resolve()
    manifest_path = root / "authorized-input-manifest.json"
    if not root.is_dir() or manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("authorized input manifest is missing or unsafe")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise RuntimeError("authorized input contains a symbolic path")
    raw = manifest_path.read_bytes()
    if sha256_bytes(raw) != expected_manifest_sha256:
        raise RuntimeError("authorized input manifest digest differs")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("authorized input manifest is malformed") from error
    if (
        not isinstance(manifest, dict)
        or raw != canonical_json(manifest)
        or set(manifest) != {"schema", "source_revision", "file_count", "files", "tree_sha256"}
        or manifest.get("schema") != AUTHORIZED_INPUT_SCHEMA
        or manifest.get("source_revision") != source_sha
        or not isinstance(manifest.get("files"), list)
        or type(manifest.get("file_count")) is not int
        or manifest["file_count"] != len(manifest["files"])
    ):
        raise RuntimeError("authorized input manifest contract is not exact")
    observed_paths: set[str] = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise RuntimeError("authorized input manifest entry is malformed")
        relative = _safe_authorized_relative(str(entry.get("path", "")))
        normalized = relative.as_posix()
        if normalized in observed_paths:
            raise RuntimeError("authorized input manifest contains a duplicate path")
        observed_paths.add(normalized)
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("authorized input file is missing or unsafe")
        if type(entry.get("bytes")) is not int or entry["bytes"] != path.stat().st_size:
            raise RuntimeError("authorized input byte count differs")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            raise RuntimeError("authorized input file digest is malformed")
        if sha256_file(path) != entry["sha256"]:
            raise RuntimeError("authorized input file digest differs")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual != observed_paths:
        raise RuntimeError("authorized input tree is not closed by its manifest")
    if manifest.get("tree_sha256") != sha256_bytes(canonical_json(manifest["files"])):
        raise RuntimeError("authorized input tree digest differs")
    return manifest


def _public_main_readback_is_exact(value: object, source_sha: str) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {"schema", "transport", "repository", "ref", "revision", "protected"}
        and value.get("schema") == PUBLIC_MAIN_SCHEMA
        and value.get("transport") == "UNAUTHENTICATED_PUBLIC_GITHUB_API"
        and value.get("repository") == SOURCE_REPO
        and value.get("ref") == "refs/heads/main"
        and value.get("revision") == source_sha
        and value.get("protected") is True
    )


def _require_public_main_revision(source_sha: str, *, deadline: float) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "public main source")

    def request_once() -> dict[str, object]:
        request = urllib.request.Request(
            PUBLIC_MAIN_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": UA,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        opener = urllib.request.build_opener(_NoRedirects)
        with opener.open(request, timeout=_remaining_timeout(deadline, 20)) as response:
            if response.status != 200 or response.geturl() != PUBLIC_MAIN_URL:
                raise RuntimeError("public main readback did not terminate exactly")
            payload = json.load(response)
        commit = payload.get("commit") if isinstance(payload, dict) else None
        revision = exact_sha(
            commit.get("sha") if isinstance(commit, dict) else None,
            "public main revision",
        )
        if not isinstance(payload, dict) or payload.get("protected") is not True:
            raise RuntimeError("public main readback is not protected")
        if revision != source_sha:
            raise RuntimeError(f"current public main {revision} differs from source {source_sha}")
        return {
            "schema": PUBLIC_MAIN_SCHEMA,
            "transport": "UNAUTHENTICATED_PUBLIC_GITHUB_API",
            "repository": SOURCE_REPO,
            "ref": "refs/heads/main",
            "revision": source_sha,
            "protected": True,
        }

    return _retry_transient(request_once, deadline=deadline, label="public main readback")


def _load_public_main_readback(path: Path, source_sha: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("public main readback evidence is unreadable") from error
    if raw != canonical_json(value) or not _public_main_readback_is_exact(value, source_sha):
        raise RuntimeError("public main readback evidence is not canonical and exact")
    return value


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


def _hf_upload_child_environment() -> dict[str, str]:
    """Return the complete, minimal environment for the HF mutation child."""
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise RuntimeError("HF_TOKEN is required in the approved secret store")
    return {"HF_TOKEN": token}


def _present_credentials(names: frozenset[str]) -> list[str]:
    return sorted(name for name in names if os.environ.get(name))


def _require_authorization_privilege_domain() -> None:
    present = _present_credentials(
        frozenset({"HF_TOKEN"}) | OIDC_CREDENTIALS | ACTIONS_RUNTIME_CREDENTIALS
    )
    if present:
        raise RuntimeError(
            "GitHub authorization received forbidden HF, OIDC, or runtime credentials: "
            + ",".join(present)
        )


def _require_publisher_privilege_domain() -> None:
    present = _present_credentials(
        GITHUB_API_CREDENTIALS | OIDC_CREDENTIALS | ACTIONS_RUNTIME_CREDENTIALS
    )
    if present:
        raise RuntimeError(
            "HF publisher received forbidden GitHub or OIDC credentials: "
            + ",".join(present)
        )


def _require_measurement_privilege_domain() -> None:
    present = _present_credentials(
        frozenset({"HF_TOKEN"}) | OIDC_CREDENTIALS | ACTIONS_RUNTIME_CREDENTIALS
    )
    if present:
        raise RuntimeError(
            "public measurement received forbidden HF or OIDC credentials: "
            + ",".join(present)
        )


def _upload_call_entered_marker_is_exact(entered_marker: Path) -> bool:
    try:
        return (
            not entered_marker.is_symlink()
            and entered_marker.is_file()
            and entered_marker.read_bytes() == b"UPLOAD_CALL_ENTERED\n"
        )
    except OSError:
        return False


def _run_killable_child(
    command: list[str],
    *,
    deadline: float,
    entered_marker: Path,
    mutation_state: dict[str, object],
    environment: dict[str, str] | None = None,
) -> None:
    wait_timeout = _remaining_timeout(
        deadline,
        max(0.001, deadline - time.monotonic()),
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=os.name != "nt",
    )
    try:
        wait_timeout = _remaining_timeout(deadline, wait_timeout)
        process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        mutation_state["upload_call_entered"] = _upload_call_entered_marker_is_exact(
            entered_marker
        )
        _kill_and_reap_child(process)
        raise TimeoutError("Hugging Face upload child exceeded its wall-clock deadline") from None
    except BaseException:
        mutation_state["upload_call_entered"] = _upload_call_entered_marker_is_exact(
            entered_marker
        )
        _kill_and_reap_child(process)
        raise
    finally:
        mutation_state["upload_call_entered"] = _upload_call_entered_marker_is_exact(
            entered_marker
        )
    if process.returncode != 0:
        raise RuntimeError("Hugging Face upload child failed")


def _kill_and_reap_child(process: subprocess.Popen[bytes]) -> None:
    """Boundedly terminate and reap a spawned upload child."""
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                "Hugging Face upload child could not be reaped after termination"
            ) from error


def upload_child_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--entered-marker", type=Path, required=True)
    parser.add_argument("--main-guard-result", type=Path, required=True)
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
    pre_mutation_main = _require_public_main_revision(
        source_sha,
        deadline=time.monotonic() + 30,
    )
    args.main_guard_result.parent.mkdir(parents=True, exist_ok=True)
    with args.main_guard_result.open("xb") as handle:
        handle.write(canonical_json(pre_mutation_main))
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
    authorization_path: Path,
    authorized_input_root: Path | None = None,
    authorized_input_manifest_sha256: str | None = None,
    mutation_timeout: float = MUTATION_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> dict[str, object]:
    if mutation_state is None:
        mutation_state = {}
    mutation_state.update(
        {
            "upload_call_entered": False,
            "authoritative_readback_attempted": False,
            "known_hf_revision": None,
            "pre_mutation_main": None,
            "post_mutation_main": None,
        }
    )
    _require_publisher_privilege_domain()
    source_sha = exact_sha(source_sha, "workflow source")
    manifest = validate_bundle(bundle, source_sha)
    authorization = GOVERNANCE.load_governed_merge(authorization_path, source_sha)
    if (authorized_input_root is None) != (authorized_input_manifest_sha256 is None):
        raise RuntimeError("authorized input root and manifest digest must be supplied together")
    if authorized_input_root is not None and authorized_input_manifest_sha256 is not None:
        validate_authorized_input(
            authorized_input_root,
            source_sha,
            authorized_input_manifest_sha256,
        )
        input_manifest_sha256 = authorized_input_manifest_sha256
    else:
        # Direct low-level unit calls remain possible; production CLI requires both arguments.
        input_manifest_sha256 = "0" * 64
    if deadline is None:
        deadline = time.monotonic() + mutation_timeout

    child_environment = _hf_upload_child_environment()
    mutation_deadline = min(deadline, time.monotonic() + mutation_timeout)
    before = _request_json_retry(
        f"https://huggingface.co/api/spaces/{HF_REPO}",
        deadline=mutation_deadline,
        label="pre-mutation Hugging Face parent readback",
    )
    if not isinstance(before, dict):
        raise RuntimeError("pre-mutation Hugging Face response is malformed")
    before_sha = exact_sha(before.get("sha"), "observed Hugging Face parent revision")

    mutation_authorization = authorization
    mutation_boundary = {
        "schema": "szl.hf-deploy-result/v3",
        "status": "MUTATION_CHILD_PREPARED",
        "source_revision": source_sha,
        "previous_hf_revision": before_sha,
        "hf_revision": None,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": HF_REPO,
        "authorization": mutation_authorization,
        "authorized_input_manifest_sha256": input_manifest_sha256,
        "pre_mutation_main": None,
        "post_mutation_main": None,
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("xb") as handle:
        handle.write(canonical_json(mutation_boundary))
    nonce = f"{os.getpid()}-{time.monotonic_ns()}"
    entered_marker = result_path.parent / f".hf-upload-entered-{nonce}"
    child_result = result_path.parent / f".hf-upload-result-{nonce}.json"
    main_guard_result = result_path.parent / f".github-main-guard-{nonce}.json"
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
        "--main-guard-result",
        str(main_guard_result.resolve()),
        "--child-result",
        str(child_result.resolve()),
    ]
    try:
        _run_killable_child(
            child_command,
            deadline=upload_deadline,
            entered_marker=entered_marker,
            mutation_state=mutation_state,
            environment=child_environment,
        )
        child_value = json.loads(child_result.read_text(encoding="utf-8"))
        pre_mutation_main = _load_public_main_readback(main_guard_result, source_sha)
        mutation_state["pre_mutation_main"] = pre_mutation_main
        target_sha = exact_sha(
            child_value.get("hf_revision") if isinstance(child_value, dict) else None,
            "published Hugging Face revision",
        )
    except Exception as upload_error:
        if main_guard_result.is_file():
            mutation_state["pre_mutation_main"] = _load_public_main_readback(
                main_guard_result,
                source_sha,
            )
        upload_call_entered = _upload_call_entered_marker_is_exact(entered_marker)
        mutation_state["upload_call_entered"] = upload_call_entered
        if not upload_call_entered:
            mutation_state["authoritative_readback_attempted"] = False
            raise
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
        main_guard_result.unlink(missing_ok=True)
    if mutation_state.get("upload_call_entered") is True:
        mutation_boundary["status"] = "MUTATION_BOUNDARY_CROSSED"
        result_path.write_bytes(canonical_json(mutation_boundary))
    mutation_state["known_hf_revision"] = target_sha
    post_mutation_main = _require_public_main_revision(
        source_sha,
        deadline=mutation_deadline,
    )
    mutation_state["post_mutation_main"] = post_mutation_main
    pre_mutation_main = mutation_state.get("pre_mutation_main")
    if not _public_main_readback_is_exact(pre_mutation_main, source_sha):
        raise RuntimeError("pre-mutation public main evidence is incomplete")
    result = {
        "schema": "szl.hf-deploy-result/v3",
        "status": "PUBLISHED_AWAITING_ATTESTATION",
        "source_revision": source_sha,
        "previous_hf_revision": before_sha,
        "hf_revision": target_sha,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": HF_REPO,
        "authorization": mutation_authorization,
        "authorized_input_manifest_sha256": input_manifest_sha256,
        "pre_mutation_main": pre_mutation_main,
        "post_mutation_main": post_mutation_main,
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
    authorization_path: Path,
    event_path: Path,
    authorization_output_path: Path,
    authorization_failure_output_path: Path,
    authorized_input_root: Path | None = None,
    authorized_input_manifest_sha256: str | None = None,
    timeout: int = ATTEST_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> dict[str, object]:
    _require_measurement_privilege_domain()
    source_sha = exact_sha(source_sha, "workflow source")
    manifest = validate_bundle(bundle, source_sha)
    authorization = GOVERNANCE.load_governed_merge(authorization_path, source_sha)
    if (authorized_input_root is None) != (authorized_input_manifest_sha256 is None):
        raise RuntimeError("authorized input root and manifest digest must be supplied together")
    if authorized_input_root is not None and authorized_input_manifest_sha256 is not None:
        validate_authorized_input(
            authorized_input_root,
            source_sha,
            authorized_input_manifest_sha256,
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if (
        result.get("schema") != "szl.hf-deploy-result/v3"
        or result.get("status") != "PUBLISHED_AWAITING_ATTESTATION"
        or result.get("source_revision") != source_sha
        or result.get("target") != HF_REPO
    ):
        raise RuntimeError("deployment result is not bound to this source and target")
    result_manifest_sha256 = result.get("authorized_input_manifest_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(result_manifest_sha256 or "")):
        raise RuntimeError("deployment result authorized input digest is malformed")
    if (
        authorized_input_manifest_sha256 is not None
        and result_manifest_sha256 != authorized_input_manifest_sha256
    ):
        raise RuntimeError("deployment result authorized input digest differs")
    if not _public_main_readback_is_exact(result.get("pre_mutation_main"), source_sha):
        raise RuntimeError("deployment result lacks exact pre-mutation main evidence")
    if not _public_main_readback_is_exact(result.get("post_mutation_main"), source_sha):
        raise RuntimeError("deployment result lacks exact post-mutation main evidence")
    if result.get("authorization") != authorization:
        raise RuntimeError("deployment result authorization is not canonical and exact")
    target_sha = exact_sha(result.get("hf_revision"), "deployment result revision")
    previous_sha = exact_sha(
        result.get("previous_hf_revision"),
        "deployment result previous revision",
    )

    if deadline is None:
        deadline = time.monotonic() + timeout
    else:
        _remaining_timeout(deadline, max(0.001, deadline - time.monotonic()))
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

    post_publication_main = GOVERNANCE.require_governed_main(
        source_sha,
        event_path,
        authorization_output_path,
        failure_output_path=authorization_failure_output_path,
        deadline=deadline,
    )
    if (
        GOVERNANCE.governed_merge_core(post_publication_main, source_sha)
        != GOVERNANCE.governed_merge_core(authorization, source_sha)
    ):
        raise RuntimeError("post-publication governed-merge tuple changed")

    attestation = {
        "schema": "szl.hf-live-attestation/v4",
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
        "authorization": authorization,
        "authorized_input_manifest_sha256": result_manifest_sha256,
        "pre_mutation_main": result["pre_mutation_main"],
        "post_mutation_main": result["post_mutation_main"],
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
    pre_mutation_main = mutation_state.get("pre_mutation_main") if mutation_state else None
    post_mutation_main = mutation_state.get("post_mutation_main") if mutation_state else None
    if not _public_main_readback_is_exact(pre_mutation_main, source_sha):
        pre_mutation_main = None
    if not _public_main_readback_is_exact(post_mutation_main, source_sha):
        post_mutation_main = None
    if not (isinstance(published_revision, str) and HEX40.fullmatch(published_revision)):
        published_revision = None
    if result_path.is_file():
        try:
            persisted = json.loads(result_path.read_text(encoding="utf-8"))
            if (
                isinstance(persisted, dict)
                and persisted.get("schema") == "szl.hf-deploy-result/v3"
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
                "schema": "szl.hf-deploy-failure/v3",
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
                "pre_mutation_main": pre_mutation_main,
                "post_mutation_main": post_mutation_main,
                "error_type": type(error).__name__,
                "error": message,
                "target": HF_REPO,
            }
        )
    )


def validate_deployment_failure_receipt(
    path: Path,
    source_sha: str,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise RuntimeError("required failed-deployment receipt is missing or unreadable") from error
    if not payload:
        raise RuntimeError("required failed-deployment receipt is empty")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("required failed-deployment receipt is malformed JSON") from error
    required_fields = {
        "schema",
        "status",
        "receipt_minted",
        "measured",
        "deployment_success",
        "upload_call_entered",
        "authoritative_readback_attempted",
        "source_repository",
        "source_revision",
        "source_relation",
        "hf_revision",
        "pre_mutation_main",
        "post_mutation_main",
        "error_type",
        "error",
        "target",
    }
    if not isinstance(value, dict) or set(value) != required_fields:
        raise RuntimeError("required failed-deployment receipt fields are not exact")
    if payload != canonical_json(value):
        raise RuntimeError("required failed-deployment receipt is not canonical JSON")
    if value.get("schema") != "szl.hf-deploy-failure/v3":
        raise RuntimeError("required failed-deployment receipt schema is not exact")
    if value.get("status") not in {
        "FAILED_BEFORE_MUTATION",
        "MUTATION_OUTCOME_UNKNOWN",
        "PARTIAL_AFTER_MUTATION",
    }:
        raise RuntimeError("required failed-deployment receipt status is invalid")
    if any(value.get(field) is not False for field in ("receipt_minted", "measured", "deployment_success")):
        raise RuntimeError("required failed-deployment receipt contains a success contradiction")
    if not isinstance(value.get("upload_call_entered"), bool) or not isinstance(
        value.get("authoritative_readback_attempted"), bool
    ):
        raise RuntimeError("required failed-deployment receipt booleans are invalid")
    if (
        value.get("source_repository") != SOURCE_REPO
        or value.get("source_revision") != source_sha
        or value.get("source_relation") != SOURCE_RELATION
        or value.get("target") != HF_REPO
    ):
        raise RuntimeError("required failed-deployment receipt provenance is not exact")
    revision = value.get("hf_revision")
    if revision is not None and not (
        isinstance(revision, str) and HEX40.fullmatch(revision)
    ):
        raise RuntimeError("required failed-deployment receipt revision is invalid")
    if value["status"] == "PARTIAL_AFTER_MUTATION" and revision is None:
        raise RuntimeError("partial failed-deployment receipt lacks its revision")
    if (
        value["status"] == "PARTIAL_AFTER_MUTATION"
        and not value["upload_call_entered"]
    ):
        raise RuntimeError("partial failed-deployment receipt lacks its mutation marker")
    if value["status"] != "PARTIAL_AFTER_MUTATION" and revision is not None:
        raise RuntimeError("failed-deployment receipt revision contradicts its status")
    pre_mutation_main = value.get("pre_mutation_main")
    post_mutation_main = value.get("post_mutation_main")
    if pre_mutation_main is not None and not _public_main_readback_is_exact(
        pre_mutation_main, source_sha
    ):
        raise RuntimeError("failed-deployment pre-mutation main evidence is invalid")
    if post_mutation_main is not None and not _public_main_readback_is_exact(
        post_mutation_main, source_sha
    ):
        raise RuntimeError("failed-deployment post-mutation main evidence is invalid")
    if value["status"] == "FAILED_BEFORE_MUTATION" and post_mutation_main is not None:
        raise RuntimeError("failed-before-mutation receipt has post-mutation evidence")
    if value["status"] == "FAILED_BEFORE_MUTATION" and value["upload_call_entered"]:
        raise RuntimeError("failed-before-mutation receipt contradicts its mutation marker")
    if (
        value["status"] == "FAILED_BEFORE_MUTATION"
        and value["authoritative_readback_attempted"]
    ):
        raise RuntimeError("failed-before-mutation receipt contradicts authoritative readback")
    if value["status"] == "MUTATION_OUTCOME_UNKNOWN" and not value["upload_call_entered"]:
        raise RuntimeError("unknown mutation receipt lacks its mutation marker")
    if (
        value["status"] == "MUTATION_OUTCOME_UNKNOWN"
        and not value["authoritative_readback_attempted"]
    ):
        raise RuntimeError("unknown mutation receipt lacks authoritative readback")
    if not isinstance(value.get("error_type"), str) or not value["error_type"]:
        raise RuntimeError("required failed-deployment receipt error type is invalid")
    if not isinstance(value.get("error"), str) or not value["error"] or len(value["error"]) > 1000:
        raise RuntimeError("required failed-deployment receipt error is invalid")
    return value


def write_workflow_stage_failure(
    path: Path,
    source_sha: str,
    result_path: Path,
    receipt_path: Path,
    *,
    failure_stage: str,
    publisher_artifact_outcome: str | None = None,
    measurement_artifact_outcome: str | None = None,
    candidate_receipt_outcome: str,
    oidc_outcome: str,
    finalize_receipt_outcome: str = "skipped",
    terminal_artifact_outcome: str = "skipped",
    cleanup_complete: bool = True,
    artifact_outcome: str | None = None,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    if measurement_artifact_outcome is None:
        measurement_artifact_outcome = artifact_outcome
    if publisher_artifact_outcome is None:
        publisher_artifact_outcome = "success"
    if measurement_artifact_outcome is None:
        raise RuntimeError("measurement artifact outcome is required")
    if failure_stage not in {
        "PUBLISHER_MUTATION",
        "PUBLIC_MEASUREMENT",
        "PUBLISHER_EVIDENCE_TRANSPORT",
        "MEASUREMENT_EVIDENCE_TRANSPORT",
        "CANDIDATE_RECEIPT_SYNTHESIS",
        "OIDC_RECEIPT_ATTESTATION",
        "FINAL_RECEIPT_PROMOTION",
        "TERMINAL_SUCCESS_ARTIFACT",
    }:
        raise RuntimeError("workflow receipt failure stage is not supported")
    result_status, result_bytes, result = _read_workflow_json(result_path)
    measurement_status, measurement_bytes, measurement = _read_workflow_json(
        receipt_path
    )
    violations: list[str] = []
    if result is not None and measurement is not None and measurement_bytes is not None:
        violations = _success_contract_violations(
            source_sha,
            result,
            measurement,
            measurement_bytes,
        )
        if any(item.startswith("result.") for item in violations):
            result_status = "INVALID_CONTRACT"
        if any(item.startswith("measurement.") for item in violations):
            measurement_status = "INVALID_CONTRACT"
        if any(item.startswith("cross.") for item in violations):
            result_status = "CONTRADICTED"
            measurement_status = "CONTRADICTED"
    measurement_valid = (
        result_status == "PARSED"
        and measurement_status == "PARSED"
        and not violations
    )

    def sanitized_outcome(value: str) -> str:
        return value if value in STEP_OUTCOMES else "unknown"

    evidence = {
        "schema": "szl.hf-receipt-stage-failure/v4",
        "status": (
            "FAILED_AFTER_LOCAL_MEASUREMENT"
            if measurement_valid
            else "WORKFLOW_STAGE_FAILURE"
        ),
        "failure_stage": failure_stage,
        "deployment_success": False,
        "receipt_minted": False,
        "source_repository": SOURCE_REPO,
        "source_revision": source_sha,
        "source_relation": SOURCE_RELATION,
        "target": HF_REPO,
        "publisher_artifact_outcome": sanitized_outcome(publisher_artifact_outcome),
        "measurement_artifact_outcome": sanitized_outcome(measurement_artifact_outcome),
        "candidate_receipt_outcome": sanitized_outcome(candidate_receipt_outcome),
        "oidc_attestation_outcome": sanitized_outcome(oidc_outcome),
        "finalize_receipt_outcome": sanitized_outcome(finalize_receipt_outcome),
        "terminal_artifact_outcome": sanitized_outcome(terminal_artifact_outcome),
        "cleanup_complete": cleanup_complete is True,
        "result_input_status": result_status,
        "measurement_input_status": measurement_status,
        "contract_violations": violations,
        "local_measurement_contract_valid": measurement_valid,
    }
    if measurement_valid:
        evidence.update(
            {
                "hf_revision": result["hf_revision"],
                "bundle_sha256": measurement["bundle_sha256"],
                "local_measured_receipt_sha256": hashlib.sha256(
                    measurement_bytes
                ).hexdigest(),
                "deployment_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(evidence))
    return evidence


MAX_WORKFLOW_EVIDENCE_BYTES = 1024 * 1024


def _read_workflow_json(
    path: Path,
) -> tuple[str, bytes | None, dict[str, object] | None]:
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return "MISSING", None, None
    except OSError:
        return "UNREADABLE", None, None
    if len(payload) > MAX_WORKFLOW_EVIDENCE_BYTES:
        return "OVERSIZED", None, None
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "INVALID_JSON", None, None
    if not isinstance(parsed, dict):
        return "INVALID_CONTRACT", payload, None
    return "PARSED", payload, parsed


def _is_exact_public_index_proof(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != PUBLIC_INDEX_FIELDS:
        return False
    normalized_bytes = value.get("normalized_bytes")
    injection_bytes = value.get("injection_bytes")
    normalized_digest = value.get("normalized_sha256")
    injection_digest = value.get("injection_sha256")
    minimum_injection_bytes = (
        len(HF_WINDOW_PREFIX) + len(b"{}") + len(HF_WINDOW_TERMINATOR)
    )
    return all(
        (
            value.get("transformation") == PUBLIC_INDEX_TRANSFORMATION,
            isinstance(normalized_bytes, int),
            not isinstance(normalized_bytes, bool),
            normalized_bytes >= len(HTML_HEAD_BOUNDARY),
            isinstance(normalized_digest, str),
            re.fullmatch(r"[0-9a-f]{64}", normalized_digest) is not None,
            isinstance(injection_bytes, int),
            not isinstance(injection_bytes, bool),
            minimum_injection_bytes <= injection_bytes <= HF_WINDOW_MAX_INJECTION_BYTES,
            isinstance(injection_digest, str),
            re.fullmatch(r"[0-9a-f]{64}", injection_digest) is not None,
        )
    )


def _manifest_tree_sha256(
    manifest: dict[str, object],
    *,
    bundle: Path | None = None,
) -> str:
    entries = manifest.get("files")
    if not isinstance(entries, list) or not all(isinstance(row, dict) for row in entries):
        raise RuntimeError("revalidated manifest tree is malformed")
    tree = [
        {
            "path": row["path"],
            "bytes": row["bytes"],
            "sha256": row["sha256"],
        }
        for row in entries
    ]
    if bundle is not None:
        if any(row["path"] == "hf-deploy-manifest.json" for row in tree):
            raise RuntimeError("revalidated manifest tree duplicates its manifest")
        manifest_bytes = (bundle / "hf-deploy-manifest.json").read_bytes()
        tree.append(
            {
                "path": "hf-deploy-manifest.json",
                "bytes": len(manifest_bytes),
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            }
        )
    tree.sort(key=lambda row: row["path"])
    return hashlib.sha256(canonical_json(tree)).hexdigest()


def _manifest_contract_file_count(
    manifest: dict[str, object],
    *,
    bundle: Path | None = None,
) -> object:
    file_count = manifest.get("file_count")
    if (
        bundle is not None
        and isinstance(file_count, int)
        and not isinstance(file_count, bool)
    ):
        return file_count + 1
    return file_count


def _success_contract_violations(
    source_sha: str,
    result: dict[str, object],
    measurement: dict[str, object],
    measurement_bytes: bytes,
    manifest: dict[str, object] | None = None,
    bundle: Path | None = None,
) -> list[str]:
    expected_source = {
        "repository": SOURCE_REPO,
        "revision": source_sha,
        "relation": SOURCE_RELATION,
    }
    violations: list[str] = []
    expected_index: dict[str, object] | None = None
    if manifest is not None:
        entries = manifest.get("files")
        matches = (
            [entry for entry in entries if entry.get("path") == "index.html"]
            if isinstance(entries, list)
            and all(isinstance(entry, dict) for entry in entries)
            else []
        )
        if len(matches) != 1:
            violations.append("manifest.index_html")
        else:
            expected_index = matches[0]

    if result.get("schema") != "szl.hf-deploy-result/v3":
        violations.append("result.schema")
    if result.get("status") != "PUBLISHED_AWAITING_ATTESTATION":
        violations.append("result.status")
    if result.get("source_revision") != source_sha:
        violations.append("result.source_revision")
    if result.get("target") != HF_REPO:
        violations.append("result.target")
    if not isinstance(result.get("hf_revision"), str) or not HEX40.fullmatch(
        result["hf_revision"]
    ):
        violations.append("result.hf_revision")
    result_bundle = result.get("bundle_sha256")
    if not isinstance(result_bundle, str) or not re.fullmatch(
        r"[0-9a-f]{64}", result_bundle
    ):
        violations.append("result.bundle_sha256")
    result_authorization = result.get("authorization")
    if not GOVERNANCE.governed_merge_is_exact(result_authorization, source_sha):
        violations.append("result.authorization")
    result_input_manifest = result.get("authorized_input_manifest_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(result_input_manifest or "")):
        violations.append("result.authorized_input_manifest_sha256")
    if not _public_main_readback_is_exact(result.get("pre_mutation_main"), source_sha):
        violations.append("result.pre_mutation_main")
    if not _public_main_readback_is_exact(result.get("post_mutation_main"), source_sha):
        violations.append("result.post_mutation_main")

    if measurement_bytes != canonical_json(measurement):
        violations.append("measurement.canonical_json")
    if measurement.get("schema") != "szl.hf-live-attestation/v4":
        violations.append("measurement.schema")
    if measurement.get("status") != "MEASURED":
        violations.append("measurement.status")
    if measurement.get("source") != expected_source:
        violations.append("measurement.source")
    if measurement.get("source_revision") != source_sha:
        violations.append("measurement.source_revision")
    if measurement.get("hf_revision") != result.get("hf_revision"):
        violations.append("cross.hf_revision")
    if measurement.get("target") != HF_REPO:
        violations.append("measurement.target")
    if measurement.get("receipt_minted") is not False:
        violations.append("measurement.receipt_minted")
    if measurement.get("deployment_success") is not False:
        violations.append("measurement.deployment_success")
    if measurement.get("runtime_stage") != "RUNNING":
        violations.append("measurement.runtime_stage")
    file_count = measurement.get("file_count")
    if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count <= 0:
        violations.append("measurement.file_count")
    measurement_bundle = measurement.get("bundle_sha256")
    if not isinstance(measurement_bundle, str) or not re.fullmatch(
        r"[0-9a-f]{64}", measurement_bundle
    ):
        violations.append("measurement.bundle_sha256")
    if (
        isinstance(result_bundle, str)
        and isinstance(measurement_bundle, str)
        and result_bundle != measurement_bundle
    ):
        violations.append("cross.bundle_sha256")
    if manifest is not None and result_bundle != manifest.get("bundle_sha256"):
        violations.append("cross.result_bundle_manifest")
    measurement_tree = measurement.get("tree_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(measurement_tree or "")):
        violations.append("measurement.tree_sha256")
    elif manifest is not None and measurement_tree != _manifest_tree_sha256(manifest, bundle=bundle):
        violations.append("cross.tree_sha256_manifest")

    public_index = measurement.get("public_index")
    if not _is_exact_public_index_proof(public_index):
        violations.append("measurement.public_index_proof")
    elif expected_index is not None:
        if public_index["normalized_bytes"] != expected_index.get("bytes"):
            violations.append("cross.public_index_normalized_bytes")
        if public_index["normalized_sha256"] != expected_index.get("sha256"):
            violations.append("cross.public_index_normalized_sha256")
    if manifest is not None and file_count != _manifest_contract_file_count(manifest, bundle=bundle):
        violations.append("cross.file_count_manifest")
    measurement_authorization = measurement.get("authorization")
    if measurement_authorization != result_authorization:
        violations.append("cross.authorization")
    if not GOVERNANCE.governed_merge_is_exact(
        measurement_authorization, source_sha
    ):
        violations.append("measurement.authorization")
    if measurement.get("authorized_input_manifest_sha256") != result_input_manifest:
        violations.append("cross.authorized_input_manifest_sha256")
    if measurement.get("pre_mutation_main") != result.get("pre_mutation_main"):
        violations.append("cross.pre_mutation_main")
    if measurement.get("post_mutation_main") != result.get("post_mutation_main"):
        violations.append("cross.post_mutation_main")
    if not _public_main_readback_is_exact(measurement.get("pre_mutation_main"), source_sha):
        violations.append("measurement.pre_mutation_main")
    if not _public_main_readback_is_exact(measurement.get("post_mutation_main"), source_sha):
        violations.append("measurement.post_mutation_main")
    post_publication_main = measurement.get("post_publication_main")
    if not GOVERNANCE.governed_merge_is_exact(post_publication_main, source_sha):
        violations.append("measurement.post_publication_main_authorized")
    elif GOVERNANCE.governed_merge_core(
        post_publication_main, source_sha
    ) != GOVERNANCE.governed_merge_core(result_authorization, source_sha):
        violations.append("cross.post_publication_governed_merge")
    public_provenance = measurement.get("public_provenance")
    if not isinstance(public_provenance, dict):
        violations.append("measurement.public_provenance")
    else:
        if public_provenance.get("verified") is not True:
            violations.append("measurement.public_provenance_verified")
        if public_provenance.get("source_repository") != SOURCE_REPO:
            violations.append("measurement.public_provenance_repository")
        if public_provenance.get("source_revision") != source_sha:
            violations.append("measurement.public_provenance_revision")
        if public_provenance.get("relation") != SOURCE_RELATION:
            violations.append("measurement.public_provenance_relation")
    return violations


def _canonical_success_receipt(
    source_sha: str,
    bundle: Path,
    result_path: Path,
    measurement_path: Path,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    manifest = validate_bundle(bundle, source_sha)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    measurement_bytes = measurement_path.read_bytes()
    measurement = json.loads(measurement_bytes)
    if not isinstance(result, dict) or not isinstance(measurement, dict):
        raise RuntimeError("local measured evidence is not exactly source-bound and complete")
    violations = _success_contract_violations(
        source_sha,
        result,
        measurement,
        measurement_bytes,
        manifest,
        bundle,
    )
    if violations:
        raise RuntimeError(
            "local measured evidence is not exactly source-bound and complete: "
            + ",".join(violations)
        )
    receipt = dict(measurement)
    receipt.update(
        {
            "schema": "szl.hf-oidc-receipt/v4",
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
    bundle: Path,
    result_path: Path,
    measurement_path: Path,
) -> dict[str, object]:
    receipt = _canonical_success_receipt(
        source_sha, bundle, result_path, measurement_path
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as handle:
        handle.write(canonical_json(receipt))
    return receipt


def finalize_attested_receipt(
    candidate_path: Path,
    output_path: Path,
    envelope_path: Path,
    source_sha: str,
    bundle: Path,
    result_path: Path,
    measurement_path: Path,
    *,
    attestation_id: str,
    attestation_url: str,
    bundle_path: str,
) -> dict[str, object]:
    expected_receipt = _canonical_success_receipt(
        source_sha, bundle, result_path, measurement_path
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


def require_deployment_failure_artifact(
    required: bool,
    receipt_outcome: str,
    primary_outcome: str,
    retry_outcome: str,
    aggregate_outcome: str | None = None,
) -> None:
    if not required:
        return
    if aggregate_outcome is None:
        aggregate_outcome = (
            "success"
            if primary_outcome == "success" or retry_outcome == "success"
            else "failure"
        )
    if (
        receipt_outcome not in STEP_OUTCOMES
        or primary_outcome not in STEP_OUTCOMES
        or retry_outcome not in STEP_OUTCOMES
        or aggregate_outcome not in STEP_OUTCOMES
    ):
        raise RuntimeError("failed-deployment artifact outcome is malformed")
    if receipt_outcome != "success":
        raise RuntimeError("required failed-deployment receipt validation did not succeed")
    if primary_outcome != "success" and retry_outcome != "success":
        raise RuntimeError("failed-deployment evidence was not preserved")
    if aggregate_outcome != "success":
        raise RuntimeError("failed-deployment aggregate artifact outcome did not succeed")


def classify_terminal_failure_stage(
    *,
    publish_outcome: str,
    publisher_artifact_outcome: str,
    measurement_outcome: str,
    measurement_artifact_outcome: str,
    candidate_receipt_outcome: str,
    oidc_outcome: str,
    finalize_receipt_outcome: str,
    terminal_artifact_outcome: str,
) -> str | None:
    ordered = (
        (publish_outcome, "PUBLISHER_MUTATION"),
        (publisher_artifact_outcome, "PUBLISHER_EVIDENCE_TRANSPORT"),
        (measurement_outcome, "PUBLIC_MEASUREMENT"),
        (measurement_artifact_outcome, "MEASUREMENT_EVIDENCE_TRANSPORT"),
        (candidate_receipt_outcome, "CANDIDATE_RECEIPT_SYNTHESIS"),
        (oidc_outcome, "OIDC_RECEIPT_ATTESTATION"),
        (finalize_receipt_outcome, "FINAL_RECEIPT_PROMOTION"),
        (terminal_artifact_outcome, "TERMINAL_SUCCESS_ARTIFACT"),
    )
    for outcome, stage in ordered:
        if outcome != "success":
            return stage
    return None


def enforce_terminal_evidence(
    *,
    publish_outcome: str,
    publisher_artifact_outcome: str | None = None,
    measurement_outcome: str = "success",
    measurement_artifact_outcome: str | None = None,
    candidate_receipt_outcome: str,
    oidc_outcome: str,
    finalize_receipt_outcome: str,
    terminal_artifact_outcome: str,
    failure_synthesis_outcome: str,
    failure_artifact_primary_outcome: str,
    failure_artifact_retry_outcome: str,
    deployment_failure_receipt_outcome: str = "skipped",
    deployment_failure_artifact_primary_outcome: str,
    deployment_failure_artifact_retry_outcome: str,
    artifact_outcome: str | None = None,
) -> dict[str, object]:
    if measurement_artifact_outcome is None:
        measurement_artifact_outcome = artifact_outcome
    if publisher_artifact_outcome is None:
        publisher_artifact_outcome = "success"
    if measurement_artifact_outcome is None:
        raise RuntimeError("measurement artifact outcome is required")
    success_path = {
        "publish": publish_outcome,
        "publisher_artifact": publisher_artifact_outcome,
        "measurement": measurement_outcome,
        "measurement_artifact": measurement_artifact_outcome,
        "candidate_receipt": candidate_receipt_outcome,
        "oidc_attestation": oidc_outcome,
        "receipt_promotion": finalize_receipt_outcome,
        "terminal_artifact": terminal_artifact_outcome,
    }
    all_outcomes = {
        **success_path,
        "failure_synthesis": failure_synthesis_outcome,
        "failure_artifact_primary": failure_artifact_primary_outcome,
        "failure_artifact_retry": failure_artifact_retry_outcome,
        "deployment_failure_receipt": deployment_failure_receipt_outcome,
        "deployment_failure_artifact_primary": deployment_failure_artifact_primary_outcome,
        "deployment_failure_artifact_retry": deployment_failure_artifact_retry_outcome,
    }
    if any(outcome not in STEP_OUTCOMES for outcome in all_outcomes.values()):
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
    require_deployment_failure_artifact(
        publish_outcome == "failure",
        deployment_failure_receipt_outcome,
        deployment_failure_artifact_primary_outcome,
        deployment_failure_artifact_retry_outcome,
        publisher_artifact_outcome,
    )
    failed = [name for name, outcome in success_path.items() if outcome != "success"]
    if failed:
        raise RuntimeError(f"terminal publication evidence is incomplete: {failed}")
    return {"status": "TERMINAL_PUBLICATION_EVIDENCE_COMPLETE"}


def cleanup_terminal_success_files(paths: list[Path]) -> bool:
    """Remove local success-looking files without recursively deleting anything."""
    complete = True
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            complete = False
    return complete


def stage_failure_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    parser.add_argument("--publish-outcome", required=True)
    parser.add_argument("--publisher-artifact-outcome", required=True)
    parser.add_argument("--measurement-outcome", required=True)
    parser.add_argument("--measurement-artifact-outcome", required=True)
    parser.add_argument("--candidate-receipt-outcome", required=True)
    parser.add_argument("--oidc-outcome", required=True)
    parser.add_argument("--finalize-receipt-outcome", required=True)
    parser.add_argument("--terminal-artifact-outcome", required=True)
    parser.add_argument("--cleanup-path", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    failure_stage = classify_terminal_failure_stage(
        publish_outcome=args.publish_outcome,
        publisher_artifact_outcome=args.publisher_artifact_outcome,
        measurement_outcome=args.measurement_outcome,
        measurement_artifact_outcome=args.measurement_artifact_outcome,
        candidate_receipt_outcome=args.candidate_receipt_outcome,
        oidc_outcome=args.oidc_outcome,
        finalize_receipt_outcome=args.finalize_receipt_outcome,
        terminal_artifact_outcome=args.terminal_artifact_outcome,
    )
    if failure_stage is None:
        raise RuntimeError("workflow failure synthesis was requested for a success graph")
    cleanup_complete = cleanup_terminal_success_files(args.cleanup_path)
    evidence = write_workflow_stage_failure(
        args.failure_evidence,
        args.source_sha,
        args.result,
        args.receipt,
        failure_stage=failure_stage,
        publisher_artifact_outcome=args.publisher_artifact_outcome,
        measurement_artifact_outcome=args.measurement_artifact_outcome,
        candidate_receipt_outcome=args.candidate_receipt_outcome,
        oidc_outcome=args.oidc_outcome,
        finalize_receipt_outcome=args.finalize_receipt_outcome,
        terminal_artifact_outcome=args.terminal_artifact_outcome,
        cleanup_complete=cleanup_complete,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


def candidate_receipt_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = synthesize_candidate_receipt(
        args.output,
        args.source_sha,
        args.bundle,
        args.result,
        args.measurement,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


def finalize_receipt_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
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
        args.bundle,
        args.result,
        args.measurement,
        attestation_id=args.attestation_id,
        attestation_url=args.attestation_url,
        bundle_path=args.bundle_path,
    )
    print(json.dumps(envelope, sort_keys=True))
    return 0


def enforce_terminal_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish-outcome", required=True)
    parser.add_argument("--publisher-artifact-outcome", required=True)
    parser.add_argument("--measurement-outcome", required=True)
    parser.add_argument("--measurement-artifact-outcome", required=True)
    parser.add_argument("--candidate-receipt-outcome", required=True)
    parser.add_argument("--oidc-outcome", required=True)
    parser.add_argument("--finalize-receipt-outcome", required=True)
    parser.add_argument("--terminal-artifact-outcome", required=True)
    parser.add_argument("--failure-synthesis-outcome", required=True)
    parser.add_argument("--failure-artifact-primary-outcome", required=True)
    parser.add_argument("--failure-artifact-retry-outcome", required=True)
    parser.add_argument("--deployment-failure-receipt-outcome", required=True)
    parser.add_argument("--deployment-failure-artifact-primary-outcome", required=True)
    parser.add_argument("--deployment-failure-artifact-retry-outcome", required=True)
    args = parser.parse_args(argv)
    result = enforce_terminal_evidence(**vars(args))
    print(json.dumps(result, sort_keys=True))
    return 0


def validate_deployment_failure_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = validate_deployment_failure_receipt(
        args.failure_evidence,
        args.source_sha,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


def bounded_action_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=sorted(BOUNDED_ACTIONS), required=True)
    parser.add_argument("--reserve-seconds", type=int, required=True)
    parser.add_argument("--max-seconds", type=int, required=True)
    args = parser.parse_args(argv)
    run_bounded_action(
        args.action,
        reserve_seconds=args.reserve_seconds,
        max_seconds=args.max_seconds,
    )
    return 0


def guard_main(argv: list[str]) -> int:
    _require_authorization_privilege_domain()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-output", type=Path, required=True)
    args = parser.parse_args(argv)
    evidence = GOVERNANCE.require_governed_main(
        args.source_sha,
        args.event,
        args.output,
        failure_output_path=args.failure_output,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


def seal_input_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = seal_authorized_input(args.root, args.source_sha, args.output)
    print(
        json.dumps(
            {
                "manifest": manifest,
                "manifest_sha256": sha256_file(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


def publish_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--authorized-input-root", type=Path, required=True)
    parser.add_argument("--authorized-input-manifest-sha256", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--failure-evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    source_sha = exact_sha(args.source_sha, "workflow source")
    mutation_state: dict[str, object] = {}
    try:
        result = deploy_bundle(
            args.bundle,
            source_sha,
            args.result,
            mutation_state,
            authorization_path=args.authorization,
            authorized_input_root=args.authorized_input_root,
            authorized_input_manifest_sha256=args.authorized_input_manifest_sha256,
            deadline=_workflow_operation_deadline(),
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
    print(json.dumps(result, sort_keys=True))
    return 0


def measure_main(argv: list[str]) -> int:
    _require_workflow_terminal_budget()
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--authorized-input-root", type=Path, required=True)
    parser.add_argument("--authorized-input-manifest-sha256", required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--authorization-output", type=Path, required=True)
    parser.add_argument("--authorization-failure-output", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, required=True)
    args = parser.parse_args(argv)
    evidence = attest_publication(
        args.bundle,
        args.source_sha,
        args.result,
        args.measurement,
        authorization_path=args.authorization,
        event_path=args.event,
        authorization_output_path=args.authorization_output,
        authorization_failure_output_path=args.authorization_failure_output,
        authorized_input_root=args.authorized_input_root,
        authorized_input_manifest_sha256=args.authorized_input_manifest_sha256,
        deadline=_workflow_operation_deadline(),
    )
    print(json.dumps(evidence, sort_keys=True))
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
    if len(sys.argv) > 1 and sys.argv[1] == "validate-deployment-failure":
        return validate_deployment_failure_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "bounded-action":
        return bounded_action_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "guard":
        return guard_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "seal-input":
        return seal_input_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "publish":
        return publish_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "measure":
        return measure_main(sys.argv[2:])
    raise SystemExit(
        "an explicit subcommand is required; combined governance/HF execution is forbidden"
    )


if __name__ == "__main__":
    raise SystemExit(main())
