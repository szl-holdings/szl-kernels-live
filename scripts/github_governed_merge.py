#!/usr/bin/env python3
"""Mint and validate exact governed-merge authorization receipts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


SOURCE_REPO = "szl-holdings/szl-kernels-live"
REPOSITORY_ID = 1295941334
GITHUB_ACTIONS_INTEGRATION_ID = 15368
RELEASE_WORKFLOW_ID = 320569265
RELEASE_WORKFLOW_NAME = "kernel-contracts"
RELEASE_WORKFLOW_PATH = ".github/workflows/kernel-contracts.yml"
REQUIRED_WORKFLOW_ID = 330467518
REQUIRED_WORKFLOW_NAME = "External release boundary"
REQUIRED_WORKFLOW_PATH = ".github/workflows/release-boundary-required.yml"
REQUIRED_STATUS_CONTEXTS = {
    "live-integrity": GITHUB_ACTIONS_INTEGRATION_ID,
    "offline-contracts": GITHUB_ACTIONS_INTEGRATION_ID,
}
GOVERNED_MAIN_STATUS = "AUTHORIZED_EXACT_GOVERNED_MERGE"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
TRANSIENT_HTTP_STATUS = frozenset({429, *range(500, 600)})
UA = "szl-kernels-governed-merge/2.0"


class GovernanceError(RuntimeError):
    """The source revision failed the governed-merge contract."""


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def exact_sha(value: object, label: str = "revision") -> str:
    normalized = str(value or "").lower()
    if not HEX40.fullmatch(normalized):
        raise GovernanceError(f"{label} must be an exact lowercase 40-character SHA")
    return normalized


def _remaining_timeout(deadline: float, cap: float = 30.0) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GovernanceError("shared governance deadline expired")
    return min(cap, remaining)


def _request_json(url: str, token: str, timeout: float = 30.0) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": UA,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _request_json_retry(
    url: str, token: str, *, deadline: float, label: str
) -> object:
    last_error: BaseException | None = None
    while True:
        try:
            return _request_json(url, token, _remaining_timeout(deadline))
        except urllib.error.HTTPError as error:
            if error.code not in TRANSIENT_HTTP_STATUS:
                raise GovernanceError(
                    f"{label} failed with terminal HTTP {error.code}"
                ) from error
            last_error = error
        except (TimeoutError, ConnectionResetError, urllib.error.URLError, OSError) as error:
            last_error = error
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GovernanceError(f"{label} exhausted its shared deadline") from last_error
        time.sleep(min(2.0, remaining))


def _load_event(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GovernanceError("push event evidence is unreadable") from error
    if not isinstance(value, dict):
        raise GovernanceError("push event evidence is not an object")
    return value


def _complete_inventory(rows: object, key: str, label: str) -> list[dict]:
    if not isinstance(rows, dict) or not isinstance(rows.get(key), list):
        raise GovernanceError(f"{label} inventory is unavailable")
    items = rows[key]
    total_count = rows.get("total_count")
    if (
        type(total_count) is not int
        or total_count != len(items)
        or total_count > 100
        or any(not isinstance(item, dict) for item in items)
    ):
        raise GovernanceError(f"{label} inventory is incomplete or malformed")
    return items


def _request_complete_list(
    base_url: str,
    token: str,
    *,
    deadline: float,
    label: str,
    max_pages: int = 10,
) -> tuple[list[dict[str, object]], int]:
    """Read a paginated bare-list endpoint completely or fail closed."""
    items: list[dict[str, object]] = []
    observed_ids: set[int] = set()
    separator = "&" if "?" in base_url else "?"
    for page in range(1, max_pages + 1):
        rows = _request_json_retry(
            f"{base_url}{separator}per_page=100&page={page}",
            token,
            deadline=deadline,
            label=f"{label} page {page}",
        )
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise GovernanceError(f"{label} inventory is unavailable or malformed")
        if len(rows) > 100:
            raise GovernanceError(f"{label} page exceeds its declared bound")
        for row in rows:
            row_id = row.get("id")
            if type(row_id) is not int or row_id <= 0 or row_id in observed_ids:
                raise GovernanceError(f"{label} inventory identity is malformed or duplicate")
            observed_ids.add(row_id)
            items.append(row)
        if len(rows) < 100:
            return items, page
    raise GovernanceError(f"{label} inventory exceeded its fail-closed page bound")


def _job_id_from_url(value: object, run_id: int) -> int | None:
    if not isinstance(value, str):
        return None
    parsed = urllib.parse.urlsplit(value)
    prefix = f"/{SOURCE_REPO}/actions/runs/{run_id}/job/"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or not parsed.path.startswith(prefix)
        or parsed.query
        or parsed.fragment
    ):
        return None
    suffix = parsed.path[len(prefix) :]
    return int(suffix) if suffix.isdigit() and int(suffix) > 0 else None


def _require_exact_attempt_jobs(
    rows: object,
    workflow: dict[str, object],
    head_sha: str,
    *,
    label: str,
    required_names: frozenset[str] | None = None,
) -> list[dict[str, object]]:
    jobs = _complete_inventory(rows, "jobs", f"{label} exact-attempt job")
    if not jobs:
        raise GovernanceError(f"{label} exact-attempt job inventory is empty")
    run_id = workflow.get("run_id")
    run_attempt = workflow.get("run_attempt")
    evidence: list[dict[str, object]] = []
    observed_names: list[str] = []
    observed_ids: set[int] = set()
    for row in jobs:
        job_id = row.get("id")
        name = row.get("name")
        if (
            type(job_id) is not int
            or job_id <= 0
            or job_id in observed_ids
            or not isinstance(name, str)
            or not name
            or row.get("run_id") != run_id
            or row.get("run_attempt") != run_attempt
            or row.get("head_sha") != head_sha
            or row.get("status") != "completed"
            or row.get("conclusion") != "success"
            or _job_id_from_url(row.get("html_url"), int(run_id)) != job_id
        ):
            raise GovernanceError(f"{label} exact-attempt job is not exact and successful")
        observed_ids.add(job_id)
        observed_names.append(name)
        evidence.append(
            {
                "conclusion": "success",
                "head_revision": head_sha,
                "job_id": job_id,
                "name": name,
                "run_attempt": run_attempt,
                "run_id": run_id,
                "status": "completed",
            }
        )
    if required_names is not None and (
        set(observed_names) != set(required_names)
        or len(observed_names) != len(required_names)
    ):
        raise GovernanceError(f"{label} required exact-attempt jobs are incomplete or duplicate")
    return sorted(evidence, key=lambda row: (str(row["name"]), int(row["job_id"])))


def _require_successful_checks(
    rows: object,
    head_sha: str,
    release_workflow: dict[str, object],
) -> list[dict[str, object]]:
    check_runs = _complete_inventory(rows, "check_runs", "exact-head check-run")
    release_run_id = int(release_workflow["run_id"])
    release_run_attempt = int(release_workflow["run_attempt"])
    release_jobs = release_workflow.get("jobs")
    if not isinstance(release_jobs, list):
        raise GovernanceError("release workflow exact-attempt jobs are unavailable")
    evidence: list[dict[str, object]] = []
    for name, integration_id in sorted(REQUIRED_STATUS_CONTEXTS.items()):
        matches = [
            row
            for row in check_runs
            if row.get("name") == name
            and row.get("head_sha") == head_sha
            and isinstance(row.get("app"), dict)
            and row["app"].get("id") == integration_id
            and type(row.get("id")) is int
            and row["id"] > 0
            and _job_id_from_url(row.get("details_url"), release_run_id) is not None
        ]
        if not matches:
            raise GovernanceError(
                f"required exact kernel-contract check is unavailable: {name}"
            )
        selected = max(matches, key=lambda row: row["id"])
        if (
            selected.get("status") != "completed"
            or selected.get("conclusion") != "success"
        ):
            raise GovernanceError(
                f"latest exact kernel-contract check did not succeed: {name}"
            )
        job_id = _job_id_from_url(selected.get("details_url"), release_run_id)
        bound_jobs = [
            job
            for job in release_jobs
            if isinstance(job, dict)
            and job.get("job_id") == job_id
            and job.get("name") == name
            and job.get("run_id") == release_run_id
            and job.get("run_attempt") == release_run_attempt
            and job.get("head_revision") == head_sha
            and job.get("status") == "completed"
            and job.get("conclusion") == "success"
        ]
        if len(bound_jobs) != 1:
            raise GovernanceError(
                f"required check is not bound to one exact latest-attempt job: {name}"
            )
        evidence.append(
            {
                "app_id": integration_id,
                "check_run_id": selected["id"],
                "conclusion": "success",
                "head_revision": head_sha,
                "job_id": job_id,
                "name": name,
                "workflow_run_attempt": release_run_attempt,
                "workflow_run_id": release_run_id,
            }
        )
    return evidence


def _require_exact_pull_request_workflow(
    rows: object,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    *,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    label: str,
) -> dict[str, object]:
    workflow_runs = _complete_inventory(rows, "workflow_runs", "workflow-run")
    matches = [
        row
        for row in workflow_runs
        if row.get("workflow_id") == workflow_id
        and row.get("name") == workflow_name
        and row.get("path") == workflow_path
        and row.get("event") == "pull_request"
        and row.get("head_sha") == head_sha
        and isinstance(row.get("repository"), dict)
        and row["repository"].get("full_name") == SOURCE_REPO
        and row["repository"].get("id") == REPOSITORY_ID
    ]
    if not matches:
        raise GovernanceError(f"exact {label} did not run for this head")
    if any(
        type(row.get("id")) is not int
        or row["id"] <= 0
        or type(row.get("run_attempt")) is not int
        or row["run_attempt"] <= 0
        for row in matches
    ):
        raise GovernanceError(f"exact {label} identity is malformed")
    selected = max(matches, key=lambda row: row["id"])
    pull_requests = selected.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        raise GovernanceError(f"exact {label} is not bound to one pull request")
    run_pull = pull_requests[0]
    run_head = run_pull.get("head") if isinstance(run_pull, dict) else None
    run_base = run_pull.get("base") if isinstance(run_pull, dict) else None
    if (
        not isinstance(run_pull, dict)
        or run_pull.get("number") != pull_number
        or not isinstance(run_head, dict)
        or run_head.get("ref") != head_ref
        or run_head.get("sha") != head_sha
        or not isinstance(run_head.get("repo"), dict)
        or run_head["repo"].get("id") != REPOSITORY_ID
        or not isinstance(run_base, dict)
        or run_base.get("ref") != "main"
        or run_base.get("sha") != base_sha
        or not isinstance(run_base.get("repo"), dict)
        or run_base["repo"].get("id") != REPOSITORY_ID
    ):
        raise GovernanceError(f"exact {label} pull-request tuple is not exact")
    if (
        selected.get("status") != "completed"
        or selected.get("conclusion") != "success"
    ):
        raise GovernanceError(f"latest exact {label} did not succeed")
    return {
        "base_revision": base_sha,
        "conclusion": "success",
        "event": "pull_request",
        "head_ref": head_ref,
        "head_revision": head_sha,
        "name": workflow_name,
        "path": workflow_path,
        "pull_request_number": pull_number,
        "repository_id": REPOSITORY_ID,
        "run_attempt": selected["run_attempt"],
        "run_id": selected["id"],
        "status": "completed",
        "workflow_id": workflow_id,
        "jobs": [],
    }


def _workflow_evidence_is_exact(
    workflow: object,
    *,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> bool:
    return (
        isinstance(workflow, dict)
        and set(workflow)
        == {
            "base_revision",
            "conclusion",
            "event",
            "head_ref",
            "head_revision",
            "jobs",
            "name",
            "path",
            "pull_request_number",
            "repository_id",
            "run_attempt",
            "run_id",
            "status",
            "workflow_id",
        }
        and workflow.get("workflow_id") == workflow_id
        and workflow.get("name") == workflow_name
        and workflow.get("path") == workflow_path
        and workflow.get("event") == "pull_request"
        and workflow.get("repository_id") == REPOSITORY_ID
        and workflow.get("pull_request_number") == pull_number
        and workflow.get("base_revision") == base_sha
        and workflow.get("head_ref") == head_ref
        and workflow.get("head_revision") == head_sha
        and workflow.get("status") == "completed"
        and workflow.get("conclusion") == "success"
        and type(workflow.get("run_id")) is int
        and workflow["run_id"] > 0
        and type(workflow.get("run_attempt")) is int
        and workflow["run_attempt"] > 0
        and isinstance(workflow.get("jobs"), list)
        and bool(workflow["jobs"])
        and all(
            isinstance(job, dict)
            and set(job)
            == {
                "conclusion",
                "head_revision",
                "job_id",
                "name",
                "run_attempt",
                "run_id",
                "status",
            }
            and job.get("run_id") == workflow.get("run_id")
            and job.get("run_attempt") == workflow.get("run_attempt")
            and job.get("head_revision") == head_sha
            and job.get("status") == "completed"
            and job.get("conclusion") == "success"
            and type(job.get("job_id")) is int
            and job["job_id"] > 0
            and isinstance(job.get("name"), str)
            and bool(job["name"])
            for job in workflow["jobs"]
        )
        and len({job["job_id"] for job in workflow["jobs"]}) == len(workflow["jobs"])
        and len({job["name"] for job in workflow["jobs"]}) == len(workflow["jobs"])
    )


def governed_merge_is_exact(evidence: object, source_sha: str) -> bool:
    source_sha = exact_sha(source_sha)
    if not isinstance(evidence, dict):
        return False
    repository = evidence.get("repository")
    push = evidence.get("push")
    pull = evidence.get("pull_request")
    checks = evidence.get("required_checks")
    release_workflow = evidence.get("release_workflow")
    required_workflow = evidence.get("required_workflow")
    associated_inventory = evidence.get("associated_pull_request_inventory")
    if (
        not isinstance(repository, dict)
        or not isinstance(push, dict)
        or not isinstance(pull, dict)
    ):
        return False
    expected_checks = set(REQUIRED_STATUS_CONTEXTS.items())
    checks_are_exact = (
        isinstance(checks, list)
        and len(checks) == len(expected_checks)
        and all(
            isinstance(row, dict)
            and set(row)
            == {
                "app_id",
                "check_run_id",
                "conclusion",
                "head_revision",
                "job_id",
                "name",
                "workflow_run_attempt",
                "workflow_run_id",
            }
            and row.get("head_revision") == pull.get("head_revision")
            and row.get("conclusion") == "success"
            and type(row.get("check_run_id")) is int
            and row["check_run_id"] > 0
            and row.get("workflow_run_id") == (release_workflow or {}).get("run_id")
            and row.get("workflow_run_attempt")
            == (release_workflow or {}).get("run_attempt")
            and type(row.get("job_id")) is int
            and row["job_id"] > 0
            for row in checks
        )
    )
    observed_checks = (
        {(row.get("name"), row.get("app_id")) for row in checks}
        if isinstance(checks, list)
        else set()
    )
    return (
        set(evidence)
        == {
            "schema",
            "status",
            "source_revision",
            "repository",
            "push",
            "pull_request",
            "required_checks",
            "release_workflow",
            "required_workflow",
            "associated_pull_request_inventory",
        }
        and evidence.get("schema") == "szl.github-governed-merge/v3"
        and evidence.get("status") == GOVERNED_MAIN_STATUS
        and evidence.get("source_revision") == source_sha
        and set(repository) == {"default_branch", "full_name", "id"}
        and repository.get("default_branch") == "main"
        and repository.get("full_name") == SOURCE_REPO
        and repository.get("id") == REPOSITORY_ID
        and set(push) == {"before", "after"}
        and isinstance(push.get("before"), str)
        and HEX40.fullmatch(push["before"]) is not None
        and push.get("after") == source_sha
        and set(pull)
        == {
            "base_revision",
            "head_ref",
            "head_revision",
            "merge_revision",
            "merged_at",
            "merged_by",
            "number",
        }
        and pull.get("base_revision") == push.get("before")
        and isinstance(pull.get("head_ref"), str)
        and bool(pull["head_ref"])
        and isinstance(pull.get("head_revision"), str)
        and HEX40.fullmatch(pull["head_revision"]) is not None
        and pull.get("merge_revision") == source_sha
        and isinstance(pull.get("merged_at"), str)
        and bool(pull["merged_at"])
        and isinstance(pull.get("merged_by"), str)
        and bool(pull["merged_by"])
        and type(pull.get("number")) is int
        and pull["number"] > 0
        and isinstance(associated_inventory, dict)
        and set(associated_inventory) == {"candidate_count", "pages", "total_count"}
        and associated_inventory.get("candidate_count") == 1
        and type(associated_inventory.get("pages")) is int
        and associated_inventory["pages"] > 0
        and associated_inventory["pages"] <= 10
        and type(associated_inventory.get("total_count")) is int
        and associated_inventory["total_count"] >= 1
        and associated_inventory["total_count"]
        <= associated_inventory["pages"] * 100
        and associated_inventory["total_count"]
        >= (associated_inventory["pages"] - 1) * 100
        and checks_are_exact
        and observed_checks == expected_checks
        and _workflow_evidence_is_exact(
            release_workflow,
            workflow_id=RELEASE_WORKFLOW_ID,
            workflow_name=RELEASE_WORKFLOW_NAME,
            workflow_path=RELEASE_WORKFLOW_PATH,
            pull_number=pull["number"],
            base_sha=pull["base_revision"],
            head_ref=pull["head_ref"],
            head_sha=pull["head_revision"],
        )
        and {job["name"] for job in release_workflow["jobs"]}
        == set(REQUIRED_STATUS_CONTEXTS)
        and len(release_workflow["jobs"]) == len(REQUIRED_STATUS_CONTEXTS)
        and _workflow_evidence_is_exact(
            required_workflow,
            workflow_id=REQUIRED_WORKFLOW_ID,
            workflow_name=REQUIRED_WORKFLOW_NAME,
            workflow_path=REQUIRED_WORKFLOW_PATH,
            pull_number=pull["number"],
            base_sha=pull["base_revision"],
            head_ref=pull["head_ref"],
            head_sha=pull["head_revision"],
        )
    )


def governed_merge_core(evidence: object, source_sha: str) -> dict[str, object]:
    if not governed_merge_is_exact(evidence, source_sha):
        raise GovernanceError("governed-merge evidence is not exact")
    assert isinstance(evidence, dict)
    return {
        "source_revision": evidence["source_revision"],
        "repository": evidence["repository"],
        "push": evidence["push"],
        "pull_request": evidence["pull_request"],
    }


def load_governed_merge(path: Path, source_sha: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        evidence = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GovernanceError("governed-merge evidence is unreadable") from error
    if (
        not isinstance(evidence, dict)
        or raw != canonical_json(evidence)
        or not governed_merge_is_exact(evidence, source_sha)
    ):
        raise GovernanceError("governed-merge evidence is not canonical and exact")
    return evidence


def _sanitized_diagnostic(error: BaseException) -> str:
    message = " ".join(f"{type(error).__name__}: {error}".replace("\x00", " ").split())
    message = re.sub(
        r"(?i)(authorization|token|secret|private[-_ ]?key)(\s*[:=]\s*)\S+",
        r"\1\2<redacted>",
        message,
    )
    return message[:500]


def require_governed_main(
    source_sha: str,
    event_path: Path,
    output_path: Path,
    *,
    failure_output_path: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    source_sha = exact_sha(source_sha, "workflow source")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_ref = os.environ.get("GITHUB_REF", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if repository != SOURCE_REPO:
        raise GovernanceError(f"unexpected GitHub repository: {repository!r}")
    if source_ref != "refs/heads/main":
        raise GovernanceError(f"refusing production release from {source_ref!r}")
    if not token:
        raise GovernanceError("GITHUB_TOKEN is required for governed-merge authorization")
    if deadline is None:
        deadline = time.monotonic() + 150
    try:
        event = _load_event(event_path)
        before_sha = exact_sha(event.get("before"), "push before revision")
        after_sha = exact_sha(event.get("after"), "push after revision")
        event_repository = event.get("repository")
        if (
            event.get("ref") != "refs/heads/main"
            or after_sha != source_sha
            or not isinstance(event_repository, dict)
            or event_repository.get("id") != REPOSITORY_ID
            or event_repository.get("full_name") != SOURCE_REPO
            or event_repository.get("default_branch") != "main"
        ):
            raise GovernanceError("push event is not bound to this exact default branch")
        metadata = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}",
            token,
            deadline=deadline,
            label="repository identity readback",
        )
        if (
            not isinstance(metadata, dict)
            or metadata.get("id") != REPOSITORY_ID
            or metadata.get("full_name") != SOURCE_REPO
            or metadata.get("default_branch") != "main"
        ):
            raise GovernanceError("repository identity/default branch is not exact")
        branch = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}/branches/main",
            token,
            deadline=deadline,
            label="protected-main revision readback",
        )
        live_sha = exact_sha(
            ((branch if isinstance(branch, dict) else {}).get("commit") or {}).get("sha"),
            "current protected-main revision",
        )
        if not isinstance(branch, dict) or branch.get("protected") is not True:
            raise GovernanceError("repository main branch is not protected")
        if live_sha != source_sha:
            raise GovernanceError(
                f"refusing stale release: current main {live_sha} != source {source_sha}"
            )
        associated, associated_pages = _request_complete_list(
            f"{api_root}/repos/{SOURCE_REPO}/commits/{source_sha}/pulls",
            token,
            deadline=deadline,
            label="associated pull-request readback",
        )
        candidates = [
            row
            for row in associated
            if isinstance(row, dict)
            and row.get("state") == "closed"
            and row.get("merged_at")
            and row.get("merge_commit_sha") == source_sha
            and isinstance(row.get("base"), dict)
            and row["base"].get("ref") == "main"
            and row["base"].get("sha") == event["before"]
            and isinstance(row["base"].get("repo"), dict)
            and row["base"]["repo"].get("full_name") == SOURCE_REPO
            and row["base"]["repo"].get("id") == REPOSITORY_ID
        ]
        if len(candidates) != 1:
            raise GovernanceError("exact main revision is not one unambiguous merged PR")
        candidate = candidates[0]
        number = candidate.get("number")
        if type(number) is not int or number <= 0:
            raise GovernanceError("associated pull-request number is malformed")
        pull = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}/pulls/{number}",
            token,
            deadline=deadline,
            label="merged pull-request readback",
        )
        if not isinstance(pull, dict) or pull.get("id") != candidate.get("id"):
            raise GovernanceError("merged pull-request readback is not exact")
        head = pull.get("head")
        base = pull.get("base")
        merged_by = pull.get("merged_by")
        head_sha = exact_sha((head or {}).get("sha"), "pull-request head revision")
        head_ref = (head or {}).get("ref")
        before_sha = exact_sha(event["before"], "push before revision")
        if (
            pull.get("state") != "closed"
            or not pull.get("merged")
            or not pull.get("merged_at")
            or pull.get("merge_commit_sha") != source_sha
            or not isinstance(base, dict)
            or base.get("ref") != "main"
            or base.get("sha") != before_sha
            or not isinstance(base.get("repo"), dict)
            or base["repo"].get("full_name") != SOURCE_REPO
            or base["repo"].get("id") != REPOSITORY_ID
            or not isinstance(head, dict)
            or not isinstance(head_ref, str)
            or not head_ref
            or not isinstance(head.get("repo"), dict)
            or head["repo"].get("full_name") != SOURCE_REPO
            or head["repo"].get("id") != REPOSITORY_ID
            or not isinstance(merged_by, dict)
            or not isinstance(merged_by.get("login"), str)
        ):
            raise GovernanceError("merged pull-request tuple is not exact")
        query = urllib.parse.urlencode(
            {"event": "pull_request", "head_sha": head_sha, "per_page": 100}
        )
        workflow_runs = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}/actions/runs?{query}",
            token,
            deadline=deadline,
            label="exact-head workflow-run readback",
        )
        release_workflow = _require_exact_pull_request_workflow(
            workflow_runs,
            number,
            before_sha,
            head_ref,
            head_sha,
            workflow_id=RELEASE_WORKFLOW_ID,
            workflow_name=RELEASE_WORKFLOW_NAME,
            workflow_path=RELEASE_WORKFLOW_PATH,
            label="kernel-contract workflow",
        )
        required_workflow = _require_exact_pull_request_workflow(
            workflow_runs,
            number,
            before_sha,
            head_ref,
            head_sha,
            workflow_id=REQUIRED_WORKFLOW_ID,
            workflow_name=REQUIRED_WORKFLOW_NAME,
            workflow_path=REQUIRED_WORKFLOW_PATH,
            label="required release-boundary workflow",
        )
        release_jobs = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}/actions/runs/"
            f"{release_workflow['run_id']}/attempts/"
            f"{release_workflow['run_attempt']}/jobs?per_page=100",
            token,
            deadline=deadline,
            label="kernel-contract exact-attempt job readback",
        )
        release_workflow["jobs"] = _require_exact_attempt_jobs(
            release_jobs,
            release_workflow,
            head_sha,
            label="kernel-contract workflow",
            required_names=frozenset(REQUIRED_STATUS_CONTEXTS),
        )
        required_jobs = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}/actions/runs/"
            f"{required_workflow['run_id']}/attempts/"
            f"{required_workflow['run_attempt']}/jobs?per_page=100",
            token,
            deadline=deadline,
            label="required workflow exact-attempt job readback",
        )
        required_workflow["jobs"] = _require_exact_attempt_jobs(
            required_jobs,
            required_workflow,
            head_sha,
            label="required release-boundary workflow",
        )
        check_runs = _request_json_retry(
            f"{api_root}/repos/{SOURCE_REPO}/commits/{head_sha}/check-runs?per_page=100",
            token,
            deadline=deadline,
            label="exact-head check-run readback",
        )
        checks = _require_successful_checks(check_runs, head_sha, release_workflow)
        evidence = {
            "schema": "szl.github-governed-merge/v3",
            "status": GOVERNED_MAIN_STATUS,
            "source_revision": source_sha,
            "repository": {
                "default_branch": "main",
                "full_name": SOURCE_REPO,
                "id": REPOSITORY_ID,
            },
            "push": {"before": before_sha, "after": source_sha},
            "pull_request": {
                "base_revision": before_sha,
                "head_ref": head_ref,
                "head_revision": head_sha,
                "merge_revision": source_sha,
                "merged_at": pull["merged_at"],
                "merged_by": merged_by["login"],
                "number": number,
            },
            "required_checks": checks,
            "release_workflow": release_workflow,
            "required_workflow": required_workflow,
            "associated_pull_request_inventory": {
                "candidate_count": len(candidates),
                "pages": associated_pages,
                "total_count": len(associated),
            },
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(canonical_json(evidence))
        if failure_output_path:
            failure_output_path.unlink(missing_ok=True)
        return evidence
    except Exception as error:
        output_path.unlink(missing_ok=True)
        if failure_output_path:
            failure = {
                "schema": "szl.github-governed-merge-failure/v1",
                "status": "GOVERNANCE_AUTHORIZATION_FAILED",
                "failure_stage": "governance_authorization",
                "source_revision": source_sha,
                "repository": repository,
                "receipt_minted": False,
                "deployment_success": False,
                "diagnostic": _sanitized_diagnostic(error),
            }
            failure_output_path.parent.mkdir(parents=True, exist_ok=True)
            failure_output_path.write_bytes(canonical_json(failure))
        raise
