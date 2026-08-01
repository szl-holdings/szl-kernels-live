import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  classifyLiveHead,
  fetchLiveHead,
  validateSnapshot,
} from "../scripts/kernel_portfolio_truth.mjs";

const REVISION_A = "a".repeat(40);
const REVISION_B = "b".repeat(40);
const DIGEST_A = "1".repeat(64);

function fixture() {
  return {
    index: {
      recorded_at: "2026-07-26T03:00:00Z",
      kernels: [
        { id: "SZLHOLDINGS/example", revision: REVISION_A, tree_digest_sha256: DIGEST_A },
      ],
    },
    receipt: {
      recorded_at: "2026-07-26T03:00:00Z",
      summary: { kernels: 1, passed: 1, failed: 0 },
      results: [
        {
          id: "SZLHOLDINGS/example",
          revision: REVISION_A,
          tree_digest_sha256: DIGEST_A,
          status: "PASS",
        },
      ],
    },
  };
}

test("checked-in snapshot is an exact ten-kernel PASS vector", () => {
  const index = JSON.parse(fs.readFileSync("contracts/index.json", "utf8"));
  const receipt = JSON.parse(
    fs.readFileSync("evidence/kernel-selfcheck-20260726.json", "utf8"),
  );
  const statuses = validateSnapshot(index, receipt);
  assert.equal(statuses.size, 10);
  assert.deepEqual(new Set(statuses.keys()), new Set(index.kernels.map((row) => row.id)));
  assert.ok([...statuses.values()].every((status) => status === "PASS"));
});

test("snapshot PASS is bound to exact revision, digest, time, IDs, and summary", () => {
  const { index, receipt } = fixture();
  assert.equal(validateSnapshot(index, receipt).get("SZLHOLDINGS/example"), "PASS");
  for (const mutate of [
    (value) => { value.index.kernels[0].revision = REVISION_B; },
    (value) => { value.index.kernels[0].tree_digest_sha256 = "2".repeat(64); },
    (value) => { value.index.recorded_at = "2026-07-27T03:00:00Z"; },
    (value) => { value.receipt.results[0].id = "SZLHOLDINGS/other"; },
    (value) => { value.receipt.summary.passed = 0; },
  ]) {
    const value = structuredClone(fixture());
    mutate(value);
    assert.throws(() => validateSnapshot(value.index, value.receipt));
  }
});

test("live head requires a valid observed 40-character SHA", () => {
  assert.equal(classifyLiveHead({ sha: REVISION_A }, REVISION_A).state, "MATCH");
  assert.equal(classifyLiveHead({ sha: REVISION_B }, REVISION_A).state, "DRIFT");
  for (const payload of [{}, { sha: null }, { sha: "main" }, { sha: "A".repeat(40) }]) {
    assert.equal(classifyLiveHead(payload, REVISION_A).state, "UNAVAILABLE");
  }
});

test("a hung live-head request terminates as unavailable", async () => {
  const fetchImpl = (_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => {
      reject(new DOMException("aborted", "AbortError"));
    });
  });
  const result = await fetchLiveHead("https://example.invalid", REVISION_A, {
    fetchImpl,
    timeoutMs: 5,
  });
  assert.equal(result.state, "UNAVAILABLE");
  assert.match(result.reason, /timed out/);
});

test("live-head fetch bypasses caches", async () => {
  let observed;
  const fetchImpl = async (_url, options) => {
    observed = options;
    return { ok: true, json: async () => ({ sha: REVISION_A }) };
  };
  const result = await fetchLiveHead("https://example.invalid", REVISION_A, {
    fetchImpl,
  });
  assert.equal(result.state, "MATCH");
  assert.equal(observed.cache, "no-store");
});
