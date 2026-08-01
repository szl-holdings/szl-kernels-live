const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RESULT_STATES = new Set(["PASS", "FAIL"]);

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} fields do not match the contract`);
  }
}

export function validateSnapshot(index, receipt) {
  if (!index || !Array.isArray(index.kernels) || !index.kernels.length) {
    throw new Error("contract index has no kernels");
  }
  if (!receipt || !Array.isArray(receipt.results)) {
    throw new Error("receipt has no results");
  }
  if (
    typeof index.recorded_at !== "string" ||
    index.recorded_at.length === 0 ||
    receipt.recorded_at !== index.recorded_at
  ) {
    throw new Error("receipt recorded_at does not match the contract index");
  }

  const resultById = new Map();
  for (const result of receipt.results) {
    if (!result || typeof result.id !== "string" || resultById.has(result.id)) {
      throw new Error("receipt result IDs must be unique non-empty strings");
    }
    if (!RESULT_STATES.has(result.status)) {
      throw new Error(`receipt result ${result.id} has an unsupported status`);
    }
    if (!SHA40.test(result.revision || "")) {
      throw new Error(`receipt result ${result.id} has an invalid revision`);
    }
    if (!SHA256.test(result.tree_digest_sha256 || "")) {
      throw new Error(`receipt result ${result.id} has an invalid tree digest`);
    }
    resultById.set(result.id, result);
  }

  const indexIds = new Set();
  const statuses = new Map();
  for (const row of index.kernels) {
    if (!row || typeof row.id !== "string" || indexIds.has(row.id)) {
      throw new Error("contract index IDs must be unique non-empty strings");
    }
    indexIds.add(row.id);
    const result = resultById.get(row.id);
    if (!result) {
      throw new Error(`receipt is missing ${row.id}`);
    }
    if (result.revision !== row.revision) {
      throw new Error(`receipt revision does not match ${row.id}`);
    }
    if (result.tree_digest_sha256 !== row.tree_digest_sha256) {
      throw new Error(`receipt tree digest does not match ${row.id}`);
    }
    statuses.set(row.id, result.status);
  }
  if (resultById.size !== indexIds.size) {
    throw new Error("receipt and contract index ID sets do not match");
  }

  const summary = {
    kernels: receipt.results.length,
    passed: receipt.results.filter((result) => result.status === "PASS").length,
    failed: receipt.results.filter((result) => result.status === "FAIL").length,
  };
  exactKeys(receipt.summary, ["failed", "kernels", "passed"], "receipt summary");
  if (
    receipt.summary.kernels !== summary.kernels ||
    receipt.summary.passed !== summary.passed ||
    receipt.summary.failed !== summary.failed ||
    summary.kernels !== index.kernels.length
  ) {
    throw new Error("receipt summary does not recompute from exact results");
  }
  return statuses;
}

export function classifyLiveHead(data, expectedRevision) {
  if (!SHA40.test(expectedRevision || "")) {
    return { state: "UNAVAILABLE", reason: "Recorded revision is malformed" };
  }
  if (!data || typeof data !== "object" || !SHA40.test(data.sha || "")) {
    return { state: "UNAVAILABLE", reason: "Live-head response is malformed" };
  }
  if (data.sha === expectedRevision) {
    return { state: "MATCH", sha: data.sha };
  }
  return { state: "DRIFT", sha: data.sha };
}

export async function fetchLiveHead(
  url,
  expectedRevision,
  { fetchImpl = globalThis.fetch, timeoutMs = 8000 } = {},
) {
  if (typeof fetchImpl !== "function") {
    return { state: "UNAVAILABLE", reason: "Fetch is unavailable" };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      cache: "no-store",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) {
      return { state: "UNAVAILABLE", reason: `HTTP ${response.status}` };
    }
    return classifyLiveHead(await response.json(), expectedRevision);
  } catch (error) {
    const reason = controller.signal.aborted
      ? `Live-head request timed out after ${timeoutMs}ms`
      : error instanceof Error
        ? error.message
        : "Live-head request failed";
    return { state: "UNAVAILABLE", reason };
  } finally {
    clearTimeout(timeout);
  }
}
