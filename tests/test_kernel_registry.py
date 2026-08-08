from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from datetime import datetime


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_kernel_registry as verifier


def schema_matches(value: object, schema: dict) -> bool:
    """Evaluate the dependency-free JSON Schema subset used by source_binding."""
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        type_checks = {
            "object": lambda item: isinstance(item, dict),
            "array": lambda item: isinstance(item, list),
            "string": lambda item: isinstance(item, str),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "null": lambda item: item is None,
        }
        if not any(type_checks[name](value) for name in allowed):
            return False
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            return False
        if "items" in schema and not all(
            schema_matches(item, schema["items"]) for item in value
        ):
            return False
        if "contains" in schema and not any(
            schema_matches(item, schema["contains"]) for item in value
        ):
            return False
    if isinstance(value, dict):
        if any(key not in value for key in schema.get("required", [])):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and any(
            key not in properties for key in value
        ):
            return False
        for key, child_schema in properties.items():
            if key in value and not schema_matches(value[key], child_schema):
                return False
    if "allOf" in schema and not all(
        schema_matches(value, branch) for branch in schema["allOf"]
    ):
        return False
    if "anyOf" in schema and not any(
        schema_matches(value, branch) for branch in schema["anyOf"]
    ):
        return False
    if "oneOf" in schema and sum(
        schema_matches(value, branch) for branch in schema["oneOf"]
    ) != 1:
        return False
    if "not" in schema and schema_matches(value, schema["not"]):
        return False
    return True


class KernelRegistryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = json.loads(
            (ROOT / "contracts" / "index.json").read_text(encoding="utf-8")
        )
        cls.contracts = verifier.load_contracts(ROOT / "contracts")
        cls.schema = json.loads(
            (ROOT / "schemas" / "kernel-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )

    def test_portfolio_has_ten_unique_revision_pinned_contracts(self) -> None:
        self.assertEqual(len(self.contracts), 10)
        self.assertEqual(len({row["id"] for row in self.contracts}), 10)
        for contract in self.contracts:
            self.assertRegex(contract["revision"], r"^[0-9a-f]{40}$")
            self.assertIn(contract["revision"], contract["loading"]["example"])

    def test_each_contract_declares_compatibility_limitations_and_source(self) -> None:
        for contract in self.contracts:
            runtime = contract["runtime"]
            self.assertEqual(runtime["classification"], "PYTHON_GOVERNANCE_KERNEL")
            self.assertEqual(runtime["hf_declared_driver_families"], [])
            self.assertTrue(runtime["measured_compatibility"]["receipt"])
            self.assertTrue(contract["limitations"])
            self.assertIn("status", contract["source_binding"])
            self.assertIn("status", contract["deprecation"])

    def test_tree_digest_recomputes(self) -> None:
        for contract in self.contracts:
            actual = hashlib.sha256(
                verifier.canonical_json(contract["artifact"]["files"])
            ).hexdigest()
            self.assertEqual(actual, contract["artifact"]["tree_digest_sha256"])

    def test_tampered_revision_fails_closed(self) -> None:
        contract = copy.deepcopy(self.contracts[0])
        contract["revision"] = "main"
        with self.assertRaisesRegex(ValueError, "40-character revision"):
            verifier.validate_contract(contract)

    def test_tampered_file_digest_fails_closed(self) -> None:
        contract = copy.deepcopy(self.contracts[0])
        contract["artifact"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "tree digest mismatch"):
            verifier.validate_contract(contract)

    def test_driver_support_cannot_be_inferred(self) -> None:
        contract = copy.deepcopy(self.contracts[0])
        contract["runtime"]["hf_declared_driver_families"] = ["cuda"]
        with self.assertRaisesRegex(ValueError, "cannot be inferred"):
            verifier.validate_contract(contract)

    def test_receipt_payload_digest_is_valid(self) -> None:
        recorded = datetime.strptime(
            self.index["recorded_at"], "%Y-%m-%dT%H:%M:%SZ"
        )
        receipt_path = (
            ROOT / "evidence" / f"kernel-selfcheck-{recorded:%Y%m%d}.json"
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        expected = receipt.pop("payload_sha256")
        actual = hashlib.sha256(verifier.canonical_json(receipt)).hexdigest()
        self.assertEqual(actual, expected)
        self.assertEqual(receipt["recorded_at"], self.index["recorded_at"])
        self.assertEqual(receipt["summary"], {"kernels": 10, "passed": 10, "failed": 0})
        for contract in self.contracts:
            self.assertEqual(
                contract["runtime"]["measured_compatibility"]["receipt"],
                f"../../evidence/{receipt_path.name}",
            )

    def test_receipt_timestamp_is_bound_to_contract_index(self) -> None:
        expected = self.index["recorded_at"]
        self.assertEqual(
            verifier.receipt_recorded_at(None, self.contracts), expected
        )
        self.assertEqual(
            verifier.receipt_recorded_at(expected, self.contracts), expected
        )
        with self.assertRaisesRegex(ValueError, "does not match contract index"):
            verifier.receipt_recorded_at("2030-01-02T03:04:05Z", self.contracts)
        with self.assertRaisesRegex(ValueError, "exact UTC timestamp"):
            verifier.receipt_recorded_at("2030-01-02", self.contracts)

    def test_szl_kernels_source_binding_is_behaviorally_contradicted(self) -> None:
        contract = next(
            row for row in self.contracts if row["id"] == "SZLHOLDINGS/szl-kernels"
        )
        binding = contract["source_binding"]
        self.assertEqual(
            contract["revision"],
            "95f74bc6720cf95953b15cc6a454ee4d21dcf107",
        )
        self.assertEqual(
            binding["revision"],
            "8fa0e9fe0e45a79276a31ed0813b1eeef69a96b1",
        )
        self.assertEqual(
            binding["status"], "SOURCE_BINDING_UNVERIFIED_CONTRADICTED"
        )
        self.assertEqual(
            binding["live_artifact_status"],
            "IMMUTABLE_BYTES_AND_CPU_PROBES_VERIFIED",
        )
        self.assertEqual(
            verifier.validate_source_binding(contract),
            ["build/torch-cpu/szl_kernels/_chain.py"],
        )

        unsupported = copy.deepcopy(contract)
        unsupported["source_binding"]["status"] = "SOURCE_BOUND_AUTHORIZED_RELEASE"
        with self.assertRaisesRegex(ValueError, "qualification contradicted"):
            verifier.validate_source_binding(unsupported)

    def test_index_source_status_cannot_relabel_authoritative_contract(self) -> None:
        contract = next(
            row for row in self.contracts if row["id"] == "SZLHOLDINGS/szl-kernels"
        )
        row = copy.deepcopy(
            next(row for row in self.index["kernels"] if row["id"] == contract["id"])
        )
        row["source_status"] = "RELATED_GITHUB_SOURCE"
        with self.assertRaisesRegex(ValueError, "differs from authoritative"):
            verifier.validate_index_source_status(row, contract)

        row["source_status"] = "INVENTED_SOURCE_QUALIFICATION"
        with self.assertRaisesRegex(ValueError, "unsupported index source status"):
            verifier.validate_index_source_status(row, contract)

        invented = copy.deepcopy(self.contracts[0])
        invented["source_binding"]["status"] = "INVENTED_SOURCE_QUALIFICATION"
        with self.assertRaisesRegex(ValueError, "unsupported source binding status"):
            verifier.validate_source_binding(invented)

    def test_source_binding_schema_rejects_invented_and_malformed_states(self) -> None:
        source_schema = self.schema["properties"]["source_binding"]
        self.assertEqual(
            set(source_schema["properties"]["status"]["enum"]),
            verifier.SOURCE_BINDING_STATUSES,
        )
        for contract in self.contracts:
            self.assertTrue(
                schema_matches(contract["source_binding"], source_schema),
                contract["id"],
            )

        contradicted = copy.deepcopy(
            next(
                contract["source_binding"]
                for contract in self.contracts
                if contract["id"] == "SZLHOLDINGS/szl-kernels"
            )
        )
        malformed_states = []
        for mutate in (
            lambda value: value.update(status="INVENTED_SOURCE_QUALIFICATION"),
            lambda value: value.pop("historical_release_attempt"),
            lambda value: value.update(revision="main"),
            lambda value: value.update(invented_claim="VERIFIED"),
            lambda value: [row.update(status="MATCH") for row in value["file_mapping"]],
        ):
            value = copy.deepcopy(contradicted)
            mutate(value)
            malformed_states.append(value)
        for value in malformed_states:
            self.assertFalse(schema_matches(value, source_schema), value)

        source_bound = copy.deepcopy(contradicted)
        source_bound["status"] = verifier.SOURCE_BOUND_STATUS
        source_bound.pop("live_artifact_status")
        source_bound.pop("source_binding_status")
        source_bound.pop("reason")
        source_bound["historical_release_attempt"]["status"] = (
            verifier.SOURCE_BOUND_STATUS
        )
        self.assertFalse(schema_matches(source_bound, source_schema))
        for mapping in source_bound["file_mapping"]:
            mapping["source_size"] = mapping["artifact_size"]
            mapping["source_sha256"] = mapping["artifact_sha256"]
            mapping["status"] = "MATCH"
        self.assertTrue(schema_matches(source_bound, source_schema))

    def test_historical_receipt_bytes_are_immutable(self) -> None:
        receipt = ROOT / "evidence" / "kernel-selfcheck-20260726.json"
        canonical = receipt.read_text(encoding="utf-8").encode("utf-8")
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            "36bc2970b2722433f49329475251ba190cb035ddc5599e12db6cbaa4774b707b",
        )

    def test_receipt_writer_is_create_only_or_exact_noop(self) -> None:
        checked = json.loads(
            (ROOT / "evidence" / "kernel-selfcheck-20260808.json").read_text(
                encoding="utf-8"
            )
        )
        results = []
        for row in checked["results"]:
            result = copy.deepcopy(row)
            for key in ("id", "revision", "tree_digest_sha256"):
                result.pop(key)
            results.append(result)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            verifier.write_receipt(path, self.contracts, results)
            original = path.read_bytes()
            verifier.write_receipt(path, self.contracts, results)
            self.assertEqual(path.read_bytes(), original)
            path.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                verifier.write_receipt(path, self.contracts, results)

    def test_pr_ci_checks_out_and_attests_the_exact_head(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "kernel-contracts.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.head.sha", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', workflow)
        self.assertIn('--source-sha "$(git rev-parse HEAD)"', workflow)
        live_job = workflow.split("  live-integrity:", maxsplit=1)[1]
        self.assertIn("github.event_name == 'pull_request'", live_job)
        self.assertIn("github.event_name == 'schedule'", live_job)
        self.assertIn("github.event_name == 'workflow_dispatch'", live_job)
        self.assertIn("github.event.pull_request.head.sha", live_job)
        self.assertIn("persist-credentials: false", live_job)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"', live_job)
        self.assertNotIn("secrets.", live_job)


if __name__ == "__main__":
    unittest.main()
