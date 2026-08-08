from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_kernel_registry as verifier


class KernelRegistryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = json.loads(
            (ROOT / "contracts" / "index.json").read_text(encoding="utf-8")
        )
        cls.contracts = verifier.load_contracts(ROOT / "contracts")

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


if __name__ == "__main__":
    unittest.main()
