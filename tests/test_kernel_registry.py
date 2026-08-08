from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
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

    def test_receipt_timestamp_is_injected_or_current_utc(self) -> None:
        explicit = "2030-01-02T03:04:05Z"
        self.assertEqual(verifier.receipt_recorded_at(explicit), explicit)
        self.assertRegex(
            verifier.receipt_recorded_at(None),
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        )
        with self.assertRaisesRegex(ValueError, "exact UTC timestamp"):
            verifier.receipt_recorded_at("2030-01-02")

    def test_szl_kernels_release_is_source_bound_and_authorized(self) -> None:
        contract = next(
            row for row in self.contracts if row["id"] == "SZLHOLDINGS/szl-kernels"
        )
        binding = contract["source_binding"]
        self.assertEqual(
            contract["revision"],
            "95f74bc6720cf95953b15cc6a454ee4d21dcf107",
        )
        self.assertEqual(binding["status"], "SOURCE_BOUND_AUTHORIZED_RELEASE")
        self.assertEqual(
            binding["revision"],
            "8fa0e9fe0e45a79276a31ed0813b1eeef69a96b1",
        )
        self.assertEqual(binding["readback"], "EXACT_BYTES_VERIFIED")
        self.assertEqual(
            binding["release_authorization"]["status"],
            "AUTHORIZED_PROTECTED_MAIN",
        )


if __name__ == "__main__":
    unittest.main()
