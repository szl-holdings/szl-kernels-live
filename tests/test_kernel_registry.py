from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_kernel_registry as verifier


class KernelRegistryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
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
        receipt_path = ROOT / "evidence" / "kernel-selfcheck-20260726.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        expected = receipt.pop("payload_sha256")
        actual = hashlib.sha256(verifier.canonical_json(receipt)).hexdigest()
        self.assertEqual(actual, expected)
        self.assertEqual(receipt["summary"], {"kernels": 10, "passed": 10, "failed": 0})


if __name__ == "__main__":
    unittest.main()
