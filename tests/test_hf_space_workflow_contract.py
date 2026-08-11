from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "hf-space-deploy.yml"


class HfSpaceWorkflowContractTests(unittest.TestCase):
    def test_terminal_failure_retry_keeps_its_execution_window(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        primary = workflow.split(
            "- name: Preserve terminal failure evidence primary", 1
        )[1].split("- name: Preserve terminal failure evidence retry", 1)[0]
        retry = workflow.split(
            "- name: Preserve terminal failure evidence retry", 1
        )[1].split("- name: Enforce terminal publication evidence", 1)[0]

        self.assertIn(
            "--action upload --reserve-seconds 120 --max-seconds 60", primary
        )
        self.assertIn(
            "--action upload --reserve-seconds 60 --max-seconds 45", retry
        )
        self.assertNotIn("--reserve-seconds 30", retry)


if __name__ == "__main__":
    unittest.main()
