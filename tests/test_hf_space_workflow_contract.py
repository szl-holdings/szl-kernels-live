from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "hf-space-deploy.yml"


class HfSpaceWorkflowContractTests(unittest.TestCase):
    def test_terminal_attestation_uses_pinned_build_provenance_action(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        step = workflow.split(
            "- name: Attest canonical final success receipt bytes", 1
        )[1].split("- name: Record terminal attestation action completion", 1)[0]

        self.assertEqual(
            workflow.count(
                "uses: actions/attest-build-provenance@"
                "a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32"
            ),
            1,
        )
        self.assertIn(
            "uses: actions/attest-build-provenance@"
            "a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
            step,
        )
        self.assertIn(
            "subject-path: ${{ runner.temp }}/kernel-terminal-candidate/"
            "hf-canonical-success-receipt.json",
            step,
        )
        self.assertNotIn("shell:", step)
        self.assertNotIn("run:", step)
        self.assertNotIn("bounded-action", step)
        self.assertNotIn("terminal-actions/attest/dist/index.js", step)

    def test_attestation_timeout_has_a_separate_credential_free_evidence_job(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        attest = workflow.split("  attest:\n", 1)[1].split(
            "  attest-timeout-fallback:\n", 1
        )[0]
        fallback = workflow.split("  attest-timeout-fallback:\n", 1)[1]

        self.assertIn(
            "oidc_completed: ${{ steps.oidc-completion.outputs.complete }}",
            attest,
        )
        self.assertLess(
            attest.index("uses: actions/attest-build-provenance@"),
            attest.index("id: oidc-completion"),
        )
        self.assertIn("needs: [authorize, deploy, measure, attest]", fallback)
        self.assertIn(
            "needs.attest.outputs.oidc_completed != 'true'",
            fallback,
        )
        self.assertNotIn("candidate_outcome:", attest)
        self.assertIn("id: timeout-candidate", fallback)
        self.assertIn("candidate-receipt", fallback)
        self.assertIn(
            '--candidate-receipt-outcome "${{ steps.timeout-candidate.outcome }}"',
            fallback,
        )
        self.assertIn("--oidc-outcome \"${{ needs.attest.result }}\"", fallback)
        self.assertIn("stage-failure", fallback)
        self.assertIn("kernel-attestation-timeout-primary-", fallback)
        self.assertIn("kernel-attestation-timeout-retry-", fallback)
        self.assertIn("Enforce attestation-timeout evidence preservation", fallback)
        self.assertIn("permissions: {}", fallback)
        self.assertIn('GITHUB_TOKEN: ""', fallback)
        self.assertIn('GH_TOKEN: ""', fallback)
        self.assertIn('HF_TOKEN: ""', fallback)
        self.assertEqual(fallback.count('token: ""'), 2)
        setup_python = fallback.split("- uses: actions/setup-python@", 1)[1].split(
            "- uses: actions/setup-node@", 1
        )[0]
        setup_node = fallback.split("- uses: actions/setup-node@", 1)[1].split(
            "- name: Download sealed authorized input", 1
        )[0]
        for step in (setup_python, setup_node):
            for credential in (
                "ACTIONS_RUNTIME_TOKEN",
                "ACTIONS_RUNTIME_URL",
                "ACTIONS_RESULTS_URL",
                "ACTIONS_CACHE_URL",
            ):
                self.assertIn(f'{credential}: ""', step)
        self.assertNotIn("id-token: write", fallback)
        self.assertNotIn("attestations: write", fallback)
        self.assertNotIn("secrets.HF_TOKEN", fallback)
        self.assertNotIn("deploy_hf_space.py publish", fallback)

    def test_terminal_failure_retry_retains_an_execution_window(self) -> None:
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
