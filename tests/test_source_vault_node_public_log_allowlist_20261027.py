"""Fail-close private Node assertion egress on the public Source Vault workflow.

No private source is loaded and no workflow is dispatched.
"""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/mmibkr-source-vault-bootstrap-r1.yml"


class SourceVaultNodeLogAllowlistTests(unittest.TestCase):
    def test_selected_ui_step_has_fixed_field_only_egress(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        start = "      - name: Accept selected read-only operator UI pure Node contracts\n"
        end = "      - name: Encrypt exact private source for parity refresh\n"
        self.assertEqual(source.count(start), 1)
        step = source.split(start, 1)[1].split(end, 1)[0]
        self.assertIn('for test_path in "${tests[@]}"; do', step)
        self.assertIn('if (cd "$source_root" && node "$test_path") >/dev/null 2>&1; then', step)
        self.assertEqual(step.count('node "$test_path"'), 1)
        self.assertNotIn("node --version", step)
        self.assertIn('MMIBKR_SELECTED_UI_NATIVE_CASE_${case_no}=PASS', step)
        self.assertIn('MMIBKR_SELECTED_UI_NATIVE_CASE_${case_no}=FAIL', step)
        self.assertIn('MMIBKR_SELECTED_UI_NATIVE_NODE_CONTRACTS=FAIL_CLOSED', step)
        self.assertIn("exit 1", step)
        self.assertIn("MMIBKR_SELECTED_UI_NATIVE_NODE_CONTRACTS=PASS", step)
        for path in (
            "BotConsolePage.acceptance.test.mjs",
            "botConsoleRecentActivity.test.mjs",
            "forwardEvidenceExactIdentity.test.mjs",
            "operator-market-ui.acceptance.test.mjs",
            "OperatorSubmitRouteTruth.test.mjs",
        ):
            self.assertIn(path, step)

    def test_synthetic_failing_process_cannot_emit_private_sentinel(self):
        # The same shell redirection shape, with a harmless synthetic child.
        script = (
            "set -euo pipefail; "
            "if (printf 'PRIVATE_NODE_SOURCE_SENTINEL\\n'; exit 17) >/dev/null 2>&1; "
            "then echo 'SAFE_PASS'; else echo 'SAFE_FAIL'; exit 1; fi"
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), "SAFE_FAIL")
        self.assertNotIn("PRIVATE_NODE_SOURCE_SENTINEL", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
