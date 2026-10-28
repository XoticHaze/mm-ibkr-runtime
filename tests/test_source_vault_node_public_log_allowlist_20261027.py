"""Fail-close private Node assertion egress on the public Source Vault workflow.

No private source is loaded and no workflow is dispatched.
"""
from pathlib import Path
import os
import subprocess
import tempfile
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

    def test_cloudflare_private_source_failure_logs_are_fixed_field_only(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "node --test cloudflare/mmibkr-live-cloud-owner/test/*.test.mjs >/dev/null 2>&1",
            source,
        )
        self.assertIn(
            "npm install --no-audit --no-fund --package-lock=false >/dev/null 2>&1",
            source,
        )
        self.assertIn(
            "npx wrangler deploy --dry-run --outdir \"$RUNNER_TEMP/mmibkr-cloudflare-bundle\" >/dev/null 2>&1",
            source,
        )
        self.assertIn(
            "MMIBKR_CLOUDFLARE_LIVE_OWNER_CANARY_TESTS=FAIL_CLOSED", source
        )
        self.assertIn(
            "MMIBKR_CLOUDFLARE_WRANGLER_DRY_RUN=FAIL_CLOSED", source
        )
        self.assertIn(
            "MMIBKR_CLOUDFLARE_CANARY_WRANGLER_DRY_RUN=FAIL_CLOSED", source
        )
        self.assertNotIn('tail -n 25 "$RUNNER_TEMP/mmibkr-cloudflare-canary-dryrun.log"', source)

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


    def test_private_python_and_funded_pytest_use_fixed_field_only_egress(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        first_start = "      - name: Run existing MM no-broker config, checkpoint and futures regression tests\n"
        funded_start = "      - name: Validate selected funded replay and PnL issuer hold from exact encrypted source\n"
        ui_start = "      - name: Accept selected read-only operator UI pure Node contracts\n"
        self.assertEqual(source.count(first_start), 1)
        self.assertEqual(source.count(funded_start), 1)
        first = source.split(first_start, 1)[1].split(funded_start, 1)[0]
        funded = source.split(funded_start, 1)[1].split(ui_start, 1)[0]
        for step in (first, funded):
            self.assertIn("private_cmd() {", step)
            self.assertIn('if "$@" >/dev/null 2>&1; then return 0; fi', step)
            self.assertIn("MMIBKR_PRIVATE_SOURCE_COMMAND=FAIL_CLOSED", step)
            self.assertNotRegex(step, r"(?m)^\s+python -m ")
            self.assertNotRegex(step, r"(?m)^\s+python - <<'PY'")
        self.assertIn("private_cmd python scripts/mmibkr_fleet_private_source_consumer_v1.py", first)
        self.assertIn("private_cmd python -m unittest -v", first)
        self.assertIn("private_cmd python -m py_compile selected_runtime_live_order_intent_journal_v1.py", first)
        self.assertIn("private_cmd python -m unittest -v tests.test_selected_runtime_live_order_intent_journal_v1", first)
        self.assertIn("private_cmd python - <<'PY'", first)
        self.assertIn("private_cmd python -m pip install", first)
        self.assertIn("private_cmd python -m pip install", funded)
        self.assertIn("private_cmd env PYTHONDONTWRITEBYTECODE=1 python -m pytest -q", funded)
        self.assertIn("MMIBKR_SELECTED_FUNDED_PNL_NATIVE_EXACT_SOURCE=PASS", funded)

    def test_synthetic_private_python_failure_is_fixed_field_only(self):
        # Synthetic nested failure, no private code, source or service access.
        script = (
            "set -euo pipefail; "
            "private_cmd() { if \"$@\" >/dev/null 2>&1; then return 0; fi; "
            "echo MMIBKR_PRIVATE_SOURCE_COMMAND=FAIL_CLOSED; return 1; }; "
            "private_cmd bash -c 'printf PRIVATE_PYTHON_SENTINEL\\\\n >&2; exit 17'"
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), "MMIBKR_PRIVATE_SOURCE_COMMAND=FAIL_CLOSED")
        self.assertNotIn("PRIVATE_PYTHON_SENTINEL", result.stdout + result.stderr)


    def test_source_validation_profile_is_explicit_and_fail_closed(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("validation_profile = 'strict_ui'", source)
        self.assertIn("validation_profile not in {'strict_ui', 'p0_owner'}", source)
        self.assertIn("source validation profile rejected", source)
        self.assertIn("REQUEST_VALIDATION_PROFILE=' + validation_profile", source)
        self.assertIn("validation_profile = str(node.get('validation_profile') or 'strict_ui')", source)
        self.assertIn("validation_profile = str((event.get('inputs') or {}).get('validation_profile') or 'strict_ui')", source)

    def test_p0_owner_ui_stage_is_not_applicable_but_strict_ui_missing_test_fails(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        start = "      - name: Accept selected read-only operator UI pure Node contracts\\n"
        end = "      - name: Encrypt exact private source for parity refresh\\n"
        step = source.split(start, 1)[1].split(end, 1)[0]
        script = step.split("        run: |\\n", 1)[1]
        script = "\\n".join(line[10:] if line.startswith("          ") else line
                           for line in script.splitlines())
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ, RUNNER_TEMP=td, REQUEST_VALIDATION_PROFILE="p0_owner")
            p0 = subprocess.run(["bash", "-c", script], env=env,
                                capture_output=True, text=True, check=False)
            self.assertEqual(p0.returncode, 0, p0.stderr)
            self.assertIn("MMIBKR_SELECTED_UI_NATIVE_NODE_CONTRACTS=NOT_APPLICABLE_P0_OWNER", p0.stdout)
            self.assertNotIn("MMIBKR_SELECTED_UI_NATIVE_NODE_CONTRACTS=PASS", p0.stdout)
            env["REQUEST_VALIDATION_PROFILE"] = "strict_ui"
            strict = subprocess.run(["bash", "-c", script], env=env,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(strict.returncode, 1)
            self.assertIn("MMIBKR_SELECTED_UI_NATIVE_CASE_1=FAIL", strict.stdout)
            self.assertIn("MMIBKR_SELECTED_UI_NATIVE_NODE_CONTRACTS=FAIL_CLOSED", strict.stdout)
            self.assertNotIn("botConsoleRecentActivity.test.mjs", strict.stdout + strict.stderr)

if __name__ == "__main__":
    unittest.main()
