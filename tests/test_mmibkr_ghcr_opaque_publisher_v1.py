"""Public contract for existing GHCR publisher opaque Pi extension.

Only synthetic source IDs; no private source, token or registry mutation.
"""
import io
import re
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from scripts import mmibkr_ghcr_opaque_publish_v1 as app


class _Response:
    def __init__(self, body):
        self.body = io.BytesIO(json.dumps(body).encode())
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return self.body.read(size)


class OpaquePublisherSourceTests(unittest.TestCase):
    def test_exact_brokerless_six_suite_contract(self):
        self.assertEqual(len(app.NATIVE), 6)
        self.assertEqual(len(set(app.NATIVE)), 6)
        self.assertIn("test_selected_runtime_live_execution_ledger_v1", app.NATIVE)
        self.assertIn("test_pi_root_external_baseline_owner_epoch_20261106", app.NATIVE)
        self.assertIn("count<1:sys.exit(81)", app.NATIVE_RUNNER)
        self.assertIn("result.testsRun!=count", app.NATIVE_RUNNER)

    def test_exact_workflow_script_entrypoint_imports_cleanly(self):
        # Real launch form used on ubuntu ARM64. It must reject the event,
        # rather than fail importing scripts before reaching the safety guard.
        import subprocess
        import sys
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, GITHUB_EVENT_NAME="workflow_dispatch")
        proc = subprocess.run(
            [sys.executable, "scripts/mmibkr_ghcr_opaque_publish_v1.py"],
            cwd=root, env=env, text=True, capture_output=True, timeout=15,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("PI_GHCR_HELD_STAGE=TRIGGER_NOT_PUSH", proc.stdout)
        self.assertNotIn("ModuleNotFoundError", proc.stderr)

    def test_wrong_github_event_does_not_touch_secrets_or_docker(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch"}, clear=True):
            with self.assertRaises(app.Held) as cm:
                app.publish()
        self.assertEqual(cm.exception.stage, "TRIGGER_NOT_PUSH")

    def test_private_candidate_only_via_authenticated_fleet(self):
        synthetic = {
            "schema": "mmibkr.pi_ghcr_opaque_candidate.v1",
            "source_sha": "a" * 40,
            "publication_only": True,
            "broker_authorized": False,
            "native_brokerless_suites": list(app.NATIVE),
        }
        with patch.object(app, "_oidc_token", return_value="synthetic"):
            with patch.object(app, "urlopen", return_value=_Response(synthetic)) as opened:
                self.assertEqual(app.private_candidate("12345678"), "a" * 40)
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url,
                         app.FLEET + "/v1/source-vault/pi-image-candidate")
        self.assertEqual(request.get_method(), "POST")
        self.assertNotIn("a" * 40, request.full_url)
        self.assertIn("Bearer synthetic", dict(request.header_items()).values())

    def test_bad_candidate_denied(self):
        invalid = {
            "schema": "mmibkr.pi_ghcr_opaque_candidate.v1",
            "source_sha": "a" * 40,
            "publication_only": False,
            "broker_authorized": False,
            "native_brokerless_suites": list(app.NATIVE),
        }
        with patch.object(app, "_oidc_token", return_value="synthetic"):
            with patch.object(app, "urlopen", return_value=_Response(invalid)):
                with self.assertRaises(app.Held) as cm:
                    app.private_candidate("12345678")
        self.assertEqual(cm.exception.stage, "CANDIDATE_POLICY")

    def test_package_must_preexist_as_private(self):
        with patch.object(app, "urlopen", return_value=_Response({
            "name": "mmibkr-pi-canonical-private-20261030", "visibility": "private"
        })):
            app.existing_private_package("synthetic")
        with patch.object(app, "urlopen", return_value=_Response({
            "name": "mmibkr-pi-canonical-private-20261030", "visibility": "public"
        })):
            with self.assertRaises(app.Held) as cm:
                app.existing_private_package("synthetic")
            self.assertEqual(cm.exception.stage, "PRIVATE_PACKAGE_VISIBILITY")

    def test_no_private_sha_in_public_fire_or_publisher_source(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts/mmibkr_ghcr_opaque_publish_v1.py").read_text()
        workflow = (root / ".github/workflows/mmibkr-ghcr-opaque-publish-r1.yml").read_text()
        self.assertIn("secrets.MMIBKR_GHCR_PRIVATE_PUSH_PAT", workflow)
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertNotIn("source_sha:", workflow)
        self.assertNotIn("docker push", workflow)
        self.assertIn("private_candidate(run_id)", source)
        self.assertIn("MMIBKR_GHCR_PRIVATE_PUSH_PAT", source)
        self.assertIn("GHCR_DIGEST_IDENTITY", source)
        self.assertIn("PI_GHCR_PUBLIC_PRIVATE_SHA_OR_DIGEST=NONE", source)
        self.assertIn("private_source_id_emitted", workflow)
        self.assertIn("private_image_digest_emitted", workflow)
        self.assertIsNone(re.search(
            r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])",
            source + Path(__file__).read_text(encoding="utf-8"),
        ))


if __name__ == "__main__":
    unittest.main()
