from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts import mmibkr_source_vault_rsa_interop_probe_v1 as probe


SOURCE = "a" * 40


class _FakePublicKey:
    def __init__(self, captured):
        self.captured = captured

    def encrypt(self, plaintext, _padding):
        self.captured["probe"] = bytes(plaintext)
        return b"sealed-probe"


class SourceVaultRsaInteropProbeTests(unittest.TestCase):
    def test_direct_script_execution_imports_repo_package(self):
        proc = subprocess.run(
            [
                sys.executable,
                "scripts/mmibkr_source_vault_rsa_interop_probe_v1.py",
                "--help",
            ],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--source-sha", proc.stdout)

    def test_probe_compares_roundtrip_without_emitting_probe_key(self):
        captured = {}
        manifest = {
            "source_sha": SOURCE,
            "archive_sha256": "b" * 64,
            "archive_bytes": 123,
            "key_id": "sha256:" + "c" * 64,
        }

        def fake_unwrap(_base, _run_id, _oidc, payload):
            captured["payload"] = payload
            return {
                "ok": True,
                "approved": True,
                "source_sha": SOURCE,
                "manifest_sha256": payload["manifest_sha256"],
                "archive_sha256": manifest["archive_sha256"],
                "archive_bytes": manifest["archive_bytes"],
                "master_key_b64": base64.b64encode(captured["probe"]).decode("ascii"),
            }

        with (
            patch.object(probe.consumer, "_fetch", return_value=b"{}"),
            patch.object(probe.consumer, "_validate_manifest", return_value=manifest),
            patch.object(probe.consumer, "_oidc_token", return_value="a.b.c"),
            patch.object(probe.consumer, "_unwrap_api", side_effect=fake_unwrap),
            patch.object(
                probe.publisher,
                "fetch_vault_public_key",
                return_value={
                    "key_id": manifest["key_id"],
                    "public_jwk": {"kty": "RSA", "n": "x", "e": "AQAB"},
                },
            ),
            patch.object(
                probe.publisher,
                "_rsa_public_key",
                return_value=_FakePublicKey(captured),
            ),
        ):
            result = probe.probe(source_sha=SOURCE, run_id="12345")

        self.assertTrue(result["ok"])
        self.assertTrue(result["runtime_to_fleet_rsa_oaep_roundtrip"])
        self.assertFalse(result["probe_key_emitted"])
        self.assertNotIn("master_key_b64", result)
        self.assertNotIn("sealed_key_b64", result)
        self.assertEqual(captured["payload"]["source_sha"], SOURCE)
        self.assertEqual(
            base64.b64decode(captured["payload"]["sealed_key_b64"]),
            b"sealed-probe",
        )


if __name__ == "__main__":
    unittest.main()
