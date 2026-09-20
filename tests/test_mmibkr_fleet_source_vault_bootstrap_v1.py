from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from scripts import mmibkr_fleet_source_vault_bootstrap_v1 as boot


SOURCE = "a" * 40


class FleetSourceVaultBootstrapTests(unittest.TestCase):
    def test_direct_script_execution_imports_repo_package(self):
        proc = subprocess.run(
            [sys.executable, "scripts/mmibkr_fleet_source_vault_bootstrap_v1.py", "--help"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--source-sha", proc.stdout)

    def test_existing_snapshot_skips_private_source_fetch(self):
        existing = {
            "manifest": {
                "source_ref": SOURCE,
                "archive_sha256": "b" * 64,
                "archive_bytes": 123,
            },
            "manifest_sha256": "c" * 64,
            "manifest_path": f"source-vault/{SOURCE}/manifest.json",
        }
        fleet_materialize = Mock(side_effect=AssertionError("private stream must be skipped"))
        with tempfile.TemporaryDirectory() as td:
            result = boot.bootstrap(
                source_sha=SOURCE,
                run_id="12345",
                work_root=Path(td) / "work",
                output=Path(td) / "receipt.json",
                existing_snapshot=lambda **_: existing,
                fleet_materialize=fleet_materialize,
            )
        self.assertEqual(result["status"], "already_published")
        self.assertFalse(result["bootstrap_private_source_fetch_used"])
        self.assertFalse(result["runtime_private_repository_token_used"])
        self.assertFalse(result["public_plaintext_included"])
        fleet_materialize.assert_not_called()

    def test_missing_snapshot_uses_fleet_once_then_publishes_only_ciphertext(self):
        archive = b"private exact source archive"
        archive_sha = boot._sha256(archive)

        def materialize(**kwargs):
            kwargs["archive_output"].parent.mkdir(parents=True, exist_ok=True)
            kwargs["archive_output"].write_bytes(archive)
            return {
                "ok": True,
                "source_sha": SOURCE,
                "source_archive_sha256": archive_sha,
                "source_archive_bytes": len(archive),
                "private_source_attestation_verified": True,
                "runtime_private_repository_token_used": False,
                "fleet_private_source_credential_exposed": False,
                "public_plaintext_emitted": False,
            }

        manifest = {
            "source_sha": SOURCE,
            "source_ref": SOURCE,
            "archive_sha256": archive_sha,
            "archive_bytes": len(archive),
            "key_id": "sha256:" + "d" * 64,
        }
        publish = Mock(return_value="e" * 40)

        with tempfile.TemporaryDirectory() as td:
            result = boot.bootstrap(
                source_sha=SOURCE,
                run_id="12345",
                work_root=Path(td) / "work",
                output=Path(td) / "receipt.json",
                public_token="public-runtime-token",
                existing_snapshot=lambda **_: None,
                fleet_materialize=materialize,
                fetch_vault_public_key=lambda _: {"key_id": "key"},
                encrypt_snapshot=lambda *args, **kwargs: (
                    manifest,
                    [("source-vault/x/ciphertext-0000.txt", b"ciphertext")],
                ),
                snapshot_publication_files=lambda *args, **kwargs: (
                    [("source-vault/x/ciphertext-0000.txt", b"ciphertext")],
                    b"manifest",
                    "f" * 64,
                ),
                publish_atomic=publish,
            )

        self.assertEqual(result["status"], "published")
        self.assertTrue(result["bootstrap_private_source_fetch_used"])
        self.assertEqual(result["archive_sha256"], archive_sha)
        self.assertFalse(result["runtime_private_repository_token_used"])
        self.assertFalse(result["fleet_private_source_credential_exposed"])
        self.assertFalse(result["public_plaintext_included"])
        publish.assert_called_once()
        self.assertEqual(publish.call_args.kwargs["repo"], boot.DEFAULT_PUBLIC_REPO)
        self.assertEqual(publish.call_args.kwargs["branch"], boot.DEFAULT_PUBLIC_BRANCH)

    def test_missing_snapshot_requires_only_public_write_token_at_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(
                RuntimeError, "public_repository_write_token_required"
            ):
                boot.bootstrap(
                    source_sha=SOURCE,
                    run_id="12345",
                    work_root=Path(td) / "work",
                    output=Path(td) / "receipt.json",
                    existing_snapshot=lambda **_: None,
                )


if __name__ == "__main__":
    unittest.main()
