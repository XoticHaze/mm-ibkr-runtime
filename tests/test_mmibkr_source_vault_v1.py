from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from scripts import mmibkr_source_vault_publish_v1 as pub
from scripts import mmibkr_source_vault_consumer_v1 as con


def _vault_key_response():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = private.public_key().public_numbers()

    def enc(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    jwk = {
        "kty": "RSA",
        "n": enc(public.n),
        "e": enc(public.e),
        "alg": "RSA-OAEP-256",
        "use": "enc",
        "key_ops": ["encrypt"],
        "ext": True,
    }
    return private, {
        "schema": pub.PUBLIC_KEY_SCHEMA,
        "ok": True,
        "algorithm": "RSA-OAEP-256",
        "key_id": "sha256:" + "1" * 64,
        "public_jwk": jwk,
        "private_key_exported": False,
        "source_approval_is_code_pinned": True,
    }


def _archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, raw in [
            ("mm-ibkr/Dockerfile.bot", b"FROM scratch\n"),
            ("mm-ibkr/main.py", b"print('ok')\n"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


class SourceVaultTests(unittest.TestCase):
    def test_snapshot_roundtrip_binds_source_manifest_and_archive(self):
        private, key = _vault_key_response()
        archive = _archive()
        source = "a" * 40
        manifest, chunks = pub.encrypt_snapshot(
            archive,
            source_sha=source,
            source_ref=source,
            vault_public_key=key,
            chunk_chars=2048,
        )
        files, _, manifest_sha = pub.snapshot_publication_files(manifest, chunks)
        stored = {path: raw for path, raw in files}
        master_key = private.decrypt(
            base64.b64decode(manifest["sealed_key_b64"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        def fetch(url):
            return stored[url.split("/mmibkr-source-vault/", 1)[1]]

        def unwrap(authority, run_id, token, payload):
            self.assertEqual(payload["source_sha"], source)
            self.assertEqual(payload["manifest_sha256"], manifest_sha)
            self.assertEqual(payload["archive_sha256"], hashlib.sha256(archive).hexdigest())
            return {
                "ok": True,
                "approved": True,
                "source_sha": source,
                "manifest_sha256": manifest_sha,
                "archive_sha256": payload["archive_sha256"],
                "archive_bytes": payload["archive_bytes"],
                "master_key_b64": base64.b64encode(master_key).decode(),
                "reusable_attestation_stored": True,
            }

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result = con.materialize(
                source_sha=source,
                destination=root / "out",
                archive_output=root / "source.tar.gz",
                output=root / "materialization.json",
                run_id="12345",
                fetch=fetch,
                token_factory=lambda: "oidc",
                unwrap_api=unwrap,
            )
            self.assertTrue((Path(result["source_root"]) / "Dockerfile.bot").is_file())
            self.assertEqual(result["source_archive_sha256"], hashlib.sha256(archive).hexdigest())
            self.assertEqual(result["source_manifest_sha256"], manifest_sha)
            self.assertTrue(result["vault_attestation_verified"])
            self.assertFalse(result["private_repository_token_used"])
            self.assertFalse(result["plaintext_emitted"])

    def test_tampered_ciphertext_is_rejected_before_unwrap(self):
        _, key = _vault_key_response()
        source = "b" * 40
        manifest, chunks = pub.encrypt_snapshot(
            _archive(),
            source_sha=source,
            source_ref=source,
            vault_public_key=key,
            chunk_chars=2048,
        )
        files, _, _ = pub.snapshot_publication_files(manifest, chunks)
        stored = {path: raw for path, raw in files}
        first = manifest["chunks"][0]["path"]
        original = stored[first]
        replacement = b"A" if original[:1] != b"A" else b"B"
        stored[first] = replacement + original[1:]
        self.assertNotEqual(stored[first], original)

        def fetch(url):
            return stored[url.split("/mmibkr-source-vault/", 1)[1]]

        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(RuntimeError, "chunk_integrity"):
                con.materialize(
                    source_sha=source,
                    destination=Path(td) / "o",
                    archive_output=Path(td) / "a",
                    output=Path(td) / "m",
                    run_id="12345",
                    fetch=fetch,
                    token_factory=lambda: "oidc",
                    unwrap_api=lambda *a, **k: self.fail("unwrap must not be called"),
                )

    def test_manifest_requires_no_public_plaintext_or_private_token(self):
        _, key = _vault_key_response()
        source = "c" * 40
        manifest, _ = pub.encrypt_snapshot(
            _archive(),
            source_sha=source,
            source_ref=source,
            vault_public_key=key,
        )
        self.assertIs(manifest["public_plaintext_included"], False)
        self.assertIs(manifest["private_repository_token_used"], False)
        self.assertIs(manifest["live_execution_authority"], False)


if __name__ == "__main__":
    unittest.main()
