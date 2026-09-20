from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts import mmibkr_fleet_private_source_consumer_v1 as mod


class FakeResponse:
    def __init__(self, raw: bytes, headers: dict[str, str]):
        self._buf = io.BytesIO(raw)
        self.headers = headers
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._buf.read(size)

    def close(self) -> None:
        self.closed = True


def make_archive(*, traversal: bool = False) -> bytes:
    root = "XoticHaze-mm-IBKR-ca1d97"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        entries = [
            (f"{root}/Dockerfile.bot", b"FROM python:3.11-slim AS bot\n"),
            (f"{root}/main.py", b"print('ok')\n"),
        ]
        if traversal:
            entries.append((f"{root}/../escape.txt", b"nope"))
        for name, raw in entries:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


class FleetPrivateSourceConsumerTests(unittest.TestCase):
    def test_stream_roundtrip_hashes_extracts_and_attests_exact_bytes(self):
        source = "a" * 40
        raw = make_archive()
        stream_id = "12345678-1234-1234-1234-123456789abc"
        expected_sha = hashlib.sha256(raw).hexdigest()
        attest_calls = []

        def open_stream(authority, source_sha, run_id, token):
            self.assertEqual(authority, "https://fleet.example")
            self.assertEqual(source_sha, source)
            self.assertEqual(run_id, "12345")
            self.assertEqual(token, "oidc-1")
            return FakeResponse(
                raw,
                {
                    "x-mmibkr-source-sha": source,
                    "x-mmibkr-source-stream-id": stream_id,
                    "x-mmibkr-source-transport": mod.TRANSPORT,
                    "x-mmibkr-private-source-token-exposed": "false",
                    "x-mmibkr-source-archive-bytes": str(len(raw)),
                },
            )

        def attest(authority, run_id, token, payload):
            attest_calls.append((authority, run_id, token, dict(payload)))
            return {
                "ok": True,
                "source_sha": source,
                "archive_sha256": expected_sha,
                "archive_bytes": len(raw),
                "private_attestation_stored": True,
                "source_transport": mod.TRANSPORT,
            }

        tokens = iter(["oidc-1", "oidc-2"])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result = mod.materialize(
                source_sha=source,
                run_id="12345",
                destination=root / "extract",
                archive_output=root / "source.tar.gz",
                output=root / "materialization.json",
                authority_base="https://fleet.example",
                token_factory=lambda: next(tokens),
                open_stream=open_stream,
                attest_api=attest,
            )
            self.assertEqual(result["source_archive_sha256"], expected_sha)
            self.assertEqual(result["source_archive_bytes"], len(raw))
            self.assertEqual(result["source_stream_id"], stream_id)
            self.assertTrue(result["private_source_attestation_verified"])
            self.assertFalse(result["runtime_private_repository_token_used"])
            self.assertFalse(result["fleet_private_source_credential_exposed"])
            self.assertFalse(result["public_plaintext_emitted"])
            self.assertTrue((Path(result["source_root"]) / "Dockerfile.bot").is_file())
            self.assertEqual(
                hashlib.sha256((root / "source.tar.gz").read_bytes()).hexdigest(),
                expected_sha,
            )
            saved = json.loads((root / "materialization.json").read_text())
            self.assertEqual(saved["source_sha"], source)

        self.assertEqual(len(attest_calls), 1)
        _, _, token, payload = attest_calls[0]
        self.assertEqual(token, "oidc-2")
        self.assertEqual(payload["source_sha"], source)
        self.assertEqual(payload["stream_id"], stream_id)
        self.assertEqual(payload["archive_sha256"], expected_sha)
        self.assertEqual(payload["archive_bytes"], len(raw))

    def test_wrong_source_header_fails_before_attestation(self):
        source = "b" * 40
        raw = make_archive()
        calls = []

        def open_stream(*args):
            return FakeResponse(
                raw,
                {
                    "x-mmibkr-source-sha": "c" * 40,
                    "x-mmibkr-source-stream-id": "12345678-1234-1234-1234-123456789abc",
                    "x-mmibkr-source-transport": mod.TRANSPORT,
                    "x-mmibkr-private-source-token-exposed": "false",
                },
            )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaisesRegex(RuntimeError, "source_sha_header"):
                mod.materialize(
                    source_sha=source,
                    run_id="12345",
                    destination=root / "extract",
                    archive_output=root / "source.tar.gz",
                    output=root / "materialization.json",
                    token_factory=lambda: "oidc",
                    open_stream=open_stream,
                    attest_api=lambda *a, **k: calls.append((a, k)),
                )
        self.assertEqual(calls, [])

    def test_tar_path_traversal_is_rejected(self):
        raw = make_archive(traversal=True)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "source.tar.gz"
            archive.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, "path_rejected"):
                mod._safe_extract_github_tar(archive, root / "extract")


if __name__ == "__main__":
    unittest.main()
