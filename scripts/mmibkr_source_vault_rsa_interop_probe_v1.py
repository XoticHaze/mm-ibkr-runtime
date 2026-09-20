from __future__ import annotations

"""Probe runtime -> Fleet RSA-OAEP interoperability without exposing key material.

The probe uses the already-approved reusable source-vault manifest identity,
wraps a fresh random 32-byte probe with Fleet's public RSA key, asks Fleet to
unwrap it through the canonical GitHub OIDC consumer route, and compares the
returned bytes in-memory. Neither the probe nor returned key bytes are logged.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import mmibkr_source_vault_consumer_v1 as consumer
from scripts import mmibkr_source_vault_publish_v1 as publisher


SCHEMA = "mmibkr-source-vault-rsa-interop-probe-v1"


def probe(
    *,
    source_sha: str,
    run_id: str,
    authority_base: str = consumer.DEFAULT_AUTHORITY_BASE,
    public_repo: str = consumer.DEFAULT_PUBLIC_REPO,
    public_branch: str = consumer.DEFAULT_PUBLIC_BRANCH,
) -> dict[str, object]:
    source_sha = publisher._valid_sha40(source_sha)
    run_id = str(run_id or "").strip()
    if not run_id.isdigit():
        raise RuntimeError("run_id_rejected")

    manifest_path = f"source-vault/{source_sha}/manifest.json"
    manifest_raw = consumer._fetch(
        consumer._raw_url(public_repo, public_branch, manifest_path)
    )
    manifest = consumer._validate_manifest(
        json.loads(manifest_raw.decode("utf-8")),
        source_sha=source_sha,
    )
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()

    vault_public = publisher.fetch_vault_public_key(authority_base)
    if str(vault_public.get("key_id") or "") != str(manifest.get("key_id") or ""):
        raise RuntimeError("vault_key_identity_mismatch")

    jwk = vault_public.get("public_jwk")
    if not isinstance(jwk, dict):
        raise RuntimeError("vault_public_jwk_missing")
    public_key = publisher._rsa_public_key(jwk)

    # Ephemeral diagnostic bytes exist only in memory and are never emitted.
    probe_key = os.urandom(32)
    sealed_probe = public_key.encrypt(
        probe_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    oidc = consumer._oidc_token()
    unwrap = consumer._unwrap_api(
        authority_base,
        run_id,
        oidc,
        {
            "schema": consumer.UNWRAP_SCHEMA,
            "source_sha": source_sha,
            "manifest_sha256": manifest_sha,
            "archive_sha256": str(manifest["archive_sha256"]),
            "archive_bytes": int(manifest["archive_bytes"]),
            "key_id": str(manifest["key_id"]),
            "sealed_key_b64": base64.b64encode(sealed_probe).decode("ascii"),
        },
    )
    if unwrap.get("ok") is not True or unwrap.get("approved") is not True:
        raise RuntimeError("vault_rsa_interop_unwrap_not_approved")
    if str(unwrap.get("source_sha") or "") != source_sha:
        raise RuntimeError("vault_rsa_interop_source_identity_mismatch")
    if str(unwrap.get("manifest_sha256") or "") != manifest_sha:
        raise RuntimeError("vault_rsa_interop_manifest_identity_mismatch")

    returned = base64.b64decode(
        str(unwrap.get("master_key_b64") or "").encode("ascii"),
        validate=True,
    )
    if not hmac.compare_digest(returned, probe_key):
        raise RuntimeError("vault_rsa_interop_roundtrip_mismatch")

    return {
        "schema": SCHEMA,
        "ok": True,
        "source_sha": source_sha,
        "manifest_sha256": manifest_sha,
        "archive_sha256": str(manifest["archive_sha256"]),
        "archive_bytes": int(manifest["archive_bytes"]),
        "key_id": str(manifest["key_id"]),
        "runtime_to_fleet_rsa_oaep_roundtrip": True,
        "probe_key_emitted": False,
        "private_repository_token_used": False,
        "public_plaintext_included": False,
        "live_execution_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--authority-base", default=consumer.DEFAULT_AUTHORITY_BASE)
    parser.add_argument("--public-repo", default=consumer.DEFAULT_PUBLIC_REPO)
    parser.add_argument("--public-branch", default=consumer.DEFAULT_PUBLIC_BRANCH)
    args = parser.parse_args()

    result = probe(
        source_sha=args.source_sha,
        run_id=args.run_id,
        authority_base=args.authority_base,
        public_repo=args.public_repo,
        public_branch=args.public_branch,
    )
    print("MMIBKR_SOURCE_VAULT_RSA_INTEROP=" + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
