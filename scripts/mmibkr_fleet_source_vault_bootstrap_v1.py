from __future__ import annotations

"""Bootstrap one reusable encrypted MM-IBKR source-vault snapshot through Fleet.

The private GitHub credential stays inside Fleet Authority. This runtime helper
uses GitHub OIDC to receive one code-approved exact-SHA private archive from
Fleet only when the reusable public ciphertext snapshot is absent. It then
encrypts that archive with the existing source-vault public key and publishes
ciphertext + manifest to this public runtime repository.

Normal startup consumes the reusable encrypted snapshot and does not need the
private-source stream again.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

# Keep direct script execution equivalent to package import under Actions/Docker.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import mmibkr_fleet_private_source_consumer_v1 as fleet
from scripts import mmibkr_source_vault_consumer_v1 as consumer
from scripts import mmibkr_source_vault_publish_v1 as publisher

DEFAULT_PUBLIC_REPO = "XoticHaze/mm-ibkr-runtime"
DEFAULT_PUBLIC_BRANCH = "mmibkr-source-vault"
RECEIPT_SCHEMA = "mmibkr-source-vault-bootstrap-receipt-v1"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _existing_snapshot(
    *,
    source_sha: str,
    public_repo: str,
    public_branch: str,
    fetch: Callable[[str], bytes] = consumer._fetch,
) -> dict[str, Any] | None:
    path = f"source-vault/{source_sha}/manifest.json"
    try:
        raw = fetch(consumer._raw_url(public_repo, public_branch, path))
    except RuntimeError as exc:
        if "snapshot_fetch_http_404" in str(exc):
            return None
        raise
    try:
        node = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("existing_snapshot_manifest_json_rejected") from exc
    manifest = consumer._validate_manifest(node, source_sha=source_sha)
    return {
        "manifest": manifest,
        "manifest_sha256": _sha256(raw),
        "manifest_path": path,
    }


def bootstrap(
    *,
    source_sha: str,
    run_id: str,
    work_root: Path,
    output: Path,
    authority_base: str = fleet.DEFAULT_AUTHORITY_BASE,
    public_repo: str = DEFAULT_PUBLIC_REPO,
    public_branch: str = DEFAULT_PUBLIC_BRANCH,
    public_token: str = "",
    existing_snapshot: Callable[..., dict[str, Any] | None] = _existing_snapshot,
    fleet_materialize: Callable[..., dict[str, Any]] = fleet.materialize,
    fetch_vault_public_key: Callable[[str], dict[str, Any]] = publisher.fetch_vault_public_key,
    encrypt_snapshot: Callable[..., tuple[dict[str, Any], list[tuple[str, bytes]]]] = publisher.encrypt_snapshot,
    snapshot_publication_files: Callable[..., tuple[list[tuple[str, bytes]], bytes, str]] = publisher.snapshot_publication_files,
    publish_atomic: Callable[..., str] = publisher.publish_atomic,
) -> dict[str, Any]:
    source_sha = publisher._valid_sha40(source_sha)
    run_id = str(run_id or "").strip()
    if not run_id.isdigit():
        raise RuntimeError("run_id_rejected")

    existing = existing_snapshot(
        source_sha=source_sha,
        public_repo=public_repo,
        public_branch=public_branch,
    )
    if existing is not None:
        manifest = existing["manifest"]
        result = {
            "schema": RECEIPT_SCHEMA,
            "ok": True,
            "status": "already_published",
            "source_sha": source_sha,
            "source_ref": str(manifest.get("source_ref") or source_sha),
            "archive_sha256": str(manifest["archive_sha256"]),
            "archive_bytes": int(manifest["archive_bytes"]),
            "manifest_sha256": str(existing["manifest_sha256"]),
            "manifest_path": str(existing["manifest_path"]),
            "public_repository": public_repo,
            "public_branch": public_branch,
            "published_commit": None,
            "bootstrap_private_source_fetch_used": False,
            "runtime_private_repository_token_used": False,
            "fleet_private_source_credential_exposed": False,
            "public_plaintext_included": False,
            "live_execution_allowed": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result

    token = str(public_token or "").strip()
    if not token:
        raise RuntimeError("public_repository_write_token_required")

    work_root.mkdir(parents=True, exist_ok=True)
    archive_path = work_root / "private-source.tar.gz"
    materialization_path = work_root / "fleet-materialization.json"
    extracted = work_root / "fleet-extracted"

    fleet_result = fleet_materialize(
        source_sha=source_sha,
        run_id=run_id,
        destination=extracted,
        archive_output=archive_path,
        output=materialization_path,
        authority_base=authority_base,
    )
    if (
        fleet_result.get("ok") is not True
        or fleet_result.get("private_source_attestation_verified") is not True
        or fleet_result.get("runtime_private_repository_token_used") is not False
        or fleet_result.get("fleet_private_source_credential_exposed") is not False
        or fleet_result.get("public_plaintext_emitted") is not False
    ):
        raise RuntimeError("fleet_private_source_bootstrap_boundary_rejected")

    archive = archive_path.read_bytes()
    archive_sha = _sha256(archive)
    if archive_sha != str(fleet_result.get("source_archive_sha256") or ""):
        raise RuntimeError("fleet_private_source_bootstrap_digest_mismatch")
    if len(archive) != int(fleet_result.get("source_archive_bytes") or 0):
        raise RuntimeError("fleet_private_source_bootstrap_size_mismatch")

    key = fetch_vault_public_key(authority_base)
    manifest, chunks = encrypt_snapshot(
        archive,
        source_sha=source_sha,
        source_ref=source_sha,
        vault_public_key=key,
    )
    files, _, manifest_sha = snapshot_publication_files(manifest, chunks)
    published_commit = publish_atomic(
        repo=public_repo,
        branch=public_branch,
        token=token,
        files=files,
        source_sha=source_sha,
    )

    result = {
        "schema": RECEIPT_SCHEMA,
        "ok": True,
        "status": "published",
        "source_sha": source_sha,
        "source_ref": source_sha,
        "archive_sha256": manifest["archive_sha256"],
        "archive_bytes": int(manifest["archive_bytes"]),
        "manifest_sha256": manifest_sha,
        "manifest_path": f"source-vault/{source_sha}/manifest.json",
        "vault_key_id": manifest["key_id"],
        "public_repository": public_repo,
        "public_branch": public_branch,
        "published_commit": published_commit,
        "bootstrap_private_source_fetch_used": True,
        "runtime_private_repository_token_used": False,
        "fleet_private_source_credential_exposed": False,
        "public_plaintext_included": False,
        "live_execution_allowed": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--authority-base", default=fleet.DEFAULT_AUTHORITY_BASE)
    parser.add_argument("--public-repo", default=DEFAULT_PUBLIC_REPO)
    parser.add_argument("--public-branch", default=DEFAULT_PUBLIC_BRANCH)
    parser.add_argument("--token-env", default="GH_TOKEN")
    args = parser.parse_args()

    result = bootstrap(
        source_sha=args.source_sha,
        run_id=args.run_id,
        work_root=args.work_root,
        output=args.output,
        authority_base=args.authority_base,
        public_repo=args.public_repo,
        public_branch=args.public_branch,
        public_token=str(os.environ.get(args.token_env) or ""),
    )
    print(
        "MMIBKR_SOURCE_VAULT_BOOTSTRAP="
        + json.dumps(
            {
                "ok": result["ok"],
                "status": result["status"],
                "source_sha": result["source_sha"],
                "archive_sha256": result["archive_sha256"],
                "archive_bytes": result["archive_bytes"],
                "manifest_sha256": result["manifest_sha256"],
                "public_repository": result["public_repository"],
                "public_branch": result["public_branch"],
                "bootstrap_private_source_fetch_used": result[
                    "bootstrap_private_source_fetch_used"
                ],
                "runtime_private_repository_token_used": False,
                "fleet_private_source_credential_exposed": False,
                "public_plaintext_included": False,
                "live_execution_allowed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
