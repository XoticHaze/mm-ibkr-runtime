from __future__ import annotations

"""Publish one exact MM-IBKR source snapshot as public ciphertext.

The private source tree is read only from a local/mounted git checkout. The GitHub
credential is used only to write ciphertext + a public manifest to the public
snapshot branch; it is never used to fetch private source.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = "mmibkr-source-vault-snapshot-v1"
PUBLIC_KEY_SCHEMA = "mmibkr-source-vault-public-key-v1"
DEFAULT_AUTHORITY_BASE = "https://fleet-authority.slenderiq.workers.dev"
DEFAULT_PUBLIC_REPO = "XoticHaze/research-compute-public-"
DEFAULT_PUBLIC_BRANCH = "mmibkr-source-vault"
DEFAULT_ROOT = "source-vault"
CHUNK_CHARS = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 150 * 1024 * 1024


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json_bytes(node: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(node), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _valid_sha40(value: str) -> str:
    value = str(value or "").strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError("exact_source_sha_required")
    return value


def _git(repo_root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root, text=True).strip()


def verify_local_source(repo_root: Path, source_sha: str) -> str:
    source_sha = _valid_sha40(source_sha)
    if not (repo_root / ".git").exists():
        raise RuntimeError("local_private_git_checkout_required")
    resolved = _git(repo_root, "rev-parse", f"{source_sha}^{{commit}}").lower()
    if resolved != source_sha:
        raise RuntimeError("local_source_sha_resolution_mismatch")
    return resolved


def archive_source(repo_root: Path, source_sha: str) -> bytes:
    source_sha = verify_local_source(repo_root, source_sha)
    proc = subprocess.run(
        ["git", "archive", "--format=tar.gz", "--prefix=mm-ibkr/", source_sha],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("source_git_archive_failed:" + proc.stderr.decode("utf-8", "replace")[:300])
    raw = bytes(proc.stdout)
    if not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise RuntimeError("source_archive_size_rejected")
    return raw


def _get_json(url: str) -> dict[str, Any]:
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "mmibkr-source-vault-publisher-v1"})
    with urlopen(req, timeout=30) as response:
        return json.load(response)


def fetch_vault_public_key(authority_base: str) -> dict[str, Any]:
    node = _get_json(authority_base.rstrip("/") + "/v1/source-vault/public-key")
    if node.get("ok") is not True or node.get("schema") != PUBLIC_KEY_SCHEMA:
        raise RuntimeError("vault_public_key_contract_rejected")
    if node.get("algorithm") != "RSA-OAEP-256" or node.get("private_key_exported") is not False:
        raise RuntimeError("vault_public_key_algorithm_rejected")
    key_id = str(node.get("key_id") or "")
    jwk = node.get("public_jwk")
    if not key_id.startswith("sha256:") or not isinstance(jwk, Mapping):
        raise RuntimeError("vault_public_key_identity_rejected")
    return dict(node)


def _b64url_uint(value: str) -> int:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return int.from_bytes(raw, "big")


def _rsa_public_key(jwk: Mapping[str, Any]):
    if jwk.get("kty") != "RSA" or not jwk.get("n") or not jwk.get("e"):
        raise RuntimeError("vault_rsa_jwk_rejected")
    return rsa.RSAPublicNumbers(_b64url_uint(str(jwk["e"])), _b64url_uint(str(jwk["n"]))).public_key()


def encrypt_snapshot(
    archive: bytes,
    *,
    source_sha: str,
    source_ref: str,
    vault_public_key: Mapping[str, Any],
    chunk_chars: int = CHUNK_CHARS,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    source_sha = _valid_sha40(source_sha)
    if not archive or len(archive) > MAX_ARCHIVE_BYTES:
        raise RuntimeError("source_archive_size_rejected")
    if chunk_chars < 1024 or chunk_chars > 8 * 1024 * 1024:
        raise ValueError("chunk_chars_rejected")

    key_id = str(vault_public_key.get("key_id") or "")
    jwk = vault_public_key.get("public_jwk")
    if not isinstance(jwk, Mapping):
        raise RuntimeError("vault_public_jwk_missing")
    public_key = _rsa_public_key(jwk)

    archive_sha = _sha256(archive)
    master_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad_node = {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "source_ref": str(source_ref),
        "archive_sha256": archive_sha,
        "archive_bytes": len(archive),
        "key_id": key_id,
    }
    aad = _canonical_json_bytes(aad_node)
    ciphertext = AESGCM(master_key).encrypt(nonce, archive, aad)
    sealed_key = public_key.encrypt(
        master_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    encoded = base64.b64encode(ciphertext).decode("ascii")

    root = f"{DEFAULT_ROOT}/{source_sha}"
    chunk_files: list[tuple[str, bytes]] = []
    descriptors: list[dict[str, Any]] = []
    for index, start in enumerate(range(0, len(encoded), chunk_chars)):
        text = encoded[start:start + chunk_chars].encode("ascii")
        path = f"{root}/ciphertext-{index:04d}.txt"
        chunk_files.append((path, text))
        descriptors.append({"index": index, "path": path, "chars": len(text), "sha256": _sha256(text)})
    if not descriptors or len(descriptors) > 4096:
        raise RuntimeError("snapshot_chunk_count_rejected")

    manifest = {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "source_ref": str(source_ref),
        "archive_sha256": archive_sha,
        "archive_bytes": len(archive),
        "cipher": "AES-256-GCM",
        "aad_b64": base64.b64encode(aad).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_sha256": _sha256(ciphertext),
        "ciphertext_bytes": len(ciphertext),
        "encoding": "base64",
        "key_wrap": "RSA-OAEP-256",
        "key_id": key_id,
        "sealed_key_b64": base64.b64encode(sealed_key).decode("ascii"),
        "chunks": descriptors,
        "public_plaintext_included": False,
        "private_repository_token_used": False,
        "broker_credentials_used": False,
        "live_execution_authority": False,
    }
    return manifest, chunk_files


def snapshot_publication_files(manifest: Mapping[str, Any], chunks: list[tuple[str, bytes]]) -> tuple[list[tuple[str, bytes]], bytes, str]:
    manifest_bytes = _canonical_json_bytes(manifest)
    manifest_sha = _sha256(manifest_bytes)
    source_sha = _valid_sha40(str(manifest.get("source_sha") or ""))
    manifest_path = f"{DEFAULT_ROOT}/{source_sha}/manifest.json"
    return [*chunks, (manifest_path, manifest_bytes)], manifest_bytes, manifest_sha


def _gh_api(method: str, url: str, token: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(dict(body), separators=(",", ":")).encode("utf-8")
    req = Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "mmibkr-source-vault-publisher-v1",
        },
    )
    try:
        with urlopen(req, timeout=45) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"github_api_{method}_{exc.code}:{detail[:500]}") from exc


def publish_atomic(
    *,
    repo: str,
    branch: str,
    token: str,
    files: list[tuple[str, bytes]],
    source_sha: str,
) -> str:
    if not token:
        raise RuntimeError("public_repository_write_token_required")
    base = f"https://api.github.com/repos/{repo}"
    ref = _gh_api("GET", f"{base}/git/ref/heads/{branch}", token)
    parent = str((ref.get("object") or {}).get("sha") or "")
    if len(parent) != 40:
        raise RuntimeError("snapshot_branch_parent_missing")
    parent_commit = _gh_api("GET", f"{base}/git/commits/{parent}", token)

    manifest_url = f"{base}/contents/{DEFAULT_ROOT}/{source_sha}/manifest.json?ref={branch}"
    try:
        _gh_api("GET", manifest_url, token)
    except RuntimeError as exc:
        if "github_api_GET_404" not in str(exc):
            raise
    else:
        raise RuntimeError("source_snapshot_already_published")

    entries = []
    for path, raw in files:
        blob = _gh_api(
            "POST",
            f"{base}/git/blobs",
            token,
            {"content": base64.b64encode(raw).decode("ascii"), "encoding": "base64"},
        )
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    tree = _gh_api(
        "POST",
        f"{base}/git/trees",
        token,
        {"base_tree": parent_commit["tree"]["sha"], "tree": entries},
    )
    commit = _gh_api(
        "POST",
        f"{base}/git/commits",
        token,
        {
            "message": f"source-vault: publish encrypted MM snapshot {source_sha}",
            "tree": tree["sha"],
            "parents": [parent],
        },
    )
    new_sha = str(commit.get("sha") or "")
    _gh_api("PATCH", f"{base}/git/refs/heads/{branch}", token, {"sha": new_sha, "force": False})
    return new_sha


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-ref", default="local-exact-sha")
    parser.add_argument("--authority-base", default=DEFAULT_AUTHORITY_BASE)
    parser.add_argument("--public-repo", default=DEFAULT_PUBLIC_REPO)
    parser.add_argument("--public-branch", default=DEFAULT_PUBLIC_BRANCH)
    parser.add_argument("--token-env", default="GH_TOKEN")
    parser.add_argument("--receipt", type=Path, default=Path("source-vault-publication-receipt.json"))
    args = parser.parse_args()

    source_sha = verify_local_source(args.repo_root.resolve(), args.source_sha)
    public_key = fetch_vault_public_key(args.authority_base)
    archive = archive_source(args.repo_root.resolve(), source_sha)
    manifest, chunks = encrypt_snapshot(
        archive,
        source_sha=source_sha,
        source_ref=args.source_ref,
        vault_public_key=public_key,
    )
    files, _, manifest_sha = snapshot_publication_files(manifest, chunks)
    token = str(os.environ.get(args.token_env) or "").strip()
    published_commit = publish_atomic(
        repo=args.public_repo,
        branch=args.public_branch,
        token=token,
        files=files,
        source_sha=source_sha,
    )
    receipt = {
        "schema": "mmibkr-source-vault-publication-receipt-v1",
        "ok": True,
        "source_sha": source_sha,
        "source_ref": args.source_ref,
        "archive_sha256": manifest["archive_sha256"],
        "archive_bytes": manifest["archive_bytes"],
        "manifest_sha256": manifest_sha,
        "vault_key_id": manifest["key_id"],
        "public_repository": args.public_repo,
        "public_branch": args.public_branch,
        "manifest_path": f"{DEFAULT_ROOT}/{source_sha}/manifest.json",
        "published_commit": published_commit,
        "public_plaintext_included": False,
        "private_repository_token_used": False,
        "broker_credentials_used": False,
        "live_execution_authority": False,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("MMIBKR_SOURCE_VAULT_PUBLICATION=" + json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
