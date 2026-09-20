from __future__ import annotations

"""Consume one exact private MM-IBKR source archive through Fleet Authority.

The canonical public runtime authenticates to Fleet with GitHub OIDC. Fleet alone
holds the private GitHub read credential and streams the exact code-pinned archive.
The runtime hashes what it actually receives, safe-extracts it, and asks Fleet to
attest that same run/source/archive tuple for later hot-B1 relay.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

AUDIENCE = "mmibkr-fleet-authority"
ATTEST_SCHEMA = "mmibkr-fleet-private-source-attest-v1"
TRANSPORT = "fleet_authority_oidc_private_archive_stream"
DEFAULT_AUTHORITY_BASE = "https://fleet-authority.slenderiq.workers.dev"
MAX_ARCHIVE_BYTES = 150 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_FILES = 20000
STREAM_ID_RE = re.compile(r"^[0-9a-f-]{36}$")


def _valid_sha40(value: str) -> str:
    value = str(value or "").strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeError("exact_source_sha_required")
    return value


def _oidc_url(base: str) -> str:
    parsed = urlparse(base)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["audience"] = AUDIENCE
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(query),
            parsed.fragment,
        )
    )


def _oidc_token() -> str:
    url = str(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") or "")
    token = str(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") or "")
    if not url or not token:
        raise RuntimeError("github_oidc_environment_missing")
    req = Request(
        _oidc_url(url),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "User-Agent": "mmibkr-fleet-private-source-consumer-v1",
        },
    )
    with urlopen(req, timeout=20) as response:
        node = json.load(response)
    value = str(node.get("value") or "")
    if value.count(".") != 2:
        raise RuntimeError("github_oidc_token_invalid")
    return value


def _open_archive_stream(
    authority_base: str,
    source_sha: str,
    run_id: str,
    token: str,
):
    req = Request(
        authority_base.rstrip("/") + f"/v1/source-vault/private-archive/{source_sha}",
        method="GET",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/gzip",
            "X-MMIBKR-Caller-Run-Id": str(run_id),
            "User-Agent": "mmibkr-fleet-private-source-consumer-v1",
        },
    )
    try:
        return urlopen(req, timeout=60)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(
            f"fleet_private_source_stream_http_{exc.code}:{detail[:300]}"
        ) from exc


def _post_attestation(
    authority_base: str,
    run_id: str,
    token: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    raw = json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    req = Request(
        authority_base.rstrip("/") + "/v1/source-vault/private-archive/attest",
        data=raw,
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-MMIBKR-Caller-Run-Id": str(run_id),
            "User-Agent": "mmibkr-fleet-private-source-consumer-v1",
        },
    )
    try:
        with urlopen(req, timeout=30) as response:
            return json.load(response)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(
            f"fleet_private_source_attest_http_{exc.code}:{detail[:300]}"
        ) from exc


def _header(headers: Mapping[str, Any], name: str) -> str:
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _safe_extract_github_tar(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    target_root = (destination / "mm-ibkr").resolve()
    total = 0
    files = 0

    with tarfile.open(archive_path, mode="r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise RuntimeError("source_archive_empty")

        top_parts: set[str] = set()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise RuntimeError("source_archive_path_rejected")
            top_parts.add(path.parts[0])
            if member.issym() or member.islnk() or member.isdev():
                raise RuntimeError("source_archive_special_member_rejected")
        if len(top_parts) != 1:
            raise RuntimeError("source_archive_single_root_required")

        target_root.mkdir(parents=True, exist_ok=True)
        for member in members:
            path = Path(member.name)
            if len(path.parts) == 1:
                continue
            relative = Path(*path.parts[1:])
            target = (target_root / relative).resolve()
            if target != target_root and target_root not in target.parents:
                raise RuntimeError("source_archive_escape_rejected")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError("source_archive_member_type_rejected")
            files += 1
            total += int(member.size or 0)
            if files > MAX_FILES or total > MAX_EXTRACTED_BYTES:
                raise RuntimeError("source_archive_expansion_rejected")
            handle = tf.extractfile(member)
            if handle is None:
                raise RuntimeError("source_archive_member_unreadable")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as out:
                shutil.copyfileobj(handle, out, length=1024 * 1024)
            try:
                os.chmod(target, int(member.mode) & 0o777)
            except OSError:
                pass

    if files <= 0 or not (target_root / "Dockerfile.bot").is_file():
        raise RuntimeError("source_archive_runtime_root_incomplete")
    return target_root


def materialize(
    *,
    source_sha: str,
    run_id: str,
    destination: Path,
    archive_output: Path,
    output: Path,
    authority_base: str = DEFAULT_AUTHORITY_BASE,
    token_factory: Callable[[], str] = _oidc_token,
    open_stream: Callable[..., Any] = _open_archive_stream,
    attest_api: Callable[..., dict[str, Any]] = _post_attestation,
) -> dict[str, Any]:
    source_sha = _valid_sha40(source_sha)
    run_id = str(run_id or "").strip()
    if not run_id.isdigit():
        raise RuntimeError("run_id_rejected")

    token = token_factory()
    archive_output.parent.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256()
    archive_bytes = 0
    stream_id = ""
    expected_bytes = 0

    response = open_stream(authority_base, source_sha, run_id, token)
    try:
        headers = response.headers
        observed_sha = _header(headers, "x-mmibkr-source-sha").lower()
        stream_id = _header(headers, "x-mmibkr-source-stream-id")
        transport = _header(headers, "x-mmibkr-source-transport")
        token_exposed = _header(
            headers, "x-mmibkr-private-source-token-exposed"
        ).lower()
        expected_text = _header(headers, "x-mmibkr-source-archive-bytes")

        if observed_sha != source_sha:
            raise RuntimeError("fleet_private_source_sha_header_rejected")
        if not STREAM_ID_RE.fullmatch(stream_id):
            raise RuntimeError("fleet_private_source_stream_id_rejected")
        if transport != TRANSPORT:
            raise RuntimeError("fleet_private_source_transport_rejected")
        if token_exposed != "false":
            raise RuntimeError("fleet_private_source_token_boundary_rejected")
        if expected_text:
            expected_bytes = int(expected_text)
            if expected_bytes <= 0 or expected_bytes > MAX_ARCHIVE_BYTES:
                raise RuntimeError("fleet_private_source_expected_size_rejected")

        with archive_output.open("wb") as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                archive_bytes += len(chunk)
                if archive_bytes > MAX_ARCHIVE_BYTES:
                    raise RuntimeError("fleet_private_source_archive_size_rejected")
                digest.update(chunk)
                out.write(chunk)
    finally:
        try:
            response.close()
        except Exception:
            pass

    if archive_bytes <= 0:
        raise RuntimeError("fleet_private_source_archive_empty")
    if expected_bytes and archive_bytes != expected_bytes:
        raise RuntimeError("fleet_private_source_archive_size_mismatch")

    archive_sha = digest.hexdigest()

    attest = attest_api(
        authority_base,
        run_id,
        token_factory(),
        {
            "schema": ATTEST_SCHEMA,
            "source_sha": source_sha,
            "stream_id": stream_id,
            "archive_sha256": archive_sha,
            "archive_bytes": archive_bytes,
        },
    )
    if (
        attest.get("ok") is not True
        or attest.get("private_attestation_stored") is not True
        or str(attest.get("source_sha") or "").lower() != source_sha
        or str(attest.get("archive_sha256") or "").lower() != archive_sha
        or int(attest.get("archive_bytes") or 0) != archive_bytes
        or attest.get("source_transport") != TRANSPORT
    ):
        raise RuntimeError("fleet_private_source_attestation_rejected")

    source_root = _safe_extract_github_tar(archive_output, destination)
    try:
        os.chmod(archive_output, 0o600)
    except OSError:
        pass

    result = {
        "schema": "mmibkr.attested_source_materialization.v3",
        "ok": True,
        "source_ref": source_sha,
        "source_sha": source_sha,
        "source_archive_sha256": archive_sha,
        "source_archive_bytes": archive_bytes,
        "source_archive_path": str(archive_output),
        "source_root": str(source_root),
        "source_transport": TRANSPORT,
        "fleet_authority_base": authority_base,
        "caller_run_id": run_id,
        "source_stream_id": stream_id,
        "private_source_attestation_verified": True,
        "runtime_private_repository_token_used": False,
        "fleet_private_source_credential_used": True,
        "fleet_private_source_credential_exposed": False,
        "broker_credentials_used": False,
        "public_plaintext_emitted": False,
        "live_execution_allowed": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(output, 0o600)
    except OSError:
        pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--archive-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--authority-base", default=DEFAULT_AUTHORITY_BASE)
    args = parser.parse_args()

    result = materialize(
        source_sha=args.source_sha,
        run_id=str(args.run_id),
        destination=args.destination,
        archive_output=args.archive_output,
        output=args.output,
        authority_base=args.authority_base,
    )
    print(
        "MMIBKR_FLEET_PRIVATE_SOURCE_MATERIALIZED="
        + json.dumps(
            {
                "ok": True,
                "source_sha": result["source_sha"],
                "source_archive_sha256": result["source_archive_sha256"],
                "source_archive_bytes": result["source_archive_bytes"],
                "source_transport": result["source_transport"],
                "private_source_attestation_verified": True,
                "runtime_private_repository_token_used": False,
                "fleet_private_source_credential_exposed": False,
                "live_execution_allowed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
