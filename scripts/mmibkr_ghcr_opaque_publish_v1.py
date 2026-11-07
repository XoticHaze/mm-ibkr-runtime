#!/usr/bin/env python3
"""Image-only GHCR extension to the EXISTING public-runtime publisher.

The public fire/request/log/receipt never contains a private source ref.
Fleet OIDC fetches a PRIVATE owner-approved candidate and exact private archive.
The existing GHCR PAT pushes only to the already-private canonical package.
No orders, Gateway access, root approval, or running Pi mutation.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# Script invocation sets sys.path[0] to /repo/scripts, not /repo.
# Restore the reviewed public runtime package root before importing scripts.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.mmibkr_fleet_private_source_consumer_v1 import (
    _oidc_token, materialize,
)

FLEET = "https://fleet-authority.slenderiq.workers.dev"
REGISTRY = "ghcr.io/xotichaze/mmibkr-pi-canonical-private-20261030"
PACKAGE_API = "https://api.github.com/users/XoticHaze/packages/container/mmibkr-pi-canonical-private-20261030"
SHA = re.compile(r"^[a-f0-9]{40}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
NATIVE = (
    "test_pi_root_external_baseline_owner_epoch_20261106",
    "test_pi_canonical_live_fill_commit_bridge_20261106",
    "test_pi_canonical_pending_live_fill_recovery_20261106",
    "test_pi_canonical_account_margin_cap_bridge_20261106",
    "test_pi_canonical_margin_call_binding_20261106",
    "test_selected_runtime_live_execution_ledger_v1",
)
# Execute the *actual* native unittest suite and reject 0 collected tests,
# import-failure pseudo-tests, failed cases or a partial run. Output is local.
NATIVE_RUNNER = r"""
import pathlib,sys,unittest
name=sys.argv[1]
allowed=set(__import__('json').loads(sys.argv[2]))
if name not in allowed: sys.exit(79)
root=pathlib.Path('/app')
test=root/'tests'/(name+'.py')
if not test.is_file() or test.stat().st_size<1:sys.exit(80)
sys.path.insert(0,str(root))
suite=unittest.TestLoader().discover(start_dir=str(root/'tests'),
                                    pattern=name+'.py',top_level_dir=str(root))
count=suite.countTestCases()
if count<1:sys.exit(81)
result=unittest.TextTestRunner(verbosity=0).run(suite)
if not result.wasSuccessful() or result.testsRun!=count:sys.exit(82)
print('CCPI_COUNT='+str(count))
"""


class Held(Exception):
    def __init__(self, stage: str):
        self.stage = stage
        super().__init__(stage)


def fixed_run(argv: list[str], *, stdin: str | None = None, timeout: int = 120):
    try:
        p = subprocess.run(argv, text=True, input=stdin,
                           capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Held("HOST_EXECUTION")
    if p.returncode:
        raise Held("NATIVE_OR_REGISTRY_COMMAND")
    return p.stdout


def existing_private_package(pat: str) -> None:
    req = Request(PACKAGE_API, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + pat,
        "User-Agent": "mmibkr-opaque-ghcr-private-package-v1",
    })
    try:
        with urlopen(req, timeout=25) as response:
            obj = json.load(response)
    except Exception:
        raise Held("PRIVATE_PACKAGE_READ")
    if obj.get("name") != REGISTRY.rsplit("/", 1)[1] or obj.get("visibility") != "private":
        raise Held("PRIVATE_PACKAGE_VISIBILITY")


def private_candidate(run_id: str):
    req = Request(FLEET + "/v1/source-vault/pi-image-candidate",
                  method="POST", data=b"{}", headers={
                      "Authorization": "Bearer " + _oidc_token(),
                      "x-mmibkr-caller-run-id": run_id,
                      "content-type": "application/json",
                      "cache-control": "no-store",
                  })
    try:
        with urlopen(req, timeout=45) as response:
            obj = json.load(response)
    except HTTPError as exc:
        # Only the HTTP status code is logged, never response bodies/URLs/SHA.
        if exc.code in {401, 403, 404, 429, 500, 502, 503}:
            raise Held("PRIVATE_CANDIDATE_HTTP_" + str(exc.code))
        raise Held("PRIVATE_CANDIDATE_HTTP_OTHER")
    except Exception:
        raise Held("PRIVATE_CANDIDATE_TRANSPORT")
    if (type(obj) is not dict
            or obj.get("schema") != "mmibkr.pi_ghcr_opaque_candidate.v1"
            or obj.get("broker_authorized") is not False
            or obj.get("publication_only") is not True
            or not SHA.fullmatch(str(obj.get("source_sha") or ""))
            or tuple(obj.get("native_brokerless_suites") or ()) != NATIVE):
        raise Held("CANDIDATE_POLICY")
    return str(obj["source_sha"])


def publish() -> int:
    if os.environ.get("GITHUB_EVENT_NAME") != "push":
        raise Held("TRIGGER_NOT_PUSH")
    run_id = str(os.environ.get("GITHUB_RUN_ID") or "")
    if not run_id.isdecimal() or not 8 <= len(run_id) <= 20:
        raise Held("RUN_ID")
    pat = os.environ.get("MMIBKR_GHCR_PRIVATE_PUSH_PAT") or ""
    if not pat or len(pat) > 512 or any(c.isspace() for c in pat):
        raise Held("EXISTING_PUBLISHER_PAT_MISSING")
    if os.environ.get("RUNNER_ARCH") != "ARM64":
        raise Held("NOT_NATIVE_ARM64")
    with tempfile.TemporaryDirectory(prefix="mm-opaque-ghcr-", dir=os.environ.get("RUNNER_TEMP") or "/tmp") as td:
        scratch = Path(td)
        os.chmod(scratch, 0o700)
        src = private_candidate(run_id)
        # This is the only source identity: fetched inside the protected job,
        # never in public Git history, workflow inputs, stdout or receipts.
        try:
            with contextlib.redirect_stdout(open(os.devnull, "w", encoding="utf-8")):
                attested = materialize(
                    source_sha=src, run_id=run_id,
                    destination=scratch / "source",
                    archive_output=scratch / "private.tar.gz",
                    output=scratch / "source-attestation.json",
                    authority_base=FLEET,
                )
        except Exception:
            raise Held("SOURCE_VAULT_MATERIALIZATION")
        if (attested.get("ok") is not True
                or attested.get("private_source_attestation_verified") is not True
                or attested.get("source_sha") != src
                or attested.get("runtime_private_repository_token_used") is not False
                or attested.get("fleet_private_source_credential_exposed") is not False):
            raise Held("SOURCE_ATTESTATION")

        root = Path(attested["source_root"]).resolve()
        if not root.is_dir() or not (root / "deploy/pi-bot/Dockerfile").is_file():
            raise Held("SOURCE_DOCKERFILE")
        if not (root / "deploy/pi-bot/Dockerfile.dockerignore").is_file():
            raise Held("SOURCE_CONTEXT_GUARD")

        local_tag = "mmibkr-private-pi-opaque:" + run_id
        fixed_run([
            "docker", "build", "--platform", "linux/arm64",
            "--build-arg", "MMIBKR_SELECTED_SOURCE_SHA=" + src,
            "--file", str(root / "deploy/pi-bot/Dockerfile"),
            "--tag", local_tag, str(root),
        ], timeout=1600)
        observed = fixed_run(["docker", "image", "inspect", local_tag,
            "--format", '{{.Architecture}} {{index .Config.Labels "org.opencontainers.image.revision"}}'])
        if observed.strip() != "arm64 " + src:
            raise Held("IMAGE_IDENTITY")

        tests_run = 0
        for suite in NATIVE:
            out = fixed_run([
                "docker", "run", "--rm", "--pull", "never", "--network", "none",
                "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "--cpus", "0.75", "--memory", "768m", "--pids-limit", "96",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--mount", "type=bind,src=" + str(root) + ",dst=/app,readonly",
                "--workdir", "/app", "--entrypoint", "python", local_tag,
                "-c", NATIVE_RUNNER, suite, json.dumps(list(NATIVE)),
            ], timeout=110)
            found = re.search(r"CCPI_COUNT=(\d+)", out)
            if not found or int(found.group(1)) < 1:
                raise Held("NATIVE_ZERO_TESTS")
            tests_run += int(found.group(1))
        if tests_run < len(NATIVE):
            raise Held("NATIVE_TEST_COUNT")
        print("PI_GHCR_BROKERLESS_NATIVE_ACCEPTANCE=PASS")
        print("PI_GHCR_BROKERLESS_TESTS_COLLECTED=" + str(tests_run), flush=True)

        existing_private_package(pat)
        docker_config = scratch / "docker-auth"
        docker_config.mkdir(mode=0o700)
        env = dict(os.environ, DOCKER_CONFIG=str(docker_config))
        # Docker login/logout are sanitized; the temporary config is scrubbed.
        try:
            p = subprocess.run(
                ["docker", "login", "ghcr.io", "--username", "XoticHaze", "--password-stdin"],
                input=pat + "\n", capture_output=True, text=True, env=env, timeout=40,
            )
            if p.returncode:
                raise Held("GHCR_AUTHENTICATION")
            target = REGISTRY + ":pi-" + src[:12]
            fixed_run(["docker", "tag", local_tag, target], timeout=20)
            result = subprocess.run(["docker", "push", target], capture_output=True,
                                    text=True, env=env, timeout=900)
            if result.returncode:
                err = (result.stderr + result.stdout).lower()
                if "denied" in err or "unauthorized" in err or "permission" in err:
                    raise Held("GHCR_PACKAGE_WRITE_DENIED")
                raise Held("GHCR_PUSH")
            digest_matches = re.findall(r"digest: (sha256:[0-9a-f]{64})", result.stdout + result.stderr)
            if not digest_matches or not DIGEST.fullmatch(digest_matches[-1]):
                raise Held("GHCR_DIGEST_MISSING")
            immutable = REGISTRY + "@" + digest_matches[-1]
            subprocess.run(["docker", "pull", immutable], env=env, text=True,
                           capture_output=True, timeout=600, check=True)
            actual = fixed_run(["docker", "image", "inspect", immutable,
                "--format", '{{.Architecture}} {{index .Config.Labels "org.opencontainers.image.revision"}}'])
            if actual.strip() != "arm64 " + src:
                raise Held("GHCR_DIGEST_IDENTITY")
            existing_private_package(pat)
        except Held:
            raise
        except Exception:
            raise Held("GHCR_PULL_BACK")
        finally:
            subprocess.run(["docker", "logout", "ghcr.io"], env=env,
                           capture_output=True, timeout=25, check=False)

        # The immutable source and digest remain within private GHCR and
        # transient runner memory; no values are published to public logs.
        print("PI_GHCR_PRIVATE_IMAGE_PUBLISHED=PASS", flush=True)
        print("PI_GHCR_PRIVATE_DIGEST_READBACK=PASS", flush=True)
        print("PI_GHCR_PUBLISHER_CREDENTIAL_REUSED=YES", flush=True)
        print("PI_GHCR_PUBLIC_PRIVATE_SHA_OR_DIGEST=NONE", flush=True)
        print("PI_GHCR_BROKER_OR_PI_MUTATIONS=NONE", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(publish())
    except Held as exc:
        print("PI_GHCR_PUBLISH_STATUS=HELD")
        print("PI_GHCR_HELD_STAGE=" + exc.stage)
        sys.exit(1)
    except BaseException:
        # Do not allow upstream GitHub/Docker traceback paths to disclose source.
        print("PI_GHCR_PUBLISH_STATUS=HELD")
        print("PI_GHCR_HELD_STAGE=INTERNAL")
        sys.exit(1)
