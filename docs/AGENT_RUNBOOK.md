# Agent Runbook

Use this runbook for MM-IBKR public runtime work.

## Lane ownership

- Private MM change → `XoticHaze/mm-IBKR`
- Runtime owner/scheduler/checkpoint/watchdog/source consumer → `XoticHaze/mm-ibkr-runtime`
- B1/Fleet/broker credential/IBKR session → `XoticHaze/research-compute-public-`

## Runtime invariants

- live trading disabled
- no synthetic/fabricated candidate
- private MM owns strategy/contract/quantity/paper authority
- B1 owns broker access only
- Fleet authenticates cross-plane capability exchange
- canonical source ingress is hostless and exact-SHA
- runtime never receives the private GitHub source credential
- private-repository Actions admission is not a source-ingress dependency
- public persisted state remains sanitized
- checkpoint loss is recoverable by canonical self-heal
- terminal boundaries remain idempotent across sessions

## Source transport

### Canonical startup ingress

`fleet_authority_oidc_private_archive_stream`

1. exact private source SHA is code-approved in Fleet;
2. canonical runtime authenticates to Fleet with pinned GitHub OIDC;
3. Fleet uses `MMIBKR_PRIVATE_SOURCE_TOKEN` only inside Cloudflare to read the exact GitHub tarball;
4. Fleet streams the archive to the admitted runtime and never exposes that credential;
5. runtime hashes the exact received archive and returns source SHA + stream ID + archive SHA-256 + byte count;
6. Fleet stores the same-source attestation used by the later B1 relay;
7. runtime safe-extracts, builds `Dockerfile.bot`, and runs private contracts.

The Cloudflare secret must be a narrowly scoped read-only GitHub credential for `XoticHaze/mm-IBKR` Contents.

### Optional encrypted snapshot cache

The encrypted source snapshot vault may be used later to reduce repeated source fetches. It is an optimization only; do not make host/local-file publication a startup dependency again.

### Hot B1 relay

The one-run X25519 source exchange is only for a genuine route-ready candidate and must relay the same Fleet-attested source.

## Finite acceptance

1. verify Fleet private-source authority is configured;
2. materialize the code-approved exact private SHA through Fleet;
3. verify runtime used no private-repo credential and Fleet did not expose its credential;
4. verify archive SHA-256/bytes and Fleet attestation;
5. build `Dockerfile.bot`;
6. run private runtime contracts;
7. restore/self-heal sanitized state;
8. run futures roll maintenance;
9. reach canonical B1 read/evaluation boundary;
10. no candidate → close cleanly;
11. genuine candidate → same-source X25519 hot relay and canonical paper command only;
12. save sanitized continuity state;
13. destroy private source/runtime material.

Do not force a trade.

## Failure taxonomy

Do not report “public compute unavailable.” Name the exact failed binding:

- Fleet private-source secret missing/invalid
- exact source SHA not code-approved
- GitHub private tarball fetch
- runtime OIDC admission
- streamed archive integrity/size
- same-run source attestation
- archive extraction/`Dockerfile.bot`
- private contract suite
- broker capability/B1 admission/session
- historical read
- hot X25519 relay
- encrypted proof return
- checkpoint handoff

## Do not use

- host/local machine as a required source path
- direct private GitHub source token in public runtime
- private Actions as source-ingress authority
- direct IBKR credentials in runtime repo
- public contract/month selection
- compatibility routes after canonical replacement is proven
