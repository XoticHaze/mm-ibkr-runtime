# Agent Runbook

Use this runbook for MM-IBKR public runtime work.

## Before changing anything

Confirm the lane:

- **Private MM change** → `XoticHaze/mm-IBKR`
- **Runtime owner/scheduler/checkpoint/watchdog change** → `XoticHaze/mm-ibkr-runtime`
- **B1/Fleet/broker credential/IBKR session change** → `XoticHaze/research-compute-public-`

If a proposed change crosses these boundaries, stop and state the exact cross-plane contract being changed.

## Runtime invariants

- live trading disabled
- no synthetic/fabricated candidate
- private MM owns strategy/contract/quantity/paper authority
- B1 owns broker access only
- Fleet authenticates cross-repo capability exchange
- source must be exact-SHA and private-producer-attested
- public persisted state must remain sanitized
- checkpoint loss must be recoverable by canonical historical self-heal
- duplicate terminal boundaries must remain idempotent across sessions

## On-demand runtime acceptance

A finite acceptance must always run before enabling or changing perpetual self-handoff.

Acceptance sequence:

1. materialize one exact private MM SHA through Fleet source exchange;
2. verify source archive SHA-256/private-producer identity;
3. build using `Dockerfile.bot`;
4. run the private runtime contract suite;
5. restore sanitized checkpoint if present, otherwise allow canonical cold self-heal;
6. run futures roll maintenance;
7. open canonical B1 boundary through the Fleet broker-capability route;
8. ingest exact returned history/quotes;
9. run private natural evaluation;
10. if **no genuine candidate**, close/expire the boundary without broker order action;
11. if a genuine route-ready paper candidate exists, relay the **same attested source archive** to that hot B1 run and execute only the private canonical paper command;
12. save sanitized checkpoint/session receipt;
13. destroy private source/runtime material.

Do not force a trade to prove the route.

## Perpetual owner

Only after finite acceptance is green:

- enable bounded session self-handoff;
- enable no-owner watchdog;
- preserve sanitized checkpoint + terminal-boundary continuity;
- keep cold-start self-heal as fallback;
- keep futures roll maintenance at session start;
- alert/fail closed after repeated transport/invariant failures.

## Source or broker route failure

Do not report "public compute unavailable."

Identify the exact failed binding:

- source producer OIDC
- Fleet source exchange
- source attestation
- runtime consumer/decrypt
- broker request capability
- B1 OIDC admission
- B1 session/auth
- historical read
- hot execution relay
- encrypted proof return
- checkpoint handoff

Then repair that binding or switch to another already-hardened public encrypted path.

## Do not use

- direct private GitHub source PATs in public runtime
- direct IBKR credentials in this repo
- root `Dockerfile` assumption for MM-IBKR; canonical bot image uses `Dockerfile.bot`
- public contract/month selection
- compatibility routes after the canonical replacement is proven
