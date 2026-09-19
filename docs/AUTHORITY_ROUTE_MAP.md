# Authority and Route Map

This document is normative for MM-IBKR cloud/runtime work.

## Canonical authorities

### Private strategy/runtime authority — `XoticHaze/mm-IBKR`

Owns:

- StrategySpec and strategy implementation
- selected-runtime universe and runtime identity
- signal-history vs execution-contract selection
- futures roll policy and contract-month choice
- natural evaluation and candidate materialization
- quantity/sizing
- DCA/exit intent
- paper-submit eligibility
- live-submit eligibility

Private MM may ask public infrastructure to qualify or execute an exact request. Public infrastructure must not choose these values.

### Public runtime control plane — `XoticHaze/mm-ibkr-runtime`

Owns:

- bounded/perpetual cloud owner
- bar-boundary scheduling
- encrypted private-source consumer
- ephemeral private runtime launch
- sanitized market-data cache/checkpoint lifecycle
- sanitized terminal-boundary idempotency continuity
- source-attestation relay client
- watchdog/self-handoff
- sanitized health/session receipts
- operator/agent runbooks for runtime invocation

Does **not** own:

- strategies
- contract selection
- order quantity
- paper/live policy
- broker credentials
- IBKR session authority

### Public broker/compute plane — `XoticHaze/research-compute-public-`

Owns:

- canonical B1 workflow: `.github/workflows/ibkr-cloudflare-readonly-b1-r1.yml`
- Fleet Authority implementation/deployment
- broker credential sealing/unsealing
- broker session lifecycle and warm-state handling
- exact-contract qualification/read transport
- same-hot B1 paper-execute transport
- generic hardened public compute primitives

B1 is broker-bearing but strategy-blind.

### Fleet Authority

Fleet Authority is the authenticated bridge between repositories.

It must authenticate GitHub-hosted workflows with OIDC and pin:

- repository
- ref
- workflow_ref
- run_id
- event type

It may hold encrypted/ciphertext rendezvous state and broker-sealed authority. It must not become strategy, contract-selection, sizing, or live-execution authority.

## Allowed route graph

```text
mm-IBKR (private)
  ├─ encrypted source producer ──> Fleet source exchange
  │                                  │
  │                                  v
  │                           mm-ibkr-runtime
  │                                  │
  ├─ private selected-runtime intent │
  │                                  ├─ read/qualification request ──> Fleet broker request ──> B1
  │                                  │
  │                                  └─ genuine paper command
  │                                         │
  │                                         └─ attested source relay ──> Fleet ──> same-hot B1
  │
  └─ remains final strategy/execution-policy authority
```

## Forbidden shortcuts

The following are route violations:

- `mm-ibkr-runtime` directly authenticating to IBKR.
- `mm-ibkr-runtime` assuming its repository `GITHUB_TOKEN` can control `research-compute-public-`.
- placing a private-repository PAT in the public runtime.
- publishing private MM source, StrategySpecs, candidate packets, account state, positions, orders, or broker credentials.
- B1 choosing a futures month, strategy, quantity, DCA intent, or entry/exit action.
- Fleet Authority manufacturing candidate/order intent.
- any public component setting or broadening live authority.
- moving B1 to this repository as part of an unrelated runtime change.

## Futures authority

Private MM independently owns:

- execution-contract roll
- signal-history roll

Those authorities may temporarily resolve to different contracts. B1 only broker-qualifies exact private-MM requests.

## Source provenance chain

The accepted source chain is:

1. private MM workflow authenticates to Fleet Authority with GitHub OIDC;
2. private workflow archives its authenticated checkout/HEAD;
3. archive is encrypted to a one-run public-runtime X25519 recipient;
4. Fleet stores ciphertext and a private-producer attestation for exact source SHA + archive SHA-256 + byte count;
5. public runtime decrypts only in ephemeral runner storage;
6. if a genuine paper candidate is produced, the exact already-attested archive is re-encrypted to the hot B1 recipient;
7. Fleet refuses the B1 relay unless the source tuple matches the private attestation;
8. B1 decrypts locally, builds the exact private runtime, executes the canonical private submit path, returns an encrypted proof, and destroys private material.

No private GitHub bearer token is part of this route.

## Current cutover state

Until finite acceptance proves the full source-attested B1 route:

- canonical B1 remains on `research-compute-public-/ibkr-b1-authority-v1`;
- private cloud changes remain on the MM feature branch;
- this repo may contain the new runtime control-plane code, but perpetual self-handoff must not be treated as accepted production authority.

Cutover requires an executed green finite acceptance, not only CI/contracts.
