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
- encrypted exact-source snapshot consumer
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
- reusable exact-SHA encrypted source snapshot vault
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

It may hold encrypted/ciphertext rendezvous state, code-pinned source-snapshot approvals, and broker-sealed authority. It must not become strategy, contract-selection, sizing, or live-execution authority.

## Allowed route graph

```text
mm-IBKR (private authority)
  |
  | exact source SHA
  v
authorized file-capable encrypted-snapshot producer
  |
  | ciphertext + source SHA + manifest SHA-256
  v
Fleet source snapshot vault
  |
  | runtime OIDC unwrap
  v
mm-ibkr-runtime
  |
  | private natural evaluation
  |
  +-- no genuine candidate --------------------------> close boundary
  |
  +-- genuine route-ready paper candidate
         |
         | same already-attested source
         v
     one-run X25519 Fleet source exchange
         |
         v
research-compute-public- / canonical B1
         |
         v
      IBKR paper
```

The source snapshot vault and the one-run X25519 source exchange are deliberately different contracts:

- **Snapshot vault:** canonical reusable private-source ingress into the public runtime. It must not require private-repository Actions admission.
- **X25519 source exchange:** ephemeral same-source relay from the runtime to hot B1 after a genuine candidate exists. It is not the canonical private-source producer path.

## Forbidden shortcuts

The following are route violations:

- `mm-ibkr-runtime` directly authenticating to IBKR.
- `mm-ibkr-runtime` assuming its repository `GITHUB_TOKEN` can control `research-compute-public-`.
- placing a private-repository PAT in the public runtime.
- treating the old private-Actions one-shot source producer as canonical source ingress.
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

## Canonical source provenance chain

The accepted reusable source-ingress chain is:

1. private MM authority identifies the exact source SHA;
2. a file-capable authorized producer receives the exact materialized source payload without making private Actions admission a dependency;
3. the producer encrypts the exact snapshot against the Fleet source-vault public key;
4. only ciphertext plus exact source SHA, snapshot manifest, manifest SHA-256, and sealed key are publicly persisted;
5. Fleet code-pins the exact source SHA + manifest SHA-256 approval;
6. `mm-ibkr-runtime` authenticates with its pinned GitHub OIDC identity and requests source-vault unwrap;
7. plaintext exists only in ephemeral admitted runner storage and is checked against the exact source/archive digests;
8. the runtime builds `Dockerfile.bot`, runs the private contract suite, restores/self-heals sanitized state, and performs natural evaluation;
9. if no genuine route-ready paper candidate exists, the boundary closes without broker action;
10. if a genuine route-ready paper candidate exists, the already-attested source is relayed to the same-hot B1 run over the one-run X25519 source exchange;
11. B1 builds the exact private runtime, executes only the canonical private submit path, returns encrypted proof, and destroys private material.

No private GitHub bearer token is part of the canonical source-ingress route.

## Current cutover state

The reusable Fleet source snapshot vault is deployed and healthy, but the exact unresolved ingress dependency remains:

`materialized local/file-ref -> authorized producer execution context -> encrypted snapshot publication/vault -> public runtime consumer`

That dependency is tracked as:

`FILE_CAPABLE_CONTEXT_TO_AUTHORIZED_PRODUCER_EXECUTION_BINDING_MISSING`

Until finite acceptance proves the full vault-to-runtime-to-B1 route:

- canonical B1 remains on `research-compute-public-/ibkr-b1-authority-v1`;
- private cloud changes remain private authority;
- this repo may contain the new runtime control-plane code, but perpetual self-handoff must not be treated as accepted production authority.

Cutover requires an executed green finite acceptance, not only CI/contracts.
