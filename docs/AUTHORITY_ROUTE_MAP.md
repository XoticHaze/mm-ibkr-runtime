# Authority and Route Map

This document is normative for MM-IBKR cloud/runtime work.

## Canonical authorities

### Private strategy/runtime authority — `XoticHaze/mm-IBKR`

Owns StrategySpec, selected-runtime identity, signal/history and execution-contract selection, futures roll policy, natural evaluation, sizing, DCA/exit intent, and paper/live policy.

### Public runtime control plane — `XoticHaze/mm-ibkr-runtime`

Owns bounded/perpetual runtime execution, bar-boundary scheduling, exact-source consumption, ephemeral private runtime launch, sanitized cache/checkpoint/idempotency continuity, source-attestation relay client, watchdog/self-handoff, and sanitized receipts.

It does **not** own strategy intent, contract selection, order quantity, broker credentials, or live authority.

### Public broker/compute plane — `XoticHaze/research-compute-public-`

Owns canonical B1, Fleet Authority, broker credential sealing, same-hot B1 paper-execute transport, and hardened public compute primitives.

### Fleet Authority

Fleet is the cross-plane capability boundary. It authenticates GitHub-hosted runtime workflows with OIDC and pins repository, ref, workflow_ref, run_id, and event type.

For canonical source ingress Fleet may hold exactly one private-source read credential as a Cloudflare secret:

- secret name: `MMIBKR_PRIVATE_SOURCE_TOKEN`
- repository scope: `XoticHaze/mm-IBKR`
- permission: GitHub Contents **read-only**
- not returned to runtime
- not used for broker access
- not strategy/contract/quantity authority

Exact source SHAs are code-approved in Fleet. A public runtime cannot select an unapproved private commit.

## Allowed route graph

```text
mm-IBKR exact private source SHA
        |
        v
Fleet code approval
        |
        v
Fleet -> GitHub private tarball API
        |
        | read-only Fleet-held credential
        | streamed, not buffered into public persistence
        v
mm-ibkr-runtime via pinned GitHub OIDC
        |
        | compute SHA-256 + bytes
        | return same-run stream attestation to Fleet
        v
Dockerfile.bot + private contracts + natural evaluation
        |
        +-- no candidate --------------------------> close boundary
        |
        +-- genuine route-ready paper candidate
               |
               | same attested source
               v
           one-run X25519 Fleet relay
               |
               v
research-compute-public- / canonical B1
               |
               v
            IBKR paper
```

## Source transport split

- **Canonical startup ingress:** `fleet_authority_oidc_private_archive_stream`.
  - hostless
  - no private Actions admission
  - no connector reconstruction
  - private source credential exists only in Fleet
  - exact source SHA is code-pinned
  - runtime attests the exact streamed archive digest/size
- **Optional reusable cache:** encrypted source snapshot vault.
  - may reduce repeated private archive fetches later
  - must never become a host/local-file dependency
- **Hot B1 relay:** one-run X25519 source exchange after a genuine candidate.
  - relays the same already-attested source
  - does not choose source, strategy, contract, or quantity

## Forbidden shortcuts

- private GitHub source credential in `mm-ibkr-runtime`
- direct IBKR credentials in `mm-ibkr-runtime`
- private-repository Actions admission as a startup dependency
- local/host source publication as a required cutover step
- connector-by-connector reconstruction as production source transport
- public contract/month/quantity selection
- fabricated candidate/order
- any public component broadening live authority
- unrelated B1 migration

## Finite cutover acceptance

Before perpetual handoff is enabled:

1. Fleet health reports private-source authority configured.
2. Runtime requests the code-approved exact private source SHA over pinned OIDC.
3. Fleet streams that exact GitHub private tarball without exposing its credential.
4. Runtime computes the archive SHA-256 and byte count and Fleet stores the same-run attestation.
5. Runtime safe-extracts the archive and requires `Dockerfile.bot`.
6. Exact private hostless/runtime contract suite passes.
7. Natural evaluation reaches the B1 boundary.
8. No genuine candidate closes cleanly; a genuine candidate uses the same-attested-source X25519 hot relay.
9. Live remains disabled.

Finite executed evidence, not only CI, is required before perpetual self-handoff promotion.
