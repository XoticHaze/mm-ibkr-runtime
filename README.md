# MM-IBKR Public Runtime

`XoticHaze/mm-ibkr-runtime` is the public, strategy-blind runtime control plane for MM-IBKR.

It is **not** a public copy of `XoticHaze/mm-IBKR`, and it is **not** the broker authority.

## Authority split

| Plane | Repository / service | Owns |
|---|---|---|
| Private MM authority | `XoticHaze/mm-IBKR` | StrategySpec, selected-runtime identity, strategy logic, contract-month choice, sizing, paper/live execution policy |
| Public runtime | **this repository** | perpetual runtime owner, scheduling, checkpoint/idempotency continuity, exact-source consumption, watchdog, sanitized receipts |
| Public broker/compute | `XoticHaze/research-compute-public-` | canonical B1 IBKR workflow, Fleet Authority, broker credential sealing, hardened public compute |
| Fleet bridge | `fleet-authority.slenderiq.workers.dev` | OIDC authentication, exact private-source streaming, same-source attestation, broker/source-relay capability exchange |

## Hard routing rules

1. **Never copy private MM source into this repository.** Private source exists only transiently on admitted compute.
2. **Never add IBKR credentials here.** B1/Fleet Authority own broker authentication.
3. **Never make this repository strategy or execution-policy authority.**
4. **Never put the private GitHub source credential in this repo/runtime.** The only allowed private-source credential is the Fleet secret `MMIBKR_PRIVATE_SOURCE_TOKEN`, scoped read-only to `XoticHaze/mm-IBKR`.
5. **Runtime → B1 crosses Fleet Authority.** Do not assume this repo's `GITHUB_TOKEN` is a cross-repository broker token.
6. **Live trading is disabled.**
7. **No fabricated candidates/orders.** Paper execution occurs only from a genuine canonical private-MM candidate.
8. **Public receipts/checkpoints are sanitized.**
9. **B1 remains canonical in `research-compute-public-` until separately migrated.**
10. **Canonical source ingress is hostless:** exact source SHA code-pinned in Fleet → Fleet private GitHub tarball fetch → OIDC-authenticated stream to runtime → runtime digest/size attestation.
11. **The encrypted snapshot vault is an optional cache optimization, not a startup dependency.**
12. **One-run X25519 remains scoped to the hot B1 relay** after a genuine candidate, using the same attested source.

## Canonical route

```text
private mm-IBKR authority
  |
  | exact source SHA
  v
Fleet Authority
  |
  | read-only private GitHub credential held only as a Cloudflare secret
  | exact SHA must be code-approved
  v
GitHub private tarball endpoint
  |
  | streamed through Fleet over authenticated TLS
  | private credential never exposed to runtime
  v
mm-ibkr-runtime (GitHub OIDC)
  |
  | SHA-256 + byte-count attestation returned to Fleet
  | Dockerfile.bot build + private contracts
  | natural private-MM evaluation
  |
  +-- no candidate -> close boundary
  |
  +-- genuine paper candidate
         |
         | same-attested-source one-run X25519 relay
         v
Fleet Authority -> canonical B1 -> IBKR paper
```

No host, private-repository Actions job, local file handoff, or connector reconstruction is part of the canonical ingress route.

See `docs/AUTHORITY_ROUTE_MAP.md` and `docs/AGENT_RUNBOOK.md` before changing runtime or broker routing.
