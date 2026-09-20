# MM-IBKR Public Runtime

`XoticHaze/mm-ibkr-runtime` is the public, strategy-blind runtime control plane for MM-IBKR.

It is **not** a public copy of `XoticHaze/mm-IBKR`, and it is **not** the broker authority.

## Authority split

| Plane | Repository / service | Owns |
|---|---|---|
| Private MM authority | `XoticHaze/mm-IBKR` | StrategySpec, selected-runtime identity, strategy logic, contract-month choice, sizing, paper/live execution policy |
| Public runtime | **this repository** | perpetual runtime owner, scheduling, checkpoint/idempotency continuity, encrypted exact-source consumption, watchdog, sanitized receipts |
| Public broker/compute | `XoticHaze/research-compute-public-` | canonical B1 IBKR workflow, Fleet Authority, reusable encrypted source vault, broker credential sealing, generic hardened public compute |
| Fleet bridge | `fleet-authority.slenderiq.workers.dev` | OIDC-authenticated encrypted source-vault unwrap plus broker/source-relay capability exchange |

## Hard routing rules

1. **Never copy private MM source into this repository.** Private source may exist only transiently on admitted compute after encrypted exact-SHA materialization.
2. **Never add IBKR credentials here.** B1/Fleet Authority own broker authentication.
3. **Never make this repository strategy or execution-policy authority.** It transports and runs exact private MM authority.
4. **Never use this repo's `GITHUB_TOKEN` as an assumed cross-repository B1 token.** Runtime → B1 requests must cross the Fleet Authority capability boundary.
5. **Live trading is disabled.** Public runtime code must not enable, infer, or broaden live authority.
6. **No fabricated candidates/orders.** Paper execution occurs only from a genuine canonical private-MM natural candidate.
7. **Public receipts/checkpoints are sanitized.** No account identifiers, balances, positions, orders, credentials, or private strategy/source payloads may be persisted publicly.
8. **B1 remains canonical in `research-compute-public-` until an explicit authority migration is separately proven and accepted.**
9. **Canonical private-source ingress is the reusable exact-SHA encrypted source vault.** The old private-Actions one-shot X25519 producer route is not canonical source ingress.
10. **One-run X25519 source exchange remains scoped to the hot B1 source relay** after a genuine paper candidate, using the same already-attested source.

## Canonical route

```text
private mm-IBKR authority
  |
  | exact source SHA selected by private authority
  v
authorized file-capable encrypted-snapshot producer
  |
  | ciphertext + exact source SHA + manifest SHA-256
  v
Fleet source snapshot vault
  |
  | runtime OIDC unwrap, no public plaintext
  v
mm-ibkr-runtime
  |
  | natural private-MM evaluation
  | no candidate -> close boundary
  | genuine paper candidate -> same-source one-run X25519 relay
  v
Fleet Authority
  |
  v
research-compute-public- / canonical B1
  |
  v
IBKR paper
```

The unresolved source-ingress dependency is intentionally explicit in `config/route-contract.json`: a verified local/file-ref must still be bound to an authorized producer execution context without relying on private-repository Actions admission.

See `docs/AUTHORITY_ROUTE_MAP.md` and `docs/AGENT_RUNBOOK.md` before changing any runtime or broker route.
