# MM-IBKR Public Runtime

`XoticHaze/mm-ibkr-runtime` is the public, strategy-blind runtime control plane for MM-IBKR.

It is **not** a public copy of `XoticHaze/mm-IBKR`, and it is **not** the broker authority.

## Authority split

| Plane | Repository / service | Owns |
|---|---|---|
| Private MM authority | `XoticHaze/mm-IBKR` | StrategySpec, selected-runtime identity, strategy logic, contract-month choice, sizing, paper/live execution policy |
| Public runtime | **this repository** | perpetual owner, scheduling, encrypted private-source consumption, sanitized cache/checkpoint lifecycle, watchdog, runtime receipts |
| Public broker/compute | `XoticHaze/research-compute-public-` | canonical B1 IBKR workflow, Fleet Authority, broker credential sealing, generic hardened public compute |
| Fleet bridge | `fleet-authority.slenderiq.workers.dev` | OIDC-authenticated encrypted rendezvous and capability exchange between the planes |

## Hard routing rules

1. **Never copy private MM source into this repository.** Private source may exist only transiently on admitted compute after encrypted, OIDC-authenticated materialization.
2. **Never add IBKR credentials here.** B1/Fleet Authority own broker authentication.
3. **Never make this repository strategy or execution-policy authority.** It transports and runs exact private MM authority.
4. **Never use this repo's `GITHUB_TOKEN` as an assumed cross-repository B1 token.** Runtime → B1 requests must cross the Fleet Authority capability boundary.
5. **Live trading is disabled.** Public runtime code must not enable, infer, or broaden live authority.
6. **No fabricated candidates/orders.** Paper execution occurs only from a genuine canonical private-MM natural candidate.
7. **Public receipts/checkpoints are sanitized.** No account identifiers, balances, positions, orders, credentials, or private strategy/source payloads may be persisted publicly.
8. **B1 remains canonical in `research-compute-public-` until an explicit authority migration is separately proven and accepted.**

## Canonical route

```text
private mm-IBKR
  |  OIDC-authenticated encrypted source
  v
Fleet Authority
  |
  v
mm-ibkr-runtime
  |  exact private SHA + private producer attestation
  |  strategy-blind broker request / command relay
  v
Fleet Authority
  |
  v
research-compute-public- / canonical B1
  |
  v
IBKR paper
```

See `docs/AUTHORITY_ROUTE_MAP.md` and `docs/AGENT_RUNBOOK.md` before changing any runtime or broker route.
