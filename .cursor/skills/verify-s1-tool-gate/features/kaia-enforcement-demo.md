# kaia enforcement demo

`python -m claims_gate demo` mints all 22 golden cases with a fresh TEST-ONLY key. It evaluates them with the kaia-mcp fixture and enforces each decision through `gate_enforcement.EnforcementSeam`, with a stub in place of the kaia tool handler. It exits 0 only when every case matches its literal expectation.

## Sub-features

- `demo-golden`: 22/22 cases match, with allow/deny/escalate = 3/18/1.
- `demo-side-effects`: the stub runs only for the three allow cases (`get_kaia_balance`, `encode_function_data`, `get_chain_info`). `sideEffect` equals `choice == allow` for every case.
- `demo-wallet`: the wallet stub never runs. `wallet-escalate` is `escalated: true` by default, and is `deny claims_wallet_denied` with `escalated: false` under `--wallet-default deny`.
- `demo-uncovered-paths`: `alg-none`, `unknown-kid`, `missing-exp`, `missing-scope`, `not-yet-valid`, and `expired-at-boundary` are exercised here.

## How to get to it (user POV)

- Run `python -m claims_gate demo`, then `python -m claims_gate demo --wallet-default deny`, from the repo root with the venv's python.

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0 for this run.

- **Run.** `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh kaia-enforcement-demo`
- **Golden.** `demo-report.json` has `summary.passed == summary.total == 22` and exit `0`.
- **Side effects.** `summary.stubCalls` is exactly the three allowed tools. `walletStubCalls` is `0`.
- **Wallet deny variant.** In `demo-report-wallet-deny.json`, the `wallet-escalate` row has `decision.reasonCode == "claims_wallet_denied"` and `escalated == false`. Its exit is `0`.
- **Proof.** `demo-report.json`, `demo-report-wallet-deny.json`, and their `.exit` files exist under `evidence/<run-id>/kaia-enforcement-demo/`.

## Gotchas

- The stub stands in for kaia-mcp's handler. This feature does not call a live kaia-mcp server, and its report says so in `nonClaims`.
- The demo uses a fixed clock (`now: 1800000000`). The live clock does not affect it.
