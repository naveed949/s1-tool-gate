# Wallet escalation

`generate_wallet` is kaia-mcp's wallet-class tool, and it can return a private key. The gate never allows it. With `kaia:wallet` it escalates by default. With `--wallet-default deny` it denies. Without `kaia:wallet` it denies for insufficient scope.

## Sub-features

- `wallet-escalate`: a `kaia:read kaia:wallet` token gives `escalate claims_wallet_escalate`.
- `wallet-no-scope`: a `kaia:read kaia:encode` token gives `deny claims_insufficient_scope`.
- `wallet-default-deny`: `--wallet-default deny` with `kaia:wallet` gives `deny claims_wallet_denied`.

## How to get to it (user POV)

- Request `generate_wallet` with a token that does or does not include `kaia:wallet`, through `python -m claims_gate decide --tool generate_wallet [--wallet-default deny]`.

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0 for this run.

- **Run.** `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh wallet-escalation`
- **Escalate.** `mint --scope 'kaia:read kaia:wallet'` with `generate_wallet` gives `escalate claims_wallet_escalate`.
- **No scope.** `mint --scope 'kaia:read kaia:encode'` with `generate_wallet` gives `deny claims_insufficient_scope`.
- **Deny policy.** The escalate token plus `--wallet-default deny` gives `deny claims_wallet_denied`.
- **Proof.** The files `wallet-escalate.json`, `wallet-no-scope.json`, and `wallet-default-deny.json` exist under `evidence/<run-id>/wallet-escalation/`. None of them has `"choice": "allow"`.

## Gotchas

- `--wallet-default` accepts only `escalate` or `deny`. There is no allow option, by design.
- Escalate is not an allow. The seam does not run the tool. The `kaia-enforcement-demo` feature proves that with `walletStubCalls=0`.
