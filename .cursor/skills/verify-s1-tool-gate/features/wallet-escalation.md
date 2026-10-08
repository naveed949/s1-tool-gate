# Wallet escalation

`generate_wallet` is kaia-mcp's wallet-class tool, and it can return a private key. The policy never allows it. With `kaia:wallet` it escalates by default. With `--wallet-default deny` it denies. Without `kaia:wallet` it denies for insufficient scope. An escalation at the live proxy is queued for a human. The operator uses `python -m claims_gate escalations list|approve|deny` to approve exactly one identical retry, or to deny it. The `live-proxy` feature drives that end to end, and this feature drives the CLI's fail-closed edges offline.

## Sub-features

- `wallet-escalate`: a `kaia:read kaia:wallet` token gives `escalate claims_wallet_escalate`.
- `wallet-no-scope`: a `kaia:read kaia:encode` token gives `deny claims_insufficient_scope`.
- `wallet-default-deny`: `--wallet-default deny` with `kaia:wallet` gives `deny claims_wallet_denied`.
- `escalation-queue-cli`:
  - `escalations list --dir <empty queue>` prints `[]` and exits 0.
  - `approve` and `deny` of an unknown id exit 1.
  - With no `--dir` and no `S1_ESCALATION_DIR`, it exits 2.
  - The queue dir is created with mode `700`, and `escalations.sqlite3` with mode `600`.

## How to get to it (user POV)

- Request `generate_wallet` with a token that does or does not include `kaia:wallet`, through `python -m claims_gate decide --tool generate_wallet [--wallet-default deny]`.
- An operator runs `python -m claims_gate escalations list|approve <id>|deny <id> --dir <queue>` against the directory the proxy was started with (`--escalation-dir` / `S1_ESCALATION_DIR`).

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0 for this run.

- **Run.** `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh wallet-escalation`
- **Escalate.** `mint --scope 'kaia:read kaia:wallet'` with `generate_wallet` gives `escalate claims_wallet_escalate`.
- **No scope.** `mint --scope 'kaia:read kaia:encode'` with `generate_wallet` gives `deny claims_insufficient_scope`.
- **Deny policy.** The escalate token plus `--wallet-default deny` gives `deny claims_wallet_denied`.
- **Queue CLI.** `queue-list-empty` exits 0 and prints `[]`. `queue-approve-unknown` and `queue-deny-unknown` exit 1, and stderr says `no escalation`. `queue-no-dir` exits 2. `queue-perms` shows dir `700` and sqlite `600`.
- **Proof.** The files `wallet-escalate.json`, `wallet-no-scope.json`, `wallet-default-deny.json`, and `queue-*.exit` exist under `evidence/<run-id>/wallet-escalation/`. None of the JSON files has `"choice": "allow"`.

## Gotchas

- `--wallet-default` accepts only `escalate` or `deny`. There is no allow option, by design.
- Escalate is not an allow. The seam does not run the tool. The `kaia-enforcement-demo` feature proves that with `walletStubCalls=0`.
- `decide` has no queue. Its escalate is terminal. Only the proxy writes queue rows, so approve-once is proven in `live-proxy` (`escalation-approved-once`, `escalation-denied`), not here.
- An approval never overrides a deny. The policy runs first, so a token without `kaia:wallet` is still `claims_insufficient_scope`.
