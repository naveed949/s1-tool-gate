# Live proxy

`python -m claims_gate proxy` sits in front of a real, running kaia-mcp. Every MCP request needs a token that verifies against kaia-mcp's JWKS with the pinned issuer and audience, and that introspection still reports active. `tools/call` is gated by the claims policy:
- allowed calls are forwarded unchanged
- denied calls get a `claims_*` JSON-RPC error
- `generate_wallet` is escalated

Denied and escalated calls never reach kaia-mcp. The proxy will not start if kaia-mcp's published tool → scope map differs from the gate's.

## Sub-features

- `proxy-allow-read`: `get_block_number` through the proxy returns live mainnet data. `Mcp-Session-Id` from `initialize` is passed through.
- `proxy-deny-scope`: `encode_function_data` with a `kaia:read kaia:wallet` token gets `-32050` `claims_insufficient_scope`, and kaia-mcp logs no `Tool call` for it.
- `proxy-escalate-wallet`: `generate_wallet` gets `-32051` `claims_wallet_escalate` with an `escalationId`, and kaia-mcp logs no `Tool call` for it.
- `proxy-forged`: the same claims and the real `kid`, signed by a foreign key, get HTTP 401 `claims_invalid_token`.
- `proxy-wrong-aud`: a proxy pinned to audience `other-api` refuses kaia tokens (`aud=kaia-mcp`) with `claims_audience_mismatch`.
- `proxy-revoked`: after `POST /oauth/revoke` at kaia-mcp the token still verifies offline, but the proxy denies it via introspection (`claims_token_revoked`).
- `proxy-introspection-down`: with introspection configured but unreachable, the proxy fails closed (`claims_introspection_unavailable`).
- `proxy-expired`: once kaia-mcp's short TTL passes, the same bearer gets `claims_expired`.
- `proxy-drift`: a missing or changed tool-scope map makes the proxy exit 3 without listening.
- `proxy-no-token-logs`: no token or introspection secret appears in any kaia-mcp, proxy, or audit log.

## How to get to it (user POV)

- An operator starts kaia-mcp over HTTP with `KAIA_INTROSPECTION_CLIENT_SECRET` set, then starts `python -m claims_gate proxy --upstream <kaia> --issuer <kaia> --audience kaia-mcp --introspection auto` with `S1_INTROSPECTION_CLIENT_ID/SECRET` in the environment.
- An agent logs in with the device flow at kaia-mcp (`/oauth/device`, `/oauth/device/verify`, `/oauth/token`), then speaks MCP Streamable HTTP to the proxy URL.
- All of the above is automated by `packages/claims-gate/e2e/live_kaia.py`.

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0, and its `live-proxy:` line shows `node`, `npm`, and `git` present.
- kaia-mcp source is one of:
  - `S1_VERIFY_KAIA_DIR` (or `KAIA_MCP_DIR`) pointing at a checkout that has JWT access tokens, `/oauth/introspect`, and `/.well-known/kaia-mcp/tool-scopes` (naveed949/kaia-mcp#3 or later). Its `node_modules` must be installed; the drive runs `npm run build`.
  - Otherwise, network access to clone the pinned commit and run `npm ci`.
- Egress to `https://public-en.node.kaia.io` for the live read.

- **Run.** `S1_VERIFY_KAIA_DIR=<kaia-mcp checkout> .cursor/skills/verify-s1-tool-gate/helpers/drive.sh live-proxy`. It takes about 20s plus build time, including a ~15s wait for token expiry.
- **Allow.** In `summary.json`, check `allow-read` has `ok: true`, a `resultText` like `Current block number on mainnet: <n>`, and `kaiaToolCallLines: 1`.
- **Deny and escalate.** `encode-denied` and `wallet-escalated` show the JSON-RPC `error` (`-32050` / `-32051`) and `kaiaToolCallLines: 0`. Cross-check with `kaia-mcp.log`, which has no `msg=Tool call tool=encode_function_data` or `tool=generate_wallet` line.
- **Token failures.**
  - `forged-denied`, `wrong-aud-denied`, `introspection-down`, and `expired-denied` each show `status: 401` and the expected `reasonCode`.
  - `revoked-denied` shows `statusBeforeRevoke: 200`, `stillValidOffline: true`, and `reasonCode: claims_token_revoked`.
- **Drift.** `drift-refused-missing` and `drift-refused-changed` show `exitCode: 3`. `proxy-drift-*.log` contains `refusing to start` and no `ready:`.
- **Audit and logs.** `audit-denies-never-forwarded` is ok. `no-token-in-logs` lists the files scanned and `leakingFiles: []`.
- **Proof.** `summary.json`, `kaia-mcp.log`, `proxy-*.log`, `audit-*.jsonl`, `live-e2e.stdout`, and `live-e2e.exit` are under `.cursor/skills/verify-s1-tool-gate/evidence/<run-id>/live-proxy/`. `summary.meta.kaia.rev` records which kaia-mcp commit ran, with a `+dirty` suffix if it was a modified checkout.

## Gotchas

- `allow-read` needs the public Kaia RPC. If it fails with a network error while every other check passes, report it as an environment failure. It is not a gate failure.
- The pinned clone runs `npm ci`, which takes a minute or more. Pointing `S1_VERIFY_KAIA_DIR` at a checkout with `node_modules` already installed is faster.
- kaia-mcp's `Tool call` line is logged before kaia-mcp's own scope check. Zero lines therefore means the proxy did not forward the call. One line would not prove kaia-mcp allowed it.
- A kaia-mcp checkout older than #3 has no JWKS keys or tool-scopes endpoint. The proxy then refuses to start, and the e2e fails at the first proxy. That is correct fail-closed behavior, not a flaky run.
- Drive `live-proxy` on its own when debugging. The CLI features do not depend on it.
