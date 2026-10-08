# Live proxy

`python -m claims_gate proxy` sits in front of a real, running kaia-mcp. Every MCP request needs a token that verifies against kaia-mcp's JWKS with the pinned issuer and audience, and that introspection still reports active. By default every request is introspected; caching active answers for a TTL is opt-in (`--introspection-cache-ttl`). `tools/call` is gated by the claims policy:
- allowed calls are forwarded unchanged
- denied calls get a `claims_*` JSON-RPC error
- `generate_wallet` is escalated and queued for a human, who can approve exactly one identical retry

Denied and unapproved calls never reach kaia-mcp. The proxy will not start if kaia-mcp's published tool → scope map differs from the gate's. While running, it rechecks the map and denies every `tools/call` while the maps differ.

## Sub-features

- `proxy-allow-encode` (required allow path, offline): `encode_function_data` with a `kaia:encode` token returns `balanceOf` calldata (`0x70a08231…`) from kaia-mcp. `Mcp-Session-Id` from `initialize` is passed through.
- `proxy-allow-read` (optional): `get_block_number` returns live mainnet data. It needs the public Kaia RPC. When the RPC is unreachable before the call, the check is `SKIP` with a `skipReason`; it is not a failure. Once the call has run, any failure is `FAIL`.
- `proxy-deny-scope`: `encode_function_data` with a `kaia:read kaia:wallet` token gets `-32050` `claims_insufficient_scope`, and kaia-mcp logs no `Tool call` for it.
- `proxy-escalate-wallet`: `generate_wallet` gets `-32051` `claims_wallet_escalate` with an `escalationId`. The queue shows that id as `pending` for the token's `sub`. kaia-mcp logs no `Tool call` for it.
- `proxy-escalation-approve-once`: after `python -m claims_gate escalations approve <id>`, exactly one identical retry reaches kaia-mcp (one `tool=generate_wallet` line), and kaia-mcp itself answers `tool_disabled`. The row becomes `consumed`. The next retry gets `-32051` with a new id.
- `proxy-escalation-deny`: after `escalations deny <id>`, the identical retry gets `-32050` `claims_escalation_denied` with that id and is not forwarded.
- `proxy-forged`: the same claims and the real `kid`, signed by a foreign key, get HTTP 401 `claims_invalid_token`.
- `proxy-wrong-aud`: a proxy pinned to audience `other-api` refuses kaia tokens (`aud=kaia-mcp`) with `claims_audience_mismatch`.
- `proxy-revoked` (default, cache off): after `POST /oauth/revoke` at kaia-mcp, the token still verifies offline, yet the very next request through the main proxy is denied with `claims_token_revoked` and not forwarded.
- `proxy-revoked-cache-opt-in`: a separate proxy started with an explicit `--introspection-cache-ttl 3`.
  - Within that TTL it still forwards the revoked token, and kaia-mcp refuses it with 401.
  - After the TTL it denies it with `claims_token_revoked`, and again on the next request (inactive answers are never cached).
- `proxy-introspection-down`: with introspection configured but unreachable, the proxy fails closed (`claims_introspection_unavailable`).
- `proxy-expired`: once kaia-mcp's short TTL passes, the same bearer gets `claims_expired`.
- `proxy-drift`: a missing or changed tool-scope map makes the proxy exit 3 without listening.
- `proxy-drift-runtime`: a proxy started with `--drift-interval 1` has its map changed under it.
  - `/health` `toolScopes.ok` turns false, and `tools/call` gets `claims_tool_scope_drift` without being forwarded.
  - When the map is restored, calls go through again.
  - The proxy log has `ok -> drift` and `drift -> ok`.
- `proxy-no-token-logs`: no token or introspection secret appears in any kaia-mcp, proxy, audit, or escalations-CLI log.

## How to get to it (user POV)

- An operator starts kaia-mcp over HTTP with `KAIA_INTROSPECTION_CLIENT_SECRET` set.
- The operator then starts the proxy with `S1_INTROSPECTION_CLIENT_ID/SECRET` in the environment: `python -m claims_gate proxy --upstream <kaia> --issuer <kaia> --audience kaia-mcp --introspection auto [--introspection-cache-ttl S] [--escalation-dir DIR] [--drift-interval S]`.
- An agent logs in with the device flow at kaia-mcp (`/oauth/device`, `/oauth/device/verify`, `/oauth/token`), then speaks MCP Streamable HTTP to the proxy URL.
- A human reviews escalations with `python -m claims_gate escalations list|approve <id>|deny <id> --dir DIR`.
- All of the above is automated by `packages/claims-gate/e2e/live_kaia.py`.

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0, and its `live-proxy:` line shows `node`, `npm`, and `git` present.
- kaia-mcp source is one of:
  - `S1_VERIFY_KAIA_DIR` (or `KAIA_MCP_DIR`) pointing at a checkout that has JWT access tokens, `/oauth/introspect`, and `/.well-known/kaia-mcp/tool-scopes` (naveed949/kaia-mcp#3 or later). Its `node_modules` must be installed; the drive runs `npm run build`.
  - Otherwise, network access to clone the pinned commit and run `npm ci`.
- Optional: egress to the Kaia RPC (`KAIA_RPC_URL`, default `https://public-en.node.kaia.io`) for `allow-read`. Without it, that one check SKIPs.

- **Run.** `S1_VERIFY_KAIA_DIR=<kaia-mcp checkout> .cursor/skills/verify-s1-tool-gate/helpers/drive.sh live-proxy`. It takes about 20s plus build time. That includes the 3s opt-in cache window and the wait for token expiry.
- **Allow.**
  - `allow-encode` has `result: PASS`, a `resultText` of `0x70a08231` followed by 64 hex chars, and `kaiaToolCallLines: 1`.
  - `allow-read` is either PASS with `Current block number on mainnet: <n>`, or SKIP with a `skipReason` naming the RPC URL and its error.
- **Deny and escalate.**
  - `encode-denied` and `wallet-escalated` show the JSON-RPC `error` (`-32050` / `-32051`) and `kaiaToolCallLines: 0`.
  - `wallet-escalated.queued.status` is `pending`.
  - Cross-check with `kaia-mcp.log`, which has no `msg=Tool call tool=encode_function_data` line from the denied call.
- **Escalation queue.**
  - `escalation-approved-once` has `approveExit: 0`, `retryAnsweredByKaia: true`, `kaiaToolCallLines: 1`, and `statuses` with the approved id `consumed` and the next id `pending`.
  - `escalation-denied` has `denyExit: 0`, `claims_escalation_denied`, and `kaiaToolCallLines` still `1`.
  - `escalations.json` holds the final rows (argument hashes only), and `escalations-cli.log` holds every CLI call.
- **Token failures.**
  - `forged-denied`, `wrong-aud-denied`, `introspection-down`, and `expired-denied` each show `status: 401` and the expected `reasonCode`.
  - `revoked-denied` shows `statusBeforeRevoke: 200`, `stillValidOffline: true`, `introspectionCache: "default (off)"`, and `nextRequest` with `status: 401`, `reasonCode: claims_token_revoked`, `auditLines: 1`, `forwarded: false`.
  - `revoked-cache-window-opt-in` shows `introspectionCacheTtl: 3.0`, `withinCacheTtl.proxyForwarded: true` (with `kaiaStatus: 401`), and `afterTtl` as two `401` / `claims_token_revoked` entries. Its proxy log and audit are `proxy-cache-opt-in.log` and `audit-cache-opt-in.jsonl`.
- **Drift.**
  - `drift-refused-missing` and `drift-refused-changed` show `exitCode: 3`, and `proxy-drift-*.log` contains `refusing to start` and no `ready:`.
  - `drift-runtime-fail-closed` shows `flippedToClosed: true`, `duringDriftReason: claims_tool_scope_drift`, `recovered: true`, `kaiaToolCallLines` going `[n, n+1, n+2]` (the drift-time call is not forwarded), and `transitionsLogged: [true, true]`.
- **Audit and logs.** `audit-denies-never-forwarded` is ok with `approvedEscalationsForwarded: 1`. `no-token-in-logs` lists the files scanned and `leakingFiles: []`.
- **Proof.** `summary.json` (`summary.passed/failed/skipped/total` and a per-check `result`), `kaia-mcp.log`, `proxy-*.log`, `audit-*.jsonl`, `escalations.json`, `escalations-cli.log`, `live-e2e.stdout`, and `live-e2e.exit` are under `.cursor/skills/verify-s1-tool-gate/evidence/<run-id>/live-proxy/`. `summary.meta.kaia.rev` records which kaia-mcp commit ran, with a `+dirty` suffix if it was a modified checkout.

## Gotchas

- `allow-read` is the only check allowed to SKIP. The harness probes the RPC with `eth_blockNumber` before the call and SKIPs only if that probe fails. It never re-probes after the call: once `get_block_number` has run, any failure (including an exception) is `FAIL` with `rpcProbe` recording the pre-call probe, so an RPC outage after the call cannot hide a gate bug. To exercise the SKIP path on purpose, set `KAIA_RPC_URL=http://127.0.0.1:9` for the drive; kaia-mcp inherits it too. A SKIP is reported as skipped, never as verified.
- kaia-mcp's access-token TTL is 15s in the e2e. Each phase logs in fresh so later checks do not race it. Only `expired-denied` waits out the first token.
- The pinned clone runs `npm ci`, which takes a minute or more. Pointing `S1_VERIFY_KAIA_DIR` at a checkout with `node_modules` already installed is faster.
- kaia-mcp's `Tool call` line is logged before kaia-mcp's own scope and `tool_disabled` checks. Zero lines therefore means the proxy did not forward the call. One line would not prove kaia-mcp allowed it, which is why the approved `generate_wallet` retry still ends in `tool_disabled`.
- A kaia-mcp checkout older than #3 has no JWKS keys or tool-scopes endpoint. The proxy then refuses to start, and the e2e fails at the first proxy. That is correct fail-closed behavior, not a flaky run.
- Drive `live-proxy` on its own when debugging. The CLI features do not depend on it.
