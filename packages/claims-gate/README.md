# claims-gate

Deterministic OIDC/OAuth claims gate for MCP tool calls. It verifies the caller's access token (a JWT) against a JWKS, issuer, and audience. It then maps the verified scopes onto a tool policy and returns the repo's standard `GateDecision` (`choice`, `probs`, `reasonCode`). `gate_enforcement.EnforcementSeam` enforces that decision unchanged.

Every failure is a **deny**. Wallet-class tools **escalate** by default, or deny when configured. They are never a silent allow.

## Decision table

Checks run in this order. The first failure wins.

| Check | Choice | `reasonCode` |
| --- | --- | --- |
| No `Authorization`, or a scheme other than `Bearer` | deny | `claims_unauthenticated` |
| Malformed JWT, bad signature, `alg` not RS256/ES256 (including `none` and HS*), unknown `kid` | deny | `claims_invalid_token` |
| `sub`, `iss`, `aud`, `exp`, or `scope`/`scp` missing or wrong type | deny | `claims_missing_claim` |
| `iss` is not the configured issuer | deny | `claims_issuer_mismatch` |
| `aud` does not contain the configured audience | deny | `claims_audience_mismatch` |
| `now >= exp` | deny | `claims_expired` |
| `now < nbf` | deny | `claims_not_yet_valid` |
| Tool not in the policy map | deny | `claims_unknown_tool` |
| Token scopes lack the tool's required scope | deny | `claims_insufficient_scope` |
| Wallet-class tool, scope present, `wallet_default="escalate"` (default) | escalate | `claims_wallet_escalate` |
| Wallet-class tool, scope present, `wallet_default="deny"` | deny | `claims_wallet_denied` |
| Otherwise | allow | `claims_allow` |

The live proxy (below) adds deny codes of its own:

| Check (proxy only) | Choice | `reasonCode` |
| --- | --- | --- |
| JWKS cannot be fetched and the cache is past its TTL | deny | `claims_jwks_unavailable` |
| Introspection is configured and says `active: false` | deny | `claims_token_revoked` |
| Introspection is configured but unreachable, errors, or answers garbage | deny | `claims_introspection_unavailable` |
| JSON-RPC batch, unparseable body, or `tools/call` without `params.name` | deny | `claims_malformed_request` |
| Escalated call whose identical request a human denied (within the deny window) | deny | `claims_escalation_denied` |
| Escalated call, but the escalation queue cannot be read or written | deny | `claims_escalation_unavailable` |
| `tools/call` while the periodic recheck finds the upstream tool-scope map different or unfetchable | deny | `claims_tool_scope_drift` |

`probs` is always `{}`. This is a rule, not a model score. `ToolPolicy` refuses `wallet_default="allow"`.

## kaia-mcp fixture

`claims_gate.kaia` copies kaia-mcp's real tool → scope map from `naveed949/kaia-mcp@253d6c8:src/auth/scopes.ts`:

- `kaia:read` covers 24 read tools (`get_kaia_balance`, `get_block`, `read_contract`, `estimate_gas`, ...).
- `kaia:encode` covers `encode_function_data`.
- `kaia:wallet` covers `generate_wallet`. It is wallet-class, so it escalates and is never allowed.

The fixture is copied by hand. A tool kaia-mcp adds later is denied (`claims_unknown_tool`) until it is added here.

**Drift guard.** The gate keeps owning its map. It does not take policy from the server it guards. Instead, the live proxy fetches kaia-mcp's published map (`GET /.well-known/kaia-mcp/tool-scopes`, added in naveed949/kaia-mcp#3) and compares it with its own:

- At startup, the proxy **refuses to start** (exit 3) if any tool or scope differs, or if the map cannot be fetched.
- While serving, it rechecks once as soon as it starts listening and then every `--drift-interval` seconds (default 60). A negative interval is refused at startup (exit 3). If the maps differ, or the fetch fails, it **fails closed**: every `tools/call` is denied with `-32050` `claims_tool_scope_drift`, and `error.data.drift` carries the diff or the fetch error. This lasts until a recheck matches again. Other MCP traffic (`initialize`, `tools/list`, …) still needs only a valid token.
  - Each transition (`ok -> drift`, `drift -> ok`) is logged at WARNING and written to the audit log as `drift_failing` / `drift_recovered`.
  - `GET /health` reports `toolScopes: {ok, checkedAt, intervalSeconds, url}`.
- `--drift-interval 0` keeps only the startup check. `--no-drift-check` turns off both checks, for upstreams that do not publish the map.

## Golden evals

[`src/claims_gate/kaia_golden.json`](src/claims_gate/kaia_golden.json) has 22 cases with literal expected decisions. They cover allow, deny-by-scope, expired, wrong audience, wrong issuer, unauthenticated, bad signature, `alg: none`, unknown `kid`, missing claims, an unknown tool, and wallet escalation. The tests mint tokens at run time with a fresh TEST-ONLY RSA key and a fixed clock. No key is committed.

```bash
python -m pip install -e packages/gate-client -e packages/gate-enforcement -e "packages/claims-gate[dev]"
python -m pytest packages/claims-gate
```

## CLI

```bash
python -m claims_gate tools                      # kaia-mcp tool -> scope fixture
python -m claims_gate demo                       # golden cases through ClaimsGate + EnforcementSeam; exit 0 iff all match
python -m claims_gate testkit init --dir /tmp/s1-kit     # TEST-ONLY key + jwks.json + config.json
TOKEN=$(python -m claims_gate testkit mint --dir /tmp/s1-kit --scope "kaia:read")
S1_AUTHORIZATION="Bearer $TOKEN" python -m claims_gate decide \
  --jwks /tmp/s1-kit/jwks.json --issuer https://idp.test.invalid --audience kaia-mcp --tool get_kaia_balance
```

`decide` reads the header value from `S1_AUTHORIZATION` or `--authorization-file`, so the token never appears in argv. It prints one JSON object (`choice`, `probs`, `reasonCode`, `tool`, `requiredScope`, `subject`, `detail`) and exits 0 for any decision. Exit 2 is a config error. The token is never printed.

`demo` uses a stub in place of the kaia-mcp tool handler. `sideEffect` is true only for the three allow cases. The `generate_wallet` stub is never called.

## Live proxy (in front of a running kaia-mcp)

`python -m claims_gate proxy` is a small stdlib HTTP reverse proxy for kaia-mcp's Streamable HTTP endpoint.

```bash
S1_INTROSPECTION_CLIENT_ID=s1-tool-gate S1_INTROSPECTION_CLIENT_SECRET=... \
python -m claims_gate proxy --upstream http://127.0.0.1:3100 \
  --issuer http://127.0.0.1:3100 --audience kaia-mcp --introspection auto \
  --port 3200 --audit-log /tmp/s1-audit.jsonl
```

- **Every request** on the MCP path needs a bearer token that verifies against the issuer's JWKS, with the **pinned** issuer and audience. That includes `initialize`, `tools/list`, notifications, the SSE `GET`, and `DELETE`.
  - The JWKS comes from the discovery `jwks_uri`. Discovery's `issuer` must equal `--issuer`, and the `jwks_uri` must be on the issuer's origin unless you pass `--jwks-uri`.
  - The JWKS is cached (`--jwks-ttl`, default 300s). A token with an unknown `kid` triggers a refetch, at most once every 10s. A cache past its TTL whose refetch fails denies with `claims_jwks_unavailable`.
  - A token failure gets HTTP 401 with `WWW-Authenticate: Bearer … resource_metadata=…` and a JSON-RPC error.
- **Introspection** (optional): `--introspection auto` (the discovery `introspection_endpoint`) or a URL. It uses RFC 7662 with `client_secret_basic`, and credentials come only from `S1_INTROSPECTION_CLIENT_ID` / `S1_INTROSPECTION_CLIENT_SECRET`.
  - It is called after the JWT checks pass, on **every request** by default. Caching `active: true` answers is opt-in (see below).
  - `active: false` → `claims_token_revoked`. An unreachable or broken endpoint → `claims_introspection_unavailable`. It fails closed.
  - **Cache (off by default).** `--introspection-cache-ttl` defaults to `0`: nothing is cached, every request is introspected, and a token revoked at the IdP is denied on the very next request. To enable the cache, pass a positive number of seconds, e.g. `--introspection-cache-ttl 5`. With a TTL set:
    - Only `active: true` answers are cached. The key is the token's sha256, never the token itself. An entry lives until `min(now + TTL, token exp)`.
    - `active: false`, HTTP errors, timeouts, and malformed answers are **never cached**. Every one of them is re-asked and denied.
    - The cache holds at most 10,000 entries. When full it drops expired entries, then clears itself (a miss only costs one introspection call).
  - **Revocation-latency tradeoff.** With a TTL of *T* seconds, a token revoked at the IdP can still pass the proxy for up to *T* seconds after its last successful introspection. In return, the proxy calls introspection at most once per token per *T* instead of on every MCP request. Only opt in when introspection load matters, and pick *T* as the longest revocation delay you can accept. Leave it at the default `0` when revocation must apply on the very next request. JWT expiry is always checked first, so the cache never extends a token past `exp`.
  - Without introspection, a token revoked at kaia-mcp stays usable at the proxy until `exp`. kaia-mcp still rejects it if forwarded.
- **`tools/call`** runs the claims policy:
  - **deny** → JSON-RPC error `-32050`, `data: {reasonCode, choice, tool, requiredScope}`. Not forwarded.
  - **escalate** (`generate_wallet`) → JSON-RPC error `-32051`, `data: {reasonCode: "claims_wallet_escalate", escalationId, escalationStatus, …}`. Not forwarded. With `--escalation-dir` a human can approve one retry (see [Escalation queue](#escalation-queue)).
  - **allow** → the request is forwarded byte-for-byte with its headers, including `Authorization` and `Mcp-Session-Id`. The response, including SSE, is streamed back.
- JSON-RPC **batches are rejected** (`claims_malformed_request`), so a batch cannot hide a `tools/call`.
- **No token is logged.** Each decision is one log line and, with `--audit-log`, one JSON line with `event`, `reasonCode`, `tool`, `subject`, `forwarded`, and a 12-char token fingerprint.
- `GET /health` and `GET /.well-known/oauth-protected-resource` are served by the proxy itself. The latter points `authorization_servers` at the issuer.
- The proxy listens with a backlog of 128 (capped by the kernel's `somaxconn`), so a burst of concurrent clients is queued rather than dropped. Each connection is handled on its own thread.
- **Startup is fail-closed.** Discovery, JWKS, introspection credentials, the escalation queue (if configured), the drift check, and every setting (for example a negative `--drift-interval`) must all pass. Otherwise the proxy prints the reason and exits 3 without listening. After startup, the drift check keeps running (see **Drift guard** above).

### Escalation queue

Without `--escalation-dir` (or `S1_ESCALATION_DIR`) an escalation is terminal: `-32051` with a random `escalationId` and `escalationStatus: "not_queued"`, and nothing can approve it.

With it, the proxy records every escalation in `<dir>/escalations.sqlite3` (dir mode `700`, file `600`). If the file (or the directory) is deleted while the proxy runs, the next queue access recreates it empty with the same modes, whatever the process umask; nothing approved survives, so the next escalation is a fresh `pending` request. One row per request:

| Field | Meaning |
| --- | --- |
| `id` | 16 hex chars; returned as `error.data.escalationId` |
| `sub` | verified token subject |
| `tool` | tool name |
| `argsHash` | sha256 of the canonical JSON of `params.arguments` (sorted keys, no whitespace). Arguments themselves are never stored. Absent arguments and `{}` hash differently. |
| `reasonCode` | why the policy escalated (`claims_wallet_escalate`) |
| `status` | `pending` → `approved` → `consumed`, or `denied`, or `expired` |
| `createdAt`, `decidedAt`, `consumedAt` | unix seconds |
| `expiresAt` | pending: decide before this; approved: retry before this; denied: identical retries denied until this |
| `pendingTtl`, `approvalTtl` | fixed by the proxy when the row is created (`--escalation-pending-ttl`, default 3600s; `--escalation-approval-ttl`, default 300s) |

```bash
python -m claims_gate escalations list [--status pending] --dir /var/lib/s1/escalations
python -m claims_gate escalations approve <id> --dir /var/lib/s1/escalations
python -m claims_gate escalations deny <id> --dir /var/lib/s1/escalations
```

When the policy escalates a call, the proxy:

1. forwards it **once** if an unexpired `approved` row has the same `sub`, `tool`, and `argsHash`. That row becomes `consumed` in the same sqlite transaction, so one approval can never be used twice, even across threads or processes;
2. denies it (`-32050`, `claims_escalation_denied`, with the `escalationId`) if a human denied the identical request and the deny window is still open;
3. otherwise answers `-32051` with the existing `pending` row's id, or a new one.

**What an approval binds to.** An approval matches on `sub` + `tool` + `argsHash`, not on a specific token: any valid token for the same subject (for example a refreshed one) can use it, and a different subject cannot. `argsHash` is sha256 over the canonical JSON of the *exact* `params.arguments` (sorted keys, no whitespace, `ensure_ascii=False`). There is no Unicode or other normalization, so arguments that differ only in Unicode form (NFC vs NFD), number spelling (`1` vs `1.0`), or string case are different requests and need their own approval.

**An approval is spent before the call is forwarded (fail closed).** The row becomes `consumed` in the same transaction that decides *allow*, before the proxy contacts kaia-mcp. If the upstream call then fails (connection error → HTTP 502 `-32052`, or an error from kaia-mcp itself), the approval is still used up; the caller must retry, get a new escalation id, and ask a human again. This is deliberate: a two-phase "reserve, then confirm after success" scheme was rejected because it is more complex and risks executing the same wallet call twice.

Approval only turns an *escalate* into one allow. The claims policy runs first, so a token without `kaia:wallet` is still denied (`claims_insufficient_scope`) whatever the queue says. A different subject, tool, or argument set is a different request. Any queue error denies (`claims_escalation_unavailable`), and a queue directory that cannot be opened stops the proxy from starting (exit 3). `approve` only works on `pending`; `deny` works on `pending` or unused `approved`. The CLI exits 1 for any other transition.

### Live e2e

[`e2e/live_kaia.py`](e2e/live_kaia.py) starts kaia-mcp, either cloned at a pinned commit (`--kaia-ref`, default in the script) or from a local checkout (`--kaia-dir` / `KAIA_MCP_DIR`). It then starts the proxy (with an escalation queue and the default introspection cache, which is off) and logs in with the **device flow**. It proves each of these:

- `encode_function_data` with `kaia:encode` returns `balanceOf` calldata through the proxy. This is the **required allow-path check**, and it is fully offline.
- `encode_function_data` without `kaia:encode` is denied by scope at the proxy, and kaia-mcp's log has zero `Tool call` lines for it.
- `generate_wallet` is escalated, queued as `pending`, and never forwarded.
  - After `escalations approve <id>`, exactly one identical retry reaches kaia-mcp. kaia-mcp itself still refuses it (`tool_disabled`). The next retry is escalated again with a new id.
  - After `escalations deny <id>`, the identical retry gets `claims_escalation_denied`.
- Forged, wrong-audience, and expired tokens are denied.
- A token revoked at kaia-mcp still verifies offline, yet with the default settings the proxy denies it with `claims_token_revoked` on the very next request, without forwarding it.
- A separate proxy that opts in with `--introspection-cache-ttl 3` forwards the revoked token only while its cache entry lives, and kaia-mcp refuses it on its own. After the TTL that proxy denies it with `claims_token_revoked` every time.
- Unreachable introspection fails closed.
- The proxy refuses to start on a missing or changed tool-scope map.
- While running with `--drift-interval 1`, a map change makes the proxy deny `tools/call` with `claims_tool_scope_drift`, and restoring the map lets calls through again.
- No token appears in any log.
- **Optional:** a `get_block_number` read returns live mainnet data. It needs the public Kaia RPC (`KAIA_RPC_URL`, default `https://public-en.node.kaia.io`). The harness probes the RPC with `eth_blockNumber` before the call. Only if that probe fails is the check reported as `SKIP` (the run does not fail). Once the `tools/call` has run, any failure is a `FAIL`; the RPC is not re-probed, so an outage after the call can never turn a gate bug into a SKIP.

It writes `summary.json` (`passed`/`failed`/`skipped`/`total`, and a `result` of `PASS`/`FAIL`/`SKIP` per check) plus all logs to `--evidence-dir`. It exits 0 only if no check failed. Only `allow-read` may SKIP; a required check can never SKIP. CI runs it in the `claims-gate-live-proxy` job. It needs GitHub access for the clone. The Kaia RPC is needed only for the optional read.

```bash
python packages/claims-gate/e2e/live_kaia.py --evidence-dir /tmp/s1-live [--kaia-dir ../kaia-mcp]
```

## Library

```python
from claims_gate import ClaimsGate, VerifierConfig, kaia_policy, combine

gate = ClaimsGate(VerifierConfig(jwks=jwks, issuer=ISSUER, audience="kaia-mcp"), kaia_policy())
result = gate.evaluate(request.headers.get("Authorization"), tool_name)
decision = combine(result.decision, nimble_decision)  # claims are the ceiling; Nimble can only narrow
seam.enforce(decision, tool_request, granted_authority)
```

## Non-claims

- This is a deterministic claims check. It is not a Nimble score.
- The `demo` command's tool is a stub. The live proxy and its e2e are the only parts that talk to a real kaia-mcp. They use kaia-mcp's in-process demo IdP, not a production identity provider.
- This is not AdaptiveSandbox.
