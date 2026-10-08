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

The live proxy (below) adds four deny codes of its own:

| Check (proxy only) | Choice | `reasonCode` |
| --- | --- | --- |
| JWKS cannot be fetched and the cache is past its TTL | deny | `claims_jwks_unavailable` |
| Introspection is configured and says `active: false` | deny | `claims_token_revoked` |
| Introspection is configured but unreachable, errors, or answers garbage | deny | `claims_introspection_unavailable` |
| JSON-RPC batch, unparseable body, or `tools/call` without `params.name` | deny | `claims_malformed_request` |

`probs` is always `{}`. This is a rule, not a model score. `ToolPolicy` refuses `wallet_default="allow"`.

## kaia-mcp fixture

`claims_gate.kaia` copies kaia-mcp's real tool → scope map from `naveed949/kaia-mcp@253d6c8:src/auth/scopes.ts`:

- `kaia:read` covers 24 read tools (`get_kaia_balance`, `get_block`, `read_contract`, `estimate_gas`, ...).
- `kaia:encode` covers `encode_function_data`.
- `kaia:wallet` covers `generate_wallet`. It is wallet-class, so it escalates and is never allowed.

The fixture is copied by hand. A tool kaia-mcp adds later is denied (`claims_unknown_tool`) until it is added here.

**Drift guard.** The gate keeps owning its map; it does not take policy from the server it guards. Instead, the live proxy fetches kaia-mcp's published map (`GET /.well-known/kaia-mcp/tool-scopes`, added in naveed949/kaia-mcp#3) at startup and **refuses to start** if any tool or scope differs, or if the map cannot be fetched. `--no-drift-check` turns this off for upstreams that do not publish the map.

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
  - It is called on every request after the JWT checks pass.
  - `active: false` → `claims_token_revoked`. An unreachable or broken endpoint → `claims_introspection_unavailable`. It fails closed.
  - Without introspection, a token revoked at kaia-mcp stays usable at the proxy until `exp`. kaia-mcp still rejects it if forwarded.
- **`tools/call`** runs the claims policy:
  - **deny** → JSON-RPC error `-32050`, `data: {reasonCode, choice, tool, requiredScope}`. Not forwarded.
  - **escalate** (`generate_wallet`) → JSON-RPC error `-32051`, `data: {reasonCode: "claims_wallet_escalate", escalationId, …}`. Not forwarded.
  - **allow** → the request is forwarded byte-for-byte with its headers, including `Authorization` and `Mcp-Session-Id`. The response, including SSE, is streamed back.
- JSON-RPC **batches are rejected** (`claims_malformed_request`), so a batch cannot hide a `tools/call`.
- **No token is logged.** Each decision is one log line and, with `--audit-log`, one JSON line with `event`, `reasonCode`, `tool`, `subject`, `forwarded`, and a 12-char token fingerprint.
- `GET /health` and `GET /.well-known/oauth-protected-resource` are served by the proxy itself. The latter points `authorization_servers` at the issuer.
- **Startup is fail-closed.** Discovery, JWKS, introspection credentials, and the drift check must all pass, or the proxy prints the reason and exits 3 without listening.

### Live e2e

[`e2e/live_kaia.py`](e2e/live_kaia.py) starts kaia-mcp, either cloned at a pinned commit (`--kaia-ref`, default in the script) or a local checkout (`--kaia-dir` / `KAIA_MCP_DIR`). It starts the proxy, logs in with the **device flow**, and proves each of these:

- a `get_block_number` read returns live mainnet data through the proxy
- `encode_function_data` is denied by scope at the proxy, with zero `Tool call` lines for it in kaia-mcp's log
- `generate_wallet` is escalated and never forwarded
- forged, wrong-audience and expired tokens are denied
- a revoked token is denied via introspection, while it still verifies offline
- unreachable introspection fails closed
- the proxy refuses to start on a missing or changed tool-scope map
- no token appears in any log

It writes `summary.json` plus all logs to `--evidence-dir` and exits 0 only if every check passed. CI runs it in the `claims-gate-live-proxy` job. It needs network access to GitHub and the Kaia public RPC.

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
