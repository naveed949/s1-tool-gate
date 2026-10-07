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

`probs` is always `{}`. This is a rule, not a model score. `ToolPolicy` refuses `wallet_default="allow"`.

## kaia-mcp fixture

`claims_gate.kaia` copies kaia-mcp's real tool → scope map from `naveed949/kaia-mcp@db76732:src/auth/scopes.ts`:

- `kaia:read` covers 24 read tools (`get_kaia_balance`, `get_block`, `read_contract`, `estimate_gas`, ...).
- `kaia:encode` covers `encode_function_data`.
- `kaia:wallet` covers `generate_wallet`. It is wallet-class, so it escalates and is never allowed.

The fixture is copied by hand. A tool kaia-mcp adds later is denied (`claims_unknown_tool`) until it is added here.

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
- The demo's tool is a stub. It does not call a live kaia-mcp.
- This is not AdaptiveSandbox.
