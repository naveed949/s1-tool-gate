# s1-tool-gate

Per-tool-call authority gate. Before each tool call, local Ollama Nimble chooses **allow / deny / escalate** from the granted policy, the tool name, redacted arguments, and a short context. The Python client uses TypeSafe’s SDK against Ollama’s `/v1/systemone` endpoint.

## Composition

The System-1 gate sits **in front of AdaptiveSandbox/gondolin**. It replaces the recommend slot. It is never the security root.

This gate is **not a substitute** for AdaptiveSandbox/gondolin.

## Fail-closed

Fail-closed → **deny**. When Ollama is down, timed out, or below the confidence threshold, the gate denies. Escalate only when Nimble is up and chooses grey.

## Gate client

`packages/gate-client` is the Python client. It calls local Ollama Nimble through TypeSafe’s official SDK (`typesafe-sdk`), not a hand-rolled `/v1/systemone` parse. Ollama **0.35 or newer** is required. The client returns `{ choice, probs, reasonCode }` and does not execute the tool.

The SDK default (no base URL) is TypeSafe cloud. This package wires local Ollama explicitly. A TypeSafe cloud host without `GATE_ALLOW_TYPESAFE_CLOUD=1` fail-closes to deny.

```bash
export TYPESAFE_BASE_URL=http://localhost:11434
export TYPESAFE_API_KEY=ollama
export TYPESAFE_DEFAULT_MODEL=nimble
```

See [packages/gate-client/README.md](packages/gate-client/README.md) for thresholds, reason codes, and tests.

## Enforcement

`packages/gate-enforcement` takes an injected gate decision and a stub tool. Deny and escalate do not call the stub. Escalate notifies an escalation-channel stub. Allow calls the stub once when the request matches a granted-authority fixture. The observation log records `choice`, `probs`, `reasonCode`, and `sideEffect`. `sideEffect` is true only when the stub actually ran. It is not copied from `choice`.

The log schema is [packages/gate-enforcement/observation-log.schema.json](packages/gate-enforcement/observation-log.schema.json), described in [packages/gate-enforcement/README.md](packages/gate-enforcement/README.md).

## Claims gate (OIDC/OAuth in front of an MCP server)

`packages/claims-gate` turns a verified access token into an allow / deny / escalate for one MCP tool call. It checks the signature against a JWKS, then `iss`, `aud`, `exp`/`nbf`, `sub`, and `scope`. The scopes map onto a tool policy. It returns the same `GateDecision` shape as the gate client, so `gate-enforcement` runs it unchanged. It ships a kaia-mcp fixture (`kaia:read`, `kaia:encode`, `kaia:wallet`, copied from kaia-mcp `253d6c8`, unchanged at `00f3511` and `5794969`) and 22 golden evals. `python -m claims_gate proxy` runs the same gate as a live reverse proxy in front of a running, stateless (MCP 2026-07-28) kaia-mcp `00f3511`+ (live e2e pin `5794969`, MCP SDK v2), with `--audience` pinned to kaia's canonical URL. It verifies kaia's JWTs via JWKS and optional introspection, never forwards denies or wallet escalations, and refuses to start on tool-scope drift. `packages/claims-gate/e2e/live_kaia.py` proves this end to end. Details are in [packages/claims-gate/README.md](packages/claims-gate/README.md).

### Wiring it in front of an MCP server

1. Terminate the partner's MCP HTTP request at a proxy or middleware you control. Read `Authorization` and the JSON-RPC `tools/call` name.
2. Build one `ClaimsGate` per resource server. Use `VerifierConfig(jwks=<your IdP JWKS>, issuer=<exact issuer>, audience=<this MCP server's audience>)` and a `ToolPolicy` that maps every exposed tool to its scope. `kaia_policy()` is the kaia-mcp map. List wallet or fund-moving tools in `wallet_tools`.
3. Call `gate.evaluate(authorization, tool_name)` before forwarding. Forward only on `allow`. On `escalate`, send the call to a human or higher-authority queue (`EscalationChannel`). On `deny`, return the MCP error without forwarding.
4. If the System-1 Nimble gate also runs, pass both through `combine(claims, nimble)`. Claims are the ceiling. Nimble can narrow an allow but cannot widen a deny or an escalate.
5. Enforce through `EnforcementSeam` so `sideEffect` is observed, not inferred.
6. Keep the MCP server's own scope checks. Kaia-mcp still enforces its scopes itself. The gate is defense in depth, not a replacement.
7. Refresh the JWKS from your IdP on rotation. An unknown `kid` denies.

### Threat notes

- **Forged or downgraded tokens.** Only RS256 and ES256 are accepted. `alg: none` and HS* are rejected, both in tokens and in `VerifierConfig`. This blocks the HS256-with-public-key confusion attack.
- **Token replay to another API.** `aud` must contain this server's audience, and `iss` must match exactly.
- **Stale tokens.** `exp` is required and checked with zero leeway by default. A future `nbf` denies.
- **Scope creep.** An unknown tool denies. A missing scope denies. The map is explicit per tool, with no wildcards.
- **Wallet and key material.** `generate_wallet` escalates even with `kaia:wallet`. `wallet_default` cannot be set to allow.
- **Token leakage.** The gate never logs or returns the token. `decide` reads it from env or a file, never from argv.
- **Fail-open fallbacks.** No path turns an error into an allow. A broken JWKS denies.
- **Not covered.** Token revocation (introspection), DPoP or mTLS sender-constraining, and argument-level policy are not covered. A stolen unexpired token with the right scopes is allowed until `exp`. Keep token lifetimes short.

## Prove non-claims

- Nimble score ≠ gate held
- high noul ≠ safe
- this is not AdaptiveSandbox

## Authority flip

`packages/authority-flip` scores a pinned set of one-fact agent-authority contrasts. Each pair is the same tool call with one policy, argument, or context fact changed so the gold label flips between allow, deny, and escalate. The package reports flip rate and expected calibration error (ECE) for three comparators: Nimble on Ollama, a base Qwen chat model on Ollama, and one frontier judge.

The judge runs only when `AUTHORITY_FLIP_JUDGE_API_KEY` is set. The pair file is hashed in `packages/authority-flip/data/manifest.json`. `npm test` checks that hash. It does not regenerate the pairs.

### What this proves

On that pinned set, the report shows whether a comparator's allow / deny / escalate choice matched both sides of the one-fact change, and whether the probability it assigned to its own choice matches its accuracy across ten bins. `status: ok` means every item was scored. It is not a promise that the flip rate is high.

### What this does not prove

- It does not prove the gate held. A Nimble score is not an observation that a side effect was allowed or blocked.
- It is not a sandbox qualification, and it is not AdaptiveSandbox mediation.
- It is not "open Jev". A local Nimble call to Ollama `/v1/systemone` does not open Jev, release Jev, or show that Nimble and Jev are the same system.
- High confidence is not safety. ECE on this set is not a certificate. Qwen and the judge report their own probabilities in JSON; those are not Nimble's choice-head probabilities.
- `unsupported` is not a pass. If Ollama is down, Nimble and base Qwen are `unsupported`. If the judge key is missing, the judge is `unsupported`. Flip rate and ECE are null in those cases. `npm run authority-flip` exits non-zero.

The report schema, the binning definition, and the commands are in [packages/authority-flip/README.md](packages/authority-flip/README.md).

## Layout

- `packages/authority-flip` is the TypeScript flip harness: pinned pairs, flip rate, and ECE.
- `packages/gate-client` is the Python System-1 gate client (`typesafe-sdk` against local Ollama Nimble).
- `packages/gate-enforcement` is the Python enforcement seam, stub tool runner, and observation log.
- `packages/e2e-demo` is the scripted demo that calls the three packages and writes one report.
- `packages/claims-gate` is the Python OIDC/OAuth claims gate: verified token claims to allow / deny / escalate, with the kaia-mcp fixture, golden evals, a live reverse proxy (`python -m claims_gate proxy`), and a live kaia-mcp e2e (`e2e/live_kaia.py`).

The flip harness does not call the gate client or the enforcement seam. `packages/e2e-demo` is the scripted path that calls all three and prints one report.

## Demo

`npm run --silent e2e-demo` loads the pinned flip pairs, asks the gate client for a decision on each side, runs that decision through the enforcement seam and stub, and embeds the authority-flip report (flip rate and ECE). `--silent` keeps npm's script banner off stdout, so the process prints only the JSON report.

Ollama **0.35 or newer** serves Nimble. The live command needs the Python packages installed once so the TypeSafe SDK imports:

```bash
export TYPESAFE_BASE_URL=http://localhost:11434
export TYPESAFE_API_KEY=ollama
export TYPESAFE_DEFAULT_MODEL=nimble
python -m pip install -e packages/gate-client -e packages/gate-enforcement
npm run --silent e2e-demo
```

The report schema is [`packages/e2e-demo/schema/report.schema.json`](packages/e2e-demo/schema/report.schema.json). It includes:

- `decisions` — gate-client `{ choice, probs, reasonCode }` for each pair side
- `observations` — one observation-log entry per side (`sideEffect` is whether the stub ran)
- `flipSummary` and `flip` — flip rate and ECE from the authority-flip harness

`npm test` covers this orchestrator with mocked gate, enforcement, and flip backends. It does not call Ollama. The block above is the live path.

When Ollama is down the gate path is `unavailable` (`reasonCode` `fail_closed_down`, choice deny). Nimble and base Qwen in the flip section are `unsupported`, and their flip rate and ECE are null. The process exits non-zero. Those nulls are not replaced with a rate computed from the fail-closed denies.

Exit 0 means every gate decision was a Nimble choice and every flip comparator, including base Qwen and the frontier judge, scored. A missing Qwen tag or a missing `AUTHORITY_FLIP_JUDGE_API_KEY` leaves that comparator `unsupported` and the exit code at 2. The report is still printed. Details, the fixture, and the exit table are in [packages/e2e-demo/README.md](packages/e2e-demo/README.md).

The report repeats the Prove non-claims:

- Nimble score ≠ gate held
- high noul ≠ safe
- this is not AdaptiveSandbox
- this is not open Jev

## Checked-in runs

[`runs/`](runs/README.md) is the fail-closed eval snapshot reviewers can re-read without starting Ollama or Nimble. [`runs/fail-closed-unsupported.json`](runs/fail-closed-unsupported.json) is the review record. [`runs/e2e-demo-fail-closed.json`](runs/e2e-demo-fail-closed.json) is the `e2e-demo` stdout it was projected from.

Nimble score ≠ gate held. Live flip/ECE was deferred until this artifact (no Soft-PASS substitute). On that missing-scorer run the decision is `unsupported`, the gate path is deny-closed, `flip_rate` and `ece` are null, and `soft_pass` is false. Soft-PASS was refused.

## Scripts

```bash
npm install
npm test
npm run typecheck
npm run lint
npm run authority-flip:verify
npm run authority-flip
npm run --silent e2e-demo

python -m pip install -e "packages/gate-client[dev]" -e "packages/gate-enforcement[dev]" -e "packages/e2e-demo[dev]" -e "packages/claims-gate[dev]"
python -m pytest packages/claims-gate
python -m pytest packages/gate-client
python -m pytest packages/gate-enforcement
python -m pytest packages/e2e-demo
```

## License

MIT. See [LICENSE](LICENSE).
