---
name: verify-s1-tool-gate
description: Verify s1-tool-gate's OIDC/OAuth claims gate (packages/claims-gate) by driving its CLI with run-time TEST-ONLY JWTs against the kaia-mcp tool/scope fixture, and its live reverse proxy in front of a real kaia-mcp. Use when proving claim-to-policy decisions (allow, deny-by-scope, expired, wrong audience/issuer, forged, unauthenticated), wallet escalation, the gate-in-front-of-enforcement demo, or live proxy enforcement (introspection revocation, drift refusal, nothing denied reaches kaia-mcp).
---

# Verify s1-tool-gate (claims gate)

Primary surface: the `python -m claims_gate` CLI (`tools`, `testkit`, `decide`, `demo`, `proxy`). A partner integration calls the same `ClaimsGate.evaluate` that `decide` wraps. Other surfaces are not driven here. The Nimble gate client needs live Ollama. The TypeScript authority-flip harness and `e2e-demo` have their own tests and `runs/`.

The decision CLI is short-lived, with no server or port. The `live-proxy` feature is the exception. Its drive runs `packages/claims-gate/e2e/live_kaia.py`, which starts kaia-mcp and several proxies on ephemeral `127.0.0.1` ports and stops them before it returns. kaia-mcp comes from `S1_VERIFY_KAIA_DIR` (or `KAIA_MCP_DIR`) as a local checkout, or else from a clone of the commit pinned in the script. It needs `git`, `node>=20`, `npm`, and egress to GitHub and the Kaia public RPC. Each run gets its own scratch dir `/tmp/s1-verify-<run-id>/`, holding a TEST-ONLY RSA key and its `jwks.json`. Two runs can coexist if their run ids differ. They share the repo `.venv` (override with `S1_VERIFY_VENV`).

## Launch

From the repo root:

```bash
export S1_VERIFY_RUN_ID="manual-$(date +%Y%m%dT%H%M%S)-$$"
.cursor/skills/verify-s1-tool-gate/helpers/launch.sh
```

`launch.sh` creates `.venv` if missing. It then reinstalls `packages/gate-client`, `packages/gate-enforcement`, and `packages/claims-gate[dev]` as editable installs, so the run uses this checkout. It runs `python -m claims_gate testkit init --dir /tmp/s1-verify-<run-id>/kit` and writes `instance.json` next to it.

Ready signal: the last line is `ready: claims_gate CLI ok (26 kaia tools)`.

Teardown is `cleanup.sh` (see Cleanup).

## Doctor

Run before the first drive, after any failed drive, and in a fresh shell:

```bash
.cursor/skills/verify-s1-tool-gate/helpers/doctor.sh
```

Doctor is read-only. It requires all of these:
- `instance.json` exists.
- The TEST-ONLY key exists with mode `600`.
- `jwks.json` exists.
- `claims_gate` imports from this checkout's `packages/claims-gate/src`, not a stale install elsewhere.
- `gate_enforcement` imports.
- The kaia fixture reports source `...253d6c8:src/auth/scopes.ts`, 26 tools, and wallet tools `["generate_wallet"]`.
- `python -m claims_gate proxy --help` works.

Doctor also prints the `live-proxy` prerequisites (`node`, `npm`, `git`, and the kaia-mcp source). It does not fail on them, because the other features do not need them.

If doctor fails, run cleanup and launch again. Do not drive.

## Drive

```bash
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh scope-mapping
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh token-validation
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh wallet-escalation
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh kaia-enforcement-demo
S1_VERIFY_KAIA_DIR=/path/to/kaia-mcp .cursor/skills/verify-s1-tool-gate/helpers/drive.sh live-proxy   # omit the var to clone the pinned commit
```

`drive.sh` is the partner path:
1. Mint a JWT with `python -m claims_gate testkit mint --dir <kit> [--scope S] [--aud A] [--iss I] [--exp-in N] [--sub ''] [--untrusted]`.
2. Pass it as `S1_AUTHORIZATION="Bearer <jwt>"` to `python -m claims_gate decide --jwks <kit>/jwks.json --issuer https://idp.test.invalid --audience kaia-mcp --tool <kaia tool>`.
3. Assert the literal `choice` and `reasonCode`.

Stable handles:
- Tool names are kaia-mcp's real ones (`get_kaia_balance`, `read_contract`, `encode_function_data`, `generate_wallet`).
- Scopes are `kaia:read`, `kaia:encode`, `kaia:wallet`.
- Reason codes are the `claims_*` values in `packages/claims-gate/README.md`.

`live-proxy` is the deployment path. A device-flow login against kaia-mcp's demo IdP produces a real kaia JWT. MCP JSON-RPC then goes through the proxy, and the drive asserts all 13 checks in `summary.json`.

Follow every entry point listed in the matching `features/` file.

## Evidence

Named location: `.cursor/skills/verify-s1-tool-gate/evidence/<run-id>/<feature>/` (gitignored). Each case writes `<case>.json`, the exact `decide` stdout, and `<case>.exit`, the exit code. The demo feature writes `demo-report.json` and `demo-report-wallet-deny.json`. `live-proxy` writes `summary.json`, `kaia-mcp.log`, `proxy-*.log`, `audit-*.jsonl`, `setup.log`, `live-e2e.stdout`, and `live-e2e.exit`.

Proof standards:
- Drive the CLI the way a partner would: a real signed JWT, verified against the JWKS. Do not call `ToolPolicy.decide` with hand-built `VerifiedClaims` as a substitute.
- Capture the decision and the observed effect. In the demo, `sideEffect` comes from the enforcement seam's stub invocation count, and `walletStubCalls` must be 0.
- Tokens never go into evidence. `drive.sh` searches every evidence file for every token it minted and fails on any match.
- In the CLI features, the JWTs and keys are TEST-ONLY. They are created at run time and deleted by cleanup. No network or real IdP is involved, and the issuer uses the `.invalid` TLD.
- In `live-proxy`, tokens come from kaia-mcp's in-process demo IdP. Its signing key lives only in that process. The introspection secret is random per run and is never written to evidence. The e2e's `no-token-in-logs` check scans every log for each token and the secret.
- "Never reached kaia-mcp" is proven from kaia-mcp's own log: there must be zero `msg=Tool call tool=<name>` lines for that tool. The proxy's audit `forwarded=false` is not enough on its own.

After cleanup, confirm `evidence/<run-id>/` still exists.

## Cleanup

```bash
.cursor/skills/verify-s1-tool-gate/helpers/cleanup.sh
```

Cleanup removes `/tmp/s1-verify-<run-id>/` (including the TEST-ONLY private key) and the `/tmp/s1-verify-current` pointer if it names this run. It does not touch `evidence/`. There are no processes to stop. Doctor and drive never create the scratch dir; only launch does.

## Helpers

All helpers are executable. Invoke them from the repo root. They use `S1_VERIFY_RUN_ID`, or else the run id in `/tmp/s1-verify-current`.

| Script | Invocation |
|---|---|
| Launch | `.cursor/skills/verify-s1-tool-gate/helpers/launch.sh` |
| Doctor | `.cursor/skills/verify-s1-tool-gate/helpers/doctor.sh` |
| Drive | `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh <scope-mapping\|token-validation\|wallet-escalation\|kaia-enforcement-demo\|live-proxy>` |
| Cleanup | `.cursor/skills/verify-s1-tool-gate/helpers/cleanup.sh` |

`helpers/common.sh` is sourced by the others. Do not run it directly.
