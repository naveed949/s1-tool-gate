---
name: verify-s1-tool-gate
description: Verify s1-tool-gate's OIDC/OAuth claims gate (packages/claims-gate) by driving its CLI with run-time TEST-ONLY JWTs against the kaia-mcp tool/scope fixture. Use when proving claim-to-policy decisions (allow, deny-by-scope, expired, wrong audience/issuer, forged, unauthenticated), wallet escalation, or the gate-in-front-of-enforcement demo.
---

# Verify s1-tool-gate (claims gate)

Primary surface: the `python -m claims_gate` CLI (`tools`, `testkit`, `decide`, `demo`). A partner integration calls the same `ClaimsGate.evaluate` that `decide` wraps. Other surfaces are not driven here. The Nimble gate client needs live Ollama. The TypeScript authority-flip harness and `e2e-demo` have their own tests and `runs/`.

The CLI is short-lived. There is no server or port. Each run gets its own scratch dir `/tmp/s1-verify-<run-id>/`, holding a TEST-ONLY RSA key and its `jwks.json`. Two runs can coexist if their run ids differ. They share the repo `.venv` (override with `S1_VERIFY_VENV`).

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
- The kaia fixture reports source `...db76732:src/auth/scopes.ts`, 26 tools, and wallet tools `["generate_wallet"]`.

If doctor fails, run cleanup and launch again. Do not drive.

## Drive

```bash
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh scope-mapping
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh token-validation
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh wallet-escalation
.cursor/skills/verify-s1-tool-gate/helpers/drive.sh kaia-enforcement-demo
```

`drive.sh` is the partner path:
1. Mint a JWT with `python -m claims_gate testkit mint --dir <kit> [--scope S] [--aud A] [--iss I] [--exp-in N] [--sub ''] [--untrusted]`.
2. Pass it as `S1_AUTHORIZATION="Bearer <jwt>"` to `python -m claims_gate decide --jwks <kit>/jwks.json --issuer https://idp.test.invalid --audience kaia-mcp --tool <kaia tool>`.
3. Assert the literal `choice` and `reasonCode`.

Stable handles:
- Tool names are kaia-mcp's real ones (`get_kaia_balance`, `read_contract`, `encode_function_data`, `generate_wallet`).
- Scopes are `kaia:read`, `kaia:encode`, `kaia:wallet`.
- Reason codes are the `claims_*` values in `packages/claims-gate/README.md`.

Follow every entry point listed in the matching `features/` file.

## Evidence

Named location: `.cursor/skills/verify-s1-tool-gate/evidence/<run-id>/<feature>/` (gitignored). Each case writes `<case>.json`, the exact `decide` stdout, and `<case>.exit`, the exit code. The demo feature writes `demo-report.json` and `demo-report-wallet-deny.json`.

Proof standards:
- Drive the CLI the way a partner would: a real signed JWT, verified against the JWKS. Do not call `ToolPolicy.decide` with hand-built `VerifiedClaims` as a substitute.
- Capture the decision and the observed effect. In the demo, `sideEffect` comes from the enforcement seam's stub invocation count, and `walletStubCalls` must be 0.
- Tokens never go into evidence. `drive.sh` searches every evidence file for every token it minted and fails on any match.
- The JWTs and keys are TEST-ONLY. They are created at run time and deleted by cleanup. No network or real IdP is involved, and the issuer uses the `.invalid` TLD.

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
| Drive | `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh <scope-mapping\|token-validation\|wallet-escalation\|kaia-enforcement-demo>` |
| Cleanup | `.cursor/skills/verify-s1-tool-gate/helpers/cleanup.sh` |

`helpers/common.sh` is sourced by the others. Do not run it directly.
