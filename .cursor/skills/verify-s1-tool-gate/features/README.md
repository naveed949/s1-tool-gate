# s1-tool-gate claims-gate verification map

This directory is the maintained source for verifying the user-facing behavior of the OIDC/OAuth claims gate (`packages/claims-gate`) in front of kaia-mcp's tools. Read this index before driving, then follow the matching feature file.

## Baseline preconditions

- Launch with `.cursor/skills/verify-s1-tool-gate/helpers/launch.sh` so the run has its own TEST-ONLY key and `jwks.json` under `/tmp/s1-verify-<run-id>/kit`.
- `doctor.sh` must exit 0. It checks that `claims_gate` is imported from this checkout, and that the fixture is kaia-mcp `db76732` with 26 tools and wallet tool `generate_wallet`.
- Trust anchors for every `decide` call:
  - issuer `https://idp.test.invalid`
  - audience `kaia-mcp`
  - `--jwks /tmp/s1-verify-<run-id>/kit/jwks.json`

## Driving conventions

- Invoke helpers from the repo root.
- Commands are literal. Keep tool names, scope strings, and reason codes unchanged.
- Pass tokens through `S1_AUTHORIZATION`, never on argv.
- Every feature starts from the baseline. No feature mutates shared state, and every token is minted fresh.
- `live-proxy` is the only feature that starts processes and uses the network. It starts and stops its own kaia-mcp and proxies inside one drive. Its tokens come from kaia-mcp's demo IdP, not the TEST-ONLY kit.

## Proof and skip reporting

- Each case records `decide` stdout (`<case>.json`) and its exit code (`<case>.exit`) under `.cursor/skills/verify-s1-tool-gate/evidence/<run-id>/<feature>/`.
- A decision proof is the literal `choice` plus `reasonCode`. For the demo, the proof also includes the observed `sideEffect` and the wallet stub call count.
- No minted token may appear in evidence.
- Report an unreachable entry point with the command tried and the unmet precondition. Do not count a skipped entry point as verified through another path.

## Feature entry contract

Each feature file starts with an H1 and one paragraph. Then come exactly four H2 sections, in this order:

1. `Sub-features`
2. `How to get to it (user POV)`
3. `Driving it with verify-s1-tool-gate`, which starts with `Preconditions:`
4. `Gotchas`

## Features

- [Scope mapping](./scope-mapping.md): a verified token's scopes allow mapped kaia tools and deny unmapped scopes and unknown tools.
- [Token validation](./token-validation.md): missing, malformed, expired, wrong-audience, wrong-issuer, forged, and missing-claim tokens fail closed.
- [Wallet escalation](./wallet-escalation.md): `generate_wallet` escalates (or denies) and is never allowed.
- [kaia enforcement demo](./kaia-enforcement-demo.md): the 22 golden cases run through the gate and the enforcement seam, and the stub runs only on allow.
- [Live proxy](./live-proxy.md): `python -m claims_gate proxy` in front of a real, running kaia-mcp. Allowed reads return chain data. Denies and wallet escalations never reach kaia-mcp. Forged, wrong-audience, expired, and revoked tokens are refused, and the proxy will not start on tool-scope drift.
