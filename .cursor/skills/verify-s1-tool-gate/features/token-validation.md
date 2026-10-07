# Token validation

The gate verifies the bearer token before it looks at scopes. A missing token, a malformed token, a forged token, the wrong issuer or audience, an expired token, or a missing required claim all deny. No such path ever allows.

## Sub-features

- `auth-missing`: no `Authorization` gives `claims_unauthenticated`.
- `auth-non-bearer`: `Basic ...` gives `claims_unauthenticated`.
- `auth-malformed`: `Bearer not-a-jwt` gives `claims_invalid_token`.
- `auth-expired`: `exp` in the past gives `claims_expired`.
- `auth-audience`: `aud` other than `kaia-mcp` gives `claims_audience_mismatch`.
- `auth-issuer`: an untrusted `iss` gives `claims_issuer_mismatch`.
- `auth-forged`: a token signed by a key outside the JWKS (same `kid`) gives `claims_invalid_token`.
- `auth-missing-claim`: a token with no `sub` gives `claims_missing_claim`.
- `config-missing-jwks`: an unreadable `--jwks` file exits `2` and prints no decision.

## How to get to it (user POV)

- Send a tool call with no token, a wrong scheme, or a bad token. Here, `testkit mint` flags (`--exp-in -5`, `--aud`, `--iss`, `--untrusted`, `--sub ''`) produce the bad tokens.
- Call `python -m claims_gate decide` with that `S1_AUTHORIZATION`, or with it unset.

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0 for this run.

- **Run.** `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh token-validation`
- **Missing.** With `S1_AUTHORIZATION` unset, `get_kaia_balance` gives `deny claims_unauthenticated`.
- **Non-bearer.** `Basic dXNlcjpwYXNz` gives `deny claims_unauthenticated`.
- **Malformed.** `Bearer not-a-jwt` gives `deny claims_invalid_token`.
- **Expired.** `mint --exp-in -5` gives `deny claims_expired`.
- **Wrong audience.** `mint --aud other-api` gives `deny claims_audience_mismatch`.
- **Wrong issuer.** `mint --iss https://evil.test.invalid` gives `deny claims_issuer_mismatch`.
- **Forged.** `mint --untrusted` gives `deny claims_invalid_token`.
- **Missing claim.** `mint --sub ''` gives `deny claims_missing_claim`.
- **Missing JWKS.** `decide --jwks <nonexistent>` exits `2`, stdout is empty, and stderr says `bad config`.
- **Proof.** The files `missing-jwks.exit` (containing `2`), `unauthenticated.json`, `non-bearer.json`, `malformed.json`, `expired.json`, `wrong-audience.json`, `wrong-issuer.json`, `forged-signature.json`, and `missing-sub.json` exist under `evidence/<run-id>/token-validation/`. The token-leak check reports no hits.

## Gotchas

- `alg: none`, an unknown `kid`, and a missing `exp` or `scope` are not mintable through `testkit mint`. The golden evals (`kaia_golden.json`, `python -m pytest packages/claims-gate`) and the `kaia-enforcement-demo` feature cover them.
- Live drives use the wall clock and zero leeway. Do not use `--exp-in 0` for an "expires now" case, because it races the clock. The fixed-clock golden case `expired-at-boundary` covers that boundary.
- `subject` is `null` on every token failure. That is expected, not a missing field.
