# Scope mapping

A partner agent with a valid token calls kaia-mcp tools. The gate allows a tool only when the token's `scope` contains that tool's required kaia scope. It denies everything else, including tools it does not know.

## Sub-features

- `scope-read-allow`: `kaia:read` allows read tools (`get_kaia_balance`, `read_contract`).
- `scope-deny`: `kaia:read` alone denies `encode_function_data` with `claims_insufficient_scope`.
- `scope-encode-allow`: `kaia:read kaia:encode` allows `encode_function_data`.
- `scope-unknown-tool`: a tool missing from the kaia fixture (`transfer_kaia`) denies with `claims_unknown_tool`.
- `scope-authz-file`: the same allow works when the header value comes from `--authorization-file` instead of `S1_AUTHORIZATION`.

## How to get to it (user POV)

- Get an access token from the IdP with the needed scopes. Here, `testkit mint --scope ...` stands in for the IdP.
- Call `python -m claims_gate decide --tool <name>` with `S1_AUTHORIZATION="Bearer <token>"` before forwarding the MCP `tools/call`.
- Or put the header value in a mode-600 file and pass `--authorization-file <path>`.

## Driving it with verify-s1-tool-gate

Preconditions:

- `doctor.sh` exits 0 for this run.

- **Run.** `.cursor/skills/verify-s1-tool-gate/helpers/drive.sh scope-mapping`
- **Read allow.** A `kaia:read` token with `get_kaia_balance` gives `allow claims_allow`. With `read_contract` it also gives `allow claims_allow`. The JSON has `"requiredScope": "kaia:read"` and `"subject": "partner-agent-1"`.
- **Deny by scope.** The same token with `encode_function_data` gives `deny claims_insufficient_scope`.
- **Encode allow.** A `kaia:read kaia:encode` token with `encode_function_data` gives `allow claims_allow`.
- **Unknown tool.** The same token with `transfer_kaia` gives `deny claims_unknown_tool`, and `requiredScope` is `null`.
- **Authorization file.** `Bearer <kaia:read token>` written to a mode-600 file under the run's scratch dir, passed with `--authorization-file`, gives `allow claims_allow` for `get_kaia_balance`. The file is deleted right after.
- **Proof.** The files `read-allow.json`, `read-allow-contract.json`, `read-denied-encode.json`, `encode-allow.json`, `unknown-tool.json`, and `authz-file-allow.json` exist under `evidence/<run-id>/scope-mapping/`. Every `.exit` file is `0`.

## Gotchas

- `decide` exits 0 for any decision, including deny. Assert on `choice` and `reasonCode`, not on the exit code.
- A scope check is exact string membership. `kaia:read` does not imply `kaia:encode`.
- The fixture is copied from kaia-mcp `db76732`. A tool added to kaia-mcp later denies as unknown until the fixture is updated.
