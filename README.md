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

## Prove non-claims

- Nimble score ≠ gate held
- high noul ≠ safe
- this is not AdaptiveSandbox

## Layout

- `packages/authority-flip` is a stub for the flip harness. It has no metrics yet.
- `packages/gate-client` is the Python System-1 gate client (`typesafe-sdk` against local Ollama Nimble).
- `packages/gate-enforcement` is the Python enforcement seam, stub tool runner, and observation log.

## Scripts

```bash
npm install
npm test
npm run typecheck
npm run lint

python -m pip install -e "packages/gate-client[dev]"
python -m pytest packages/gate-client
python -m pytest packages/gate-enforcement
```

## License

MIT. See [LICENSE](LICENSE).
