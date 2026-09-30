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

The flip harness does not call the gate client or the enforcement seam.

## Scripts

```bash
npm install
npm test
npm run typecheck
npm run lint
npm run authority-flip:verify
npm run authority-flip

python -m pip install -e "packages/gate-client[dev]"
python -m pytest packages/gate-client
python -m pytest packages/gate-enforcement
```

## License

MIT. See [LICENSE](LICENSE).
