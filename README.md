# s1-tool-gate

Per-tool-call authority gate. Before each tool call, a local Ollama `/v1/systemone` Nimble score chooses **allow / deny / escalate** from the granted policy, the tool name, redacted arguments, and a short context.

## Composition

The System-1 gate sits **in front of AdaptiveSandbox/gondolin**. It replaces the recommend slot. It is never the security root.

This gate is **not a substitute** for AdaptiveSandbox/gondolin.

## Fail-closed

Fail-closed → **deny**. When Ollama is down, timed out, or below the confidence threshold, the gate denies. Escalate only when Nimble is up and chooses grey.

## Prove non-claims

- Nimble score ≠ gate held
- high noul ≠ safe
- this is not AdaptiveSandbox

## Layout

- `packages/authority-flip` is a stub for the flip harness. It has no metrics yet.
- `packages/gate-client` is an empty Python package stub for the gate client. It has no SDK wiring and no Ollama calls.

## Scripts

```bash
npm install
npm test
npm run typecheck
npm run lint
```

## License

MIT. See [LICENSE](LICENSE).
