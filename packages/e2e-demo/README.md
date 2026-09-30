# e2e-demo

One scripted path that composes the packages already in this repo:

1. Load the pinned pairs from [`packages/authority-flip`](../authority-flip/README.md) and check the manifest hash.
2. Ask [`packages/gate-client`](../gate-client/README.md) for an allow / deny / escalate decision on each side. The client uses the TypeSafe Python SDK against local Ollama Nimble.
3. Run each decision through [`packages/gate-enforcement`](../gate-enforcement/README.md). The stub runs only for an allow that matches the granted-authority fixture. The observation log records whether it ran.
4. Run the authority-flip harness and copy its flip rate and ECE into the same report.

`npm test` mocks the gate client, the enforcement result, and the flip backends. It does not start Ollama. The live command is below.

## What this shows

The three packages can run as one path: pinned cases in, decisions and stub observations and a flip report out.

## What this does not show

- Nimble score ≠ gate held
- high noul ≠ safe
- this is not AdaptiveSandbox
- this is not open Jev

A Nimble choice in `decisions` is the gate client's answer. `observations[].entry.sideEffect` is whether the stub ran. Those are different fields. The flip section is the authority-flip harness, which scores Nimble with its own HTTP call. It is not computed from the gate decisions.

## Command

Ollama **0.35 or newer** must be running locally. Pull `nimble` on that server. The flip section also asks for base Qwen (`qwen2.5:7b`, or `AUTHORITY_FLIP_QWEN_MODEL`) and, when `AUTHORITY_FLIP_JUDGE_API_KEY` is set, the frontier judge.

```bash
export TYPESAFE_BASE_URL=http://localhost:11434
export TYPESAFE_API_KEY=ollama
export TYPESAFE_DEFAULT_MODEL=nimble
python -m pip install -e packages/gate-client -e packages/gate-enforcement
npm run --silent e2e-demo
```

`npm run --silent e2e-demo` is the single live command. `--silent` keeps npm's script banner off stdout, so the process prints one JSON document and nothing else. Install the Python packages once so `typesafe-sdk` and `gate_client` import. The Node process sets `PYTHONPATH` to this package's `python/` directory and the two package `src/` trees.

When `AUTHORITY_FLIP_OLLAMA_BASE_URL` is unset and `TYPESAFE_BASE_URL` is set, the harness uses `TYPESAFE_BASE_URL`. When both are unset, the harness keeps its own default, `http://127.0.0.1:11434`. The gate client default is `http://localhost:11434`. Set `TYPESAFE_BASE_URL` so both paths use the same host. When `AUTHORITY_FLIP_NIMBLE_MODEL` is unset and `TYPESAFE_DEFAULT_MODEL` is set, the harness uses that model. An explicit flip variable wins.

| Variable | Role |
| --- | --- |
| `TYPESAFE_BASE_URL` | Gate client base URL. Also the flip harness base URL when the flip variable is unset. `http://localhost:11434` for local Ollama. |
| `TYPESAFE_API_KEY` | SDK API key. Ollama ignores it. Use `ollama`. |
| `TYPESAFE_DEFAULT_MODEL` | Gate model, and the Nimble flip model when `AUTHORITY_FLIP_NIMBLE_MODEL` is unset. `nimble`. |
| `GATE_CONFIDENCE_THRESHOLD` | Gate client threshold. Default `0.5`. |
| `GATE_TIMEOUT_SECONDS` | Gate client timeout. Default `30`. |
| `AUTHORITY_FLIP_OLLAMA_BASE_URL` | Optional override for the flip harness only. |
| `AUTHORITY_FLIP_QWEN_MODEL` | Base chat model. Default `qwen2.5:7b`. |
| `AUTHORITY_FLIP_JUDGE_API_KEY` | Optional. Unset leaves the judge `unsupported`. |
| `E2E_DEMO_PYTHON` | Python executable. Default `python3`. |

## When Ollama is down

The gate client fail-closes. Each decision is `choice: deny` with `reasonCode: fail_closed_down` (or another `fail_closed_*` code). `gate.status` is `unavailable`. The stub does not run, so `sideEffect` is false. That observation is the seam recording a deny. It is not a scored Nimble deny.

The flip harness marks `nimble-ollama` and `base-qwen` `unsupported`. `flipRate`, `rawFlipRate`, `ece`, and `calibration` are null. The command still prints the report, and it exits non-zero. Null metrics stay null. This package does not fill them from the fail-closed denies.

`python -m e2e_demo` exits 0 when it managed to write its fragment, including `status: unavailable`. The demo command does not treat that as a pass. It reads `gate.status`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | `gate.status` is `ok` and every flip comparator is `ok` |
| 2 | The gate path is `unavailable` or a flip comparator is `unsupported`, and nothing is `failed` |
| 1 | The pair hash does not match, the gate path `failed`, a flip comparator `failed`, or the report could not be built |

Exit 0 needs Nimble, base Qwen, and the frontier judge all scored, and every gate decision to be `nimble_allow`, `nimble_deny`, or `nimble_escalate`. A missing judge key or a missing Qwen tag is exit 2. The report is still printed. `unsupported` is not a pass. The same rule is documented for `npm run authority-flip`.

A hash mismatch prints the error on stderr and does not print a report. Gate and flip are not called.

## Report

Schema: [`schema/report.schema.json`](schema/report.schema.json) (`e2e-demo.report.v1`).

| Field | Source |
| --- | --- |
| `nonClaims` | The four sentences in [What this does not show](#what-this-does-not-show) |
| `dataset` | Pinned dataset id, path, sha256, byte length, pair count |
| `gate` | `ok`, `unavailable`, or `failed`, plus notes |
| `decisions` | One `{pairId, side, gold, decision}` per side. `decision` is `GateDecision.to_dict()`: `choice`, `probs`, `reasonCode` |
| `observations` | One `{pairId, side, entry}` per side. `entry` is an [observation log](../gate-enforcement/observation-log.schema.json) object |
| `flipSummary` | `status`, `flipRate`, `rawFlipRate`, and `ece` copied from each comparator in `flip` |
| `flip` | The full [`authority-flip.report.v1`](../authority-flip/schema/report.schema.json) document, including ECE bins |

`gold` is the pinned label, so a reader can see it next to the decision. It is not an input to flip rate. Flip rate and ECE are only the numbers inside `flip` and the copy in `flipSummary`.

Pair id and side sit outside `entry` so the observation object stays on the enforcement schema.

### Granted-authority fixture

For each side the fixture is that side's policy text and tool name. The request uses the same policy and tool name, so `withinGrantedAuthority` is true. Allow calls the stub once. Deny and escalate do not. Escalate is handed to the escalation-channel stub. Argument checks are outside this seam, same as `gate-enforcement`. An allow whose gold label is deny still runs the stub. The observation records that. It does not rewrite the gold label.

## Tests

```bash
npm test
python -m pip install -e packages/gate-client -e packages/gate-enforcement -e "packages/e2e-demo[dev]"
python -m pytest packages/e2e-demo
```

`npm test` injects the gate path and the flip report, and it drives the flip harness with a mock `fetch` that fails the Ollama probe. `pytest` uses a fake `GateClient` and the real enforcement seam. Neither suite calls Ollama.

## Out of scope

Production AdaptiveSandbox or gondolin wiring, cascades, and fine-tuning. This package does not modify the gate client, the seam, or the flip metrics.
