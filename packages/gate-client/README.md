# gate-client

Python System-1 gate client. Before a tool call, it asks local Ollama Nimble for one **allow / deny / escalate** choice through TypeSafe’s official Python SDK (`typesafe-sdk`). It returns that decision. It does not run the tool.

Ollama **0.35 or newer** is required. Nimble’s decision API is `/v1/systemone`, and the SDK calls it. This package does not parse that HTTP response itself.

## Local SDK config

The SDK’s default base URL is TypeSafe cloud (`https://api.typesafe.ai`, model `jev-latest`). That host is the wrong target for this MVP. The gate always passes `base_url`, `api_key`, and `model` into `TypeSafeClient`. When the variables below are unset, those arguments are the local values, not the SDK cloud default.

```bash
export TYPESAFE_BASE_URL=http://localhost:11434
export TYPESAFE_API_KEY=ollama
export TYPESAFE_DEFAULT_MODEL=nimble
```

Ollama ignores the API key. The SDK still requires one, so `ollama` is the local value.

A base URL on `typesafe.ai` or any `*.typesafe.ai` host fail-closes to **deny** with `reasonCode: fail_closed_cloud_misconfigured` unless cloud is explicitly opted in:

```bash
export GATE_ALLOW_TYPESAFE_CLOUD=1
```

Opt-in does not change the default. You still set `TYPESAFE_BASE_URL` to the cloud root. Hosted Jev is not the supported path.

| Variable | Default in this package | Role |
| --- | --- | --- |
| `TYPESAFE_BASE_URL` | `http://localhost:11434` | SDK `base_url` |
| `TYPESAFE_API_KEY` | `ollama` | SDK `api_key` |
| `TYPESAFE_DEFAULT_MODEL` | `nimble` | SDK `model` |
| `GATE_ALLOW_TYPESAFE_CLOUD` | unset | Set to `1` to permit a TypeSafe cloud host |
| `GATE_CONFIDENCE_THRESHOLD` | `0.5` | Minimum SDK `confidence` (0 to 1) |
| `GATE_TIMEOUT_SECONDS` | `30` | Per-call SDK timeout. Retries are off |

Pull the model with `ollama pull nimble` on that Ollama server.

## Decision

`GateClient.decide` sends one state object and one choice question:

- `granted_policy`
- `tool_name`
- `args` with secret-like values replaced by `[REDACTED]`
- `context`, shortened to 2000 characters

The question criteria are `allow`, `deny`, and `escalate`. The decision is taken from the SDK `ChoiceAnswer` (`choice`, `probabilities`, `confidence`), not from a hand-parsed Ollama body.

```python
from gate_client import GateClient

decision = GateClient().decide(
    policy="May read files under /tmp.",
    tool_name="read_file",
    args={"path": "/tmp/note.txt"},
    context="The user asked for the note.",
)
print(decision.to_dict())
# {"choice": "allow", "probs": {"allow": 0.91, "deny": 0.05, "escalate": 0.04}, "reasonCode": "nimble_allow"}
```

`probs` is the SDK probability map. It is empty when the SDK did not return a choice.

| `reasonCode` | `choice` | When |
| --- | --- | --- |
| `nimble_allow` | `allow` | SDK chose allow at or above the confidence threshold |
| `nimble_deny` | `deny` | SDK chose deny at or above the threshold |
| `nimble_escalate` | `escalate` | SDK chose escalate at or above the threshold |
| `fail_closed_low_confidence` | `deny` | SDK confidence is below the threshold |
| `fail_closed_timeout` | `deny` | The SDK call timed out |
| `fail_closed_down` | `deny` | Connection failed, or the model/endpoint was not found |
| `fail_closed_cloud_misconfigured` | `deny` | Base URL is TypeSafe cloud and opt-in is off |
| `fail_closed_sdk_error` | `deny` | Any other SDK or HTTP failure |
| `fail_closed_invalid_response` | `deny` | The SDK answer was missing or not one of the three labels |
| `fail_closed_invalid_config` | `deny` | Threshold, timeout, URL, or API key could not be used |

Escalate is returned only when Nimble is up and selects `escalate` with enough confidence. Timeout, downtime, a cloud misconfiguration, and low confidence all deny. They do not allow and they do not escalate.

SDK `confidence` is how concentrated the probabilities are. It is not a claim that the decision is safe, and a high probability is not proof the gate held.

## Tests

```bash
python -m pip install -e "packages/gate-client[dev]"
python -m pytest packages/gate-client
```

Tests mock `TypeSafeClient`. They do not call Ollama.

## Out of scope

This package does not execute tools. The stub runner and observation log live in [`packages/gate-enforcement`](../gate-enforcement/README.md). The flip harness and live sandbox wiring are still out of scope here.
