# gate-enforcement

Enforcement seam and observation log for the System-1 gate.

`packages/gate-client` returns a decision (`choice`, `probs`, `reasonCode`). This package takes that decision as an input and decides whether a **stub tool** runs. It does not call Ollama, does not score Nimble, and does not reimplement fail-closed. A fail-closed decision arrives already as `choice: deny`.

A logged choice is the injected decision. It is not proof the gate held. **Nimble score ≠ gate held.** This package is not AdaptiveSandbox qualification.

## Rules

| Injected `choice` | Granted-authority fixture | Stub tool | Escalation channel | `sideEffect` |
| --- | --- | --- | --- | --- |
| `deny` | any | not called | not used | `false` |
| `escalate` | any | not called | one submission | `false` |
| `allow` | matches the request | called once | not used | `true` when the stub's invocation count increased |
| `allow` | does not match | not called | not used | `false` |

Escalate is a grey handoff to the escalation channel stub. It is not an allow, and it does not run the tool.

`sideEffect` is computed from the stub runner's invocation count before and after `enforce`. The flag is not set from `choice`. An allow outside the fixture is logged with `choice: allow` and `sideEffect: false`.

## Granted-authority fixture

`GrantedAuthority` admits a request when `policy` and `tool_name` match exactly. That is the MVP fixture for "effect only inside granted authority." Argument checks and real sandbox mediation are out of scope.

## Observation log schema

Canonical schema: [`observation-log.schema.json`](observation-log.schema.json) (JSON Schema draft 2020-12, `schemaVersion` **1**).

Each `enforce` call appends one entry, including deny and escalate. Fields:

| Field | Type | Source |
| --- | --- | --- |
| `schemaVersion` | `1` | This schema |
| `choice` | `allow` \| `deny` \| `escalate` | Copied from the injected `GateDecision` |
| `probs` | object, label → number | Copied from the injected `GateDecision`. May be `{}` on a fail-closed deny |
| `reasonCode` | string | Copied from the injected `GateDecision` |
| `sideEffect` | boolean | **Observed.** `true` only if the stub runner was invoked during this call |
| `toolName` | string | `ToolRequest.tool_name` |
| `withinGrantedAuthority` | boolean | `true` when the request matched the fixture |

`choice`, `probs`, and `reasonCode` are the decision. `sideEffect` is a separate observation of the stub. The log does not include raw tool arguments.

### Deny

Deny inside the fixture still does not run the stub:

```json
{
  "schemaVersion": 1,
  "choice": "deny",
  "probs": {"allow": 0.02, "deny": 0.96, "escalate": 0.02},
  "reasonCode": "nimble_deny",
  "sideEffect": false,
  "toolName": "read_file",
  "withinGrantedAuthority": true
}
```

### Escalate

Grey. The stub does not run. `sideEffect` stays false.

```json
{
  "schemaVersion": 1,
  "choice": "escalate",
  "probs": {"allow": 0.2, "deny": 0.1, "escalate": 0.7},
  "reasonCode": "nimble_escalate",
  "sideEffect": false,
  "toolName": "read_file",
  "withinGrantedAuthority": true
}
```

### Allow inside the fixture

```json
{
  "schemaVersion": 1,
  "choice": "allow",
  "probs": {"allow": 0.91, "deny": 0.05, "escalate": 0.04},
  "reasonCode": "nimble_allow",
  "sideEffect": true,
  "toolName": "read_file",
  "withinGrantedAuthority": true
}
```

## Usage

Install the gate client first so `gate_client` is importable. This package does not call it.

```bash
python -m pip install -e packages/gate-client -e "packages/gate-enforcement[dev]"
```

```python
from gate_client import GateDecision
from gate_enforcement import (
    EnforcementSeam,
    EscalationChannel,
    GrantedAuthority,
    ObservationLog,
    StubToolRunner,
    ToolRequest,
)

authority = GrantedAuthority(policy="May read files under /tmp.", tool_name="read_file")
request = ToolRequest(
    tool_name="read_file",
    policy="May read files under /tmp.",
    args={"path": "/tmp/note.txt"},
    context="The user asked for the note.",
)
decision = GateDecision(
    choice="allow",
    probs={"allow": 0.91, "deny": 0.05, "escalate": 0.04},
    reason_code="nimble_allow",
)

log = ObservationLog()
runner = StubToolRunner()
seam = EnforcementSeam(runner, log=log, escalation=EscalationChannel())
result = seam.enforce(decision, request, authority)
assert runner.invocation_count == 1
assert result.record.to_dict()["sideEffect"] is True
```

Pass any callable with the `ToolRequest` signature. The seam wraps it in a `StubToolRunner` so the invocation is still observable. Deny and escalate do not call that callable.

## Tests

```bash
python -m pytest packages/gate-enforcement
```

Tests inject `GateDecision` values. They do not call Ollama.

## Out of scope

Flip harness, AdaptiveSandbox or gondolin mediation, and live Ollama are not part of this package.

## Non-claims

- Nimble score ≠ gate held
- This is not AdaptiveSandbox
