"""Enforcement seam tests. Decisions are injected. Ollama is not called."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from gate_client.decision import ChoiceLabel, GateDecision, ReasonCode, reason_for_choice

from gate_enforcement import (
    OBSERVATION_LOG_FIELDS,
    OBSERVATION_SCHEMA_VERSION,
    EnforcementSeam,
    EscalationChannel,
    GrantedAuthority,
    ObservationLog,
    ObservationRecord,
    StubToolRunner,
    ToolRequest,
)

POLICY = "May read files under /tmp."
TOOL = "read_file"

_PROBS: dict[str, dict[str, float]] = {
    "allow": {"allow": 0.91, "deny": 0.05, "escalate": 0.04},
    "deny": {"allow": 0.02, "deny": 0.96, "escalate": 0.02},
    "escalate": {"allow": 0.20, "deny": 0.10, "escalate": 0.70},
}

_PACKAGE = Path(__file__).resolve().parents[1]


def _decision(choice: ChoiceLabel, probs: dict[str, float] | None = None, reason: str | None = None) -> GateDecision:
    return GateDecision(
        choice=choice,
        probs=dict(_PROBS[choice] if probs is None else probs),
        reason_code=reason_for_choice(choice).value if reason is None else reason,
    )


@pytest.fixture
def granted_authority() -> GrantedAuthority:
    return GrantedAuthority(policy=POLICY, tool_name=TOOL)


@pytest.fixture
def inside(granted_authority: GrantedAuthority) -> ToolRequest:
    return ToolRequest(
        tool_name=granted_authority.tool_name,
        policy=granted_authority.policy,
        args={"path": "/tmp/note.txt"},
        context="The user asked for the note.",
    )


@pytest.fixture
def runner() -> StubToolRunner:
    return StubToolRunner()


@pytest.fixture
def log() -> ObservationLog:
    return ObservationLog()


@pytest.fixture
def channel() -> EscalationChannel:
    return EscalationChannel()


@pytest.fixture
def seam(runner: StubToolRunner, log: ObservationLog, channel: EscalationChannel) -> EnforcementSeam:
    return EnforcementSeam(runner, log=log, escalation=channel)


def test_deny_does_not_call_stub_and_logs_no_side_effect(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    log: ObservationLog,
    channel: EscalationChannel,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    decision = _decision("deny")

    result = seam.enforce(decision, inside, granted_authority)

    assert runner.invocation_count == 0
    assert runner.invocations == []
    assert channel.submissions == []
    assert result.tool_result is None
    assert result.record.side_effect is False
    entry = result.record.to_dict()
    assert entry["sideEffect"] is False
    assert entry["choice"] == "deny"
    assert entry["probs"] == _PROBS["deny"]
    assert entry["reasonCode"] == "nimble_deny"
    assert log.to_list() == [entry]
    assert len(log) == 1


def test_escalate_does_not_call_stub_and_logs_no_side_effect(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    log: ObservationLog,
    channel: EscalationChannel,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    decision = _decision("escalate")

    result = seam.enforce(decision, inside, granted_authority)

    assert runner.invocation_count == 0
    assert result.tool_result is None
    assert len(channel.submissions) == 1
    notice = channel.submissions[0]
    assert notice.tool_name == TOOL
    assert notice.policy == POLICY
    assert notice.decision is decision
    entry = result.record.to_dict()
    assert entry["sideEffect"] is False
    assert entry["choice"] == "escalate"
    assert entry["probs"] == _PROBS["escalate"]
    assert entry["reasonCode"] == "nimble_escalate"
    assert entry["withinGrantedAuthority"] is True
    assert log.to_list() == [entry]


def test_allow_calls_stub_once_inside_granted_authority(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    channel: EscalationChannel,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    decision = _decision("allow")
    before = runner.invocation_count

    result = seam.enforce(decision, inside, granted_authority)

    assert runner.invocation_count == before + 1
    assert len(runner.invocations) == 1
    assert runner.invocations[0].tool_name == TOOL
    assert runner.invocations[0].args == {"path": "/tmp/note.txt"}
    assert channel.submissions == []
    assert result.tool_result == {"ok": True, "tool": TOOL}
    observed = runner.invocation_count > before
    entry = result.record.to_dict()
    assert entry["sideEffect"] is True
    assert entry["sideEffect"] is observed
    assert entry["choice"] == "allow"
    assert entry["probs"] == _PROBS["allow"]
    assert entry["reasonCode"] == "nimble_allow"
    assert entry["withinGrantedAuthority"] is True
    assert entry["toolName"] == TOOL


@pytest.mark.parametrize("choice", ["allow", "deny", "escalate"])
def test_log_records_choice_probs_and_observed_side_effect(
    choice: ChoiceLabel,
    seam: EnforcementSeam,
    runner: StubToolRunner,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    decision = _decision(choice)
    before = runner.invocation_count

    result = seam.enforce(decision, inside, granted_authority)

    observed = runner.invocation_count > before
    entry = result.record.to_dict()
    assert entry["choice"] == choice
    assert entry["probs"] == decision.probs
    assert entry["probs"] == _PROBS[choice]
    assert entry["reasonCode"] == decision.reason_code
    assert entry["sideEffect"] is observed
    assert entry["schemaVersion"] == OBSERVATION_SCHEMA_VERSION
    assert tuple(entry) == OBSERVATION_LOG_FIELDS
    if choice == "allow":
        assert runner.invocation_count == 1
        assert entry["sideEffect"] is True
    else:
        assert runner.invocation_count == 0
        assert entry["sideEffect"] is False


def test_three_choices_append_three_log_entries(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    log: ObservationLog,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    for choice in ("deny", "escalate", "allow"):
        seam.enforce(_decision(choice), inside, granted_authority)

    entries = log.to_list()
    assert [entry["choice"] for entry in entries] == ["deny", "escalate", "allow"]
    assert [entry["sideEffect"] for entry in entries] == [False, False, True]
    assert [entry["probs"] for entry in entries] == [_PROBS["deny"], _PROBS["escalate"], _PROBS["allow"]]
    assert runner.invocation_count == 1


def test_allow_outside_fixture_does_not_run_and_side_effect_stays_false(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    channel: EscalationChannel,
    granted_authority: GrantedAuthority,
) -> None:
    request = ToolRequest(
        tool_name="delete_file",
        policy=POLICY,
        args={"path": "/tmp/note.txt"},
    )
    decision = _decision("allow")

    result = seam.enforce(decision, request, granted_authority)

    assert runner.invocation_count == 0
    assert channel.submissions == []
    entry = result.record.to_dict()
    assert entry["choice"] == "allow"
    assert entry["sideEffect"] is False
    assert entry["withinGrantedAuthority"] is False
    assert entry["toolName"] == "delete_file"


def test_allow_with_different_policy_does_not_run(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    granted_authority: GrantedAuthority,
) -> None:
    request = ToolRequest(tool_name=TOOL, policy="May write anywhere.", args={})

    result = seam.enforce(_decision("allow"), request, granted_authority)

    assert runner.invocation_count == 0
    assert result.record.to_dict()["sideEffect"] is False
    assert result.record.to_dict()["choice"] == "allow"
    assert result.record.within_granted_authority is False


def test_observation_record_can_disagree_with_choice() -> None:
    record = ObservationRecord(
        choice="allow",
        probs=_PROBS["allow"],
        reason_code="nimble_allow",
        side_effect=False,
        tool_name=TOOL,
        within_granted_authority=False,
    )

    assert record.to_dict()["choice"] == "allow"
    assert record.sideEffect is False
    assert record.to_dict()["sideEffect"] is False


def test_fail_closed_deny_is_enforced_without_rescoring(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    decision = GateDecision(choice="deny", probs={}, reason_code=ReasonCode.FAIL_CLOSED_TIMEOUT.value)

    result = seam.enforce(decision, inside, granted_authority)

    assert runner.invocation_count == 0
    entry = result.record.to_dict()
    assert entry["choice"] == "deny"
    assert entry["probs"] == {}
    assert entry["reasonCode"] == "fail_closed_timeout"
    assert entry["sideEffect"] is False


def test_deny_and_escalate_do_not_call_a_raising_tool(
    log: ObservationLog,
    channel: EscalationChannel,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    def boom(_request: ToolRequest) -> Any:
        raise AssertionError("stub must not run")

    seam = EnforcementSeam(boom, log=log, escalation=channel)

    for choice in ("deny", "escalate"):
        result = seam.enforce(_decision(choice), inside, granted_authority)
        assert result.record.side_effect is False

    assert seam.runner.invocation_count == 0
    assert len(channel.submissions) == 1
    assert len(log) == 2


def test_plain_callable_allow_is_observed(
    log: ObservationLog,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    calls: list[ToolRequest] = []

    def tool(request: ToolRequest) -> str:
        calls.append(request)
        return "ran"

    seam = EnforcementSeam(tool, log=log)
    result = seam.enforce(_decision("allow"), inside, granted_authority)

    assert calls == [inside]
    assert result.tool_result == "ran"
    assert result.record.to_dict()["sideEffect"] is True
    assert seam.runner.invocation_count == 1


def test_tool_exception_still_logs_observed_side_effect(
    log: ObservationLog,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    def boom(_request: ToolRequest) -> Any:
        raise RuntimeError("stub failed after entry")

    seam = EnforcementSeam(StubToolRunner(impl=boom), log=log)

    with pytest.raises(RuntimeError, match="stub failed"):
        seam.enforce(_decision("allow"), inside, granted_authority)

    assert seam.runner.invocation_count == 1
    assert len(log) == 1
    assert log.entries[0].to_dict()["sideEffect"] is True
    assert log.entries[0].to_dict()["choice"] == "allow"


def test_second_allow_is_a_second_single_call(
    seam: EnforcementSeam,
    runner: StubToolRunner,
    inside: ToolRequest,
    granted_authority: GrantedAuthority,
) -> None:
    seam.enforce(_decision("allow"), inside, granted_authority)
    seam.enforce(_decision("allow"), inside, granted_authority)

    assert runner.invocation_count == 2


def test_logged_probs_are_a_copy(seam: EnforcementSeam, inside: ToolRequest, granted_authority: GrantedAuthority) -> None:
    probs = {"allow": 0.5, "deny": 0.5, "escalate": 0.0}
    decision = _decision("deny", probs=probs)

    result = seam.enforce(decision, inside, granted_authority)
    decision.probs["deny"] = 0.0

    assert result.record.to_dict()["probs"] == {"allow": 0.5, "deny": 0.5, "escalate": 0.0}


def test_rejects_non_decision(seam: EnforcementSeam, runner: StubToolRunner, inside: ToolRequest, granted_authority: GrantedAuthority) -> None:
    with pytest.raises(TypeError):
        seam.enforce({"choice": "allow"}, inside, granted_authority)  # type: ignore[arg-type]

    assert runner.invocation_count == 0
    assert len(seam.log) == 0


def test_schema_file_matches_log_fields() -> None:
    schema = json.loads((_PACKAGE / "observation-log.schema.json").read_text())
    readme = (_PACKAGE / "README.md").read_text()

    assert schema["title"] == "ObservationLogEntry"
    assert schema["required"] == list(OBSERVATION_LOG_FIELDS)
    assert set(schema["properties"]) == set(OBSERVATION_LOG_FIELDS)
    assert schema["properties"]["choice"]["enum"] == ["allow", "deny", "escalate"]
    assert schema["properties"]["sideEffect"]["type"] == "boolean"
    assert schema["properties"]["schemaVersion"]["const"] == OBSERVATION_SCHEMA_VERSION
    for field in OBSERVATION_LOG_FIELDS:
        assert f"`{field}`" in readme
    assert "sideEffect" in readme
    assert "observation-log.schema.json" in readme
