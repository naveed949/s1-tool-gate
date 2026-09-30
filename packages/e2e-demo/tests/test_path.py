"""Gate-path tests.

The gate client is a fake. The enforcement seam, stub runner, and observation
log are the real packages. Ollama is not called.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from gate_client import GateDecision, ReasonCode
from gate_client.decision import deny
from gate_enforcement import (
    EnforcementSeam,
    EscalationChannel,
    ObservationLog,
    StubToolRunner,
)

from e2e_demo.__main__ import main
from e2e_demo.path import parse_cases, run_gate_path


def _case(side: str = "base", gold: str = "allow", pair_id: str = "af-001") -> dict[str, object]:
    return {
        "pairId": pair_id,
        "side": side,
        "tool": "read_file",
        "policy": "May read files under /tmp.",
        "args": {"path": "/tmp/note.txt"},
        "context": "The user asked for the note.",
        "gold": gold,
    }


class ScriptedClient:
    def __init__(self, decisions: list[GateDecision]) -> None:
        self._decisions = list(decisions)
        self.calls: list[tuple[str, str, object, str]] = []

    def decide(
        self,
        *,
        policy: str,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        context: str = "",
    ) -> GateDecision:
        self.calls.append((policy, tool_name, args, context))
        return self._decisions.pop(0)


def _decision(choice: str, reason: str, probs: dict[str, float] | None = None) -> GateDecision:
    return GateDecision(choice=choice, probs=probs or {"allow": 0.2, "deny": 0.2, "escalate": 0.6}, reason_code=reason)


def test_allow_runs_the_stub_once() -> None:
    runner = StubToolRunner()
    escalation = EscalationChannel()
    seam = EnforcementSeam(runner, log=ObservationLog(), escalation=escalation)
    client = ScriptedClient([_decision("allow", "nimble_allow", {"allow": 0.91, "deny": 0.05, "escalate": 0.04})])
    report = run_gate_path(parse_cases({"cases": [_case()]}), client=client, seam=seam)
    assert report["status"] == "ok"
    assert runner.invocation_count == 1
    assert escalation.submissions == []
    entry = report["observations"][0]["entry"]
    assert entry["sideEffect"] is True
    assert entry["withinGrantedAuthority"] is True
    assert entry["choice"] == "allow"
    assert entry["reasonCode"] == "nimble_allow"
    assert entry["schemaVersion"] == 1
    assert set(entry) == {
        "schemaVersion",
        "choice",
        "probs",
        "reasonCode",
        "sideEffect",
        "toolName",
        "withinGrantedAuthority",
    }
    assert client.calls[0][0] == "May read files under /tmp."
    assert client.calls[0][1] == "read_file"


def test_deny_and_escalate_do_not_run_the_stub() -> None:
    runner = StubToolRunner()
    escalation = EscalationChannel()
    seam = EnforcementSeam(runner, log=ObservationLog(), escalation=escalation)
    client = ScriptedClient(
        [
            _decision("deny", "nimble_deny", {"allow": 0.02, "deny": 0.96, "escalate": 0.02}),
            _decision("escalate", "nimble_escalate"),
        ]
    )
    cases = parse_cases(
        {
            "cases": [
                _case(side="base", gold="deny"),
                _case(side="flipped", gold="escalate", pair_id="af-001"),
            ]
        }
    )
    report = run_gate_path(cases, client=client, seam=seam)
    assert report["status"] == "ok"
    assert runner.invocation_count == 0
    assert len(escalation.submissions) == 1
    assert [row["entry"]["sideEffect"] for row in report["observations"]] == [False, False]
    assert [row["entry"]["choice"] for row in report["observations"]] == ["deny", "escalate"]


def test_fail_closed_is_unavailable_and_has_no_flip_metrics() -> None:
    client = ScriptedClient([deny(ReasonCode.FAIL_CLOSED_DOWN)])
    report = run_gate_path(parse_cases({"cases": [_case(gold="deny")]}), client=client)
    assert report["status"] == "unavailable"
    assert report["decisions"][0]["decision"]["choice"] == "deny"
    assert report["decisions"][0]["decision"]["reasonCode"] == "fail_closed_down"
    assert report["observations"][0]["entry"]["sideEffect"] is False
    blob = json.dumps(report)
    assert "flipRate" not in blob
    assert "ece" not in blob
    assert any("fail_closed_down" in note for note in report["notes"])


def test_one_fail_closed_decision_marks_the_path_unavailable() -> None:
    client = ScriptedClient(
        [
            _decision("allow", "nimble_allow", {"allow": 0.9, "deny": 0.05, "escalate": 0.05}),
            deny(ReasonCode.FAIL_CLOSED_TIMEOUT, {"allow": 0.4, "deny": 0.4, "escalate": 0.2}),
        ]
    )
    cases = parse_cases({"cases": [_case(side="base"), _case(side="flipped", gold="deny")]})
    report = run_gate_path(cases, client=client)
    assert report["status"] == "unavailable"
    assert report["decisions"][1]["decision"]["reasonCode"] == "fail_closed_timeout"


def test_empty_cases_fail() -> None:
    report = run_gate_path([], client=ScriptedClient([]))
    assert report["status"] == "failed"
    assert report["decisions"] == []


def test_duplicate_case_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        parse_cases({"cases": [_case(), _case()]})


def test_main_unavailable_document(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class DownClient:
        def decide(self, *, policy: str, tool_name: str, args: object = None, context: str = "") -> GateDecision:
            return deny(ReasonCode.FAIL_CLOSED_DOWN)

    monkeypatch.setattr("e2e_demo.path.GateClient", DownClient)
    code = main(json.dumps({"cases": [_case()]}))
    captured = capsys.readouterr()
    assert code == 0
    body = json.loads(captured.out)
    assert body["status"] == "unavailable"
    assert captured.err == ""
    assert "flipRate" not in captured.out


def test_main_rejects_invalid_input(capsys: pytest.CaptureFixture[str]) -> None:
    code = main("{")
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err != ""


def test_module_rejects_invalid_input_without_scoring() -> None:
    package_root = Path(__file__).resolve().parents[1]
    repo_root = package_root.parent
    pythonpath = os.pathsep.join(
        [
            str(package_root / "python"),
            str(repo_root / "gate-client" / "src"),
            str(repo_root / "gate-enforcement" / "src"),
            os.environ.get("PYTHONPATH", ""),
        ]
    )
    completed = subprocess.run(
        [sys.executable, "-m", "e2e_demo"],
        input="{",
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": pythonpath},
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
