"""Enforcement seam.

The gate client decides. This module runs a stub tool only for an allow that
matches the granted-authority fixture, then logs whether that stub ran.

``sideEffect`` is the change in the runner's invocation count. It is not
copied from ``decision.choice``. A logged allow is not a claim that Nimble
held the gate.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from gate_client.decision import GateDecision

from gate_enforcement.authority import GrantedAuthority
from gate_enforcement.escalate import EscalationChannel
from gate_enforcement.log import ObservationLog, ObservationRecord
from gate_enforcement.request import ToolRequest
from gate_enforcement.runner import StubToolRunner


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    """Outcome of one ``enforce`` call, including the log record just appended."""

    record: ObservationRecord
    tool_result: Any | None


class EnforcementSeam:
    """Apply one injected gate decision to a stub tool and an observation log."""

    def __init__(
        self,
        tool: StubToolRunner | Callable[[ToolRequest], Any],
        *,
        log: ObservationLog | None = None,
        escalation: EscalationChannel | None = None,
    ) -> None:
        if isinstance(tool, StubToolRunner):
            self._runner = tool
        else:
            self._runner = StubToolRunner(impl=tool)
        self._log = ObservationLog() if log is None else log
        self._escalation = EscalationChannel() if escalation is None else escalation

    @property
    def runner(self) -> StubToolRunner:
        return self._runner

    @property
    def log(self) -> ObservationLog:
        return self._log

    @property
    def escalation(self) -> EscalationChannel:
        return self._escalation

    def enforce(
        self,
        decision: GateDecision,
        request: ToolRequest,
        authority: GrantedAuthority,
    ) -> EnforcementResult:
        """Run the stub only for an allow inside ``authority``. Always log.

        Deny does not call the tool. Escalate submits to the escalation
        channel and does not call the tool. Any other choice does not call
        the tool. Fail-closed decisions arrive here already as ``choice: deny``
        from the gate client; this method does not score Nimble.
        """
        if not isinstance(decision, GateDecision):
            raise TypeError("decision must be a gate_client.GateDecision")
        if not isinstance(request, ToolRequest):
            raise TypeError("request must be a ToolRequest")
        if not isinstance(authority, GrantedAuthority):
            raise TypeError("authority must be a GrantedAuthority fixture")

        before = self._runner.invocation_count
        tool_result: Any = None
        admitted = authority.admits(request)
        try:
            if decision.choice == "allow" and admitted:
                tool_result = self._runner(request)
            elif decision.choice == "escalate":
                self._escalation.submit(request=request, decision=decision)
        finally:
            # Observed from the runner. Choice is not an input to this flag.
            side_effect = self._runner.invocation_count > before
            record = ObservationRecord(
                choice=decision.choice,
                probs=decision.probs,
                reason_code=decision.reason_code,
                side_effect=side_effect,
                tool_name=request.tool_name,
                within_granted_authority=admitted,
            )
            self._log.append(record)
        return EnforcementResult(record=record, tool_result=tool_result)
