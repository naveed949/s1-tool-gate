"""Escalation channel stub.

Grey decisions are handed here. Submitting a notice does not run the tool
and is not an allow.
"""

from __future__ import annotations

from dataclasses import dataclass

from gate_client.decision import GateDecision

from gate_enforcement.request import ToolRequest


@dataclass(frozen=True, slots=True)
class EscalationNotice:
    """Record that a grey decision was handed to the escalation channel."""

    tool_name: str
    policy: str
    decision: GateDecision


class EscalationChannel:
    """In-process stand-in for a human or higher-authority review queue."""

    def __init__(self) -> None:
        self.submissions: list[EscalationNotice] = []

    def submit(self, *, request: ToolRequest, decision: GateDecision) -> None:
        self.submissions.append(
            EscalationNotice(
                tool_name=request.tool_name,
                policy=request.policy,
                decision=decision,
            )
        )
