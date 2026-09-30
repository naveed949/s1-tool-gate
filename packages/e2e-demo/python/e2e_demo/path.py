"""Run pinned cases through the gate client and the enforcement seam.

Each case uses a granted-authority fixture of that case's own policy and tool
name. Allow inside that fixture calls the stub once. Deny and escalate do not.
``sideEffect`` is taken from the observation record, which reads the stub
runner's invocation count.

A fail-closed decision is stored as the gate client returned it. This module
does not turn those denies into a flip rate or an ECE.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from gate_client import GateClient, GateDecision
from gate_enforcement import (
    EnforcementSeam,
    EscalationChannel,
    GrantedAuthority,
    ObservationLog,
    StubToolRunner,
    ToolRequest,
)

SCORED_REASONS = frozenset({"nimble_allow", "nimble_deny", "nimble_escalate"})
SIDES = frozenset({"base", "flipped"})
GOLDS = frozenset({"allow", "deny", "escalate"})


class Decider(Protocol):
    """The slice of ``GateClient`` this path calls."""

    def decide(
        self,
        *,
        policy: str,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        context: str = "",
    ) -> GateDecision: ...


@dataclass(frozen=True, slots=True)
class GateCase:
    """One side of a pinned pair, including the gold label for the report."""

    pair_id: str
    side: Literal["base", "flipped"]
    tool: str
    policy: str
    args: dict[str, Any]
    context: str
    gold: str


def parse_cases(payload: object) -> list[GateCase]:
    """Parse the orchestrator's stdin document into cases."""
    if not isinstance(payload, Mapping) or not isinstance(payload.get("cases"), list):
        raise ValueError("gate-path input must be an object with a cases array")
    cases: list[GateCase] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(payload["cases"]):
        case = _parse_case(raw, index)
        key = (case.pair_id, case.side)
        if key in seen:
            raise ValueError(f"duplicate case {case.pair_id} {case.side}")
        seen.add(key)
        cases.append(case)
    return cases


def run_gate_path(
    cases: list[GateCase],
    *,
    client: Decider | None = None,
    seam: EnforcementSeam | None = None,
) -> dict[str, object]:
    """Decide each case, enforce it on the stub, and return JSON-ready rows.

    ``status`` is ``ok`` only when every decision reason is a Nimble choice
    (``nimble_allow``, ``nimble_deny``, or ``nimble_escalate``). Any
    ``fail_closed_*`` reason yields ``unavailable``. An empty case list or an
    unexpected error yields ``failed``.
    """
    if len(cases) == 0:
        return _result(
            "failed",
            ["gate path received no cases"],
            [],
            [],
        )

    gate = client if client is not None else GateClient()
    active = seam if seam is not None else EnforcementSeam(
        StubToolRunner(),
        log=ObservationLog(),
        escalation=EscalationChannel(),
    )
    decisions: list[dict[str, object]] = []
    observations: list[dict[str, object]] = []
    reasons: list[str] = []

    for case in cases:
        try:
            decision = gate.decide(
                policy=case.policy,
                tool_name=case.tool,
                args=case.args,
                context=case.context,
            )
        except Exception as exc:
            note = f"{case.pair_id} {case.side}: gate client raised {type(exc).__name__}: {exc}"
            return _result("failed", [note], decisions, observations)
        if not isinstance(decision, GateDecision):
            note = f"{case.pair_id} {case.side}: gate client did not return a GateDecision"
            return _result("failed", [note], decisions, observations)

        authority = GrantedAuthority(policy=case.policy, tool_name=case.tool)
        request = ToolRequest(
            tool_name=case.tool,
            policy=case.policy,
            args=case.args,
            context=case.context,
        )
        try:
            enforced = active.enforce(decision, request, authority)
        except Exception as exc:
            note = f"{case.pair_id} {case.side}: enforcement raised {type(exc).__name__}: {exc}"
            return _result("failed", [note], decisions, observations)

        reasons.append(decision.reason_code)
        decisions.append(
            {
                "pairId": case.pair_id,
                "side": case.side,
                "gold": case.gold,
                "decision": decision.to_dict(),
            }
        )
        observations.append(
            {
                "pairId": case.pair_id,
                "side": case.side,
                "entry": enforced.record.to_dict(),
            }
        )

    fail_closed = [reason for reason in reasons if reason not in SCORED_REASONS]
    if fail_closed:
        counts = Counter(fail_closed)
        notes = [
            f"{count} decision(s) fail-closed with {reason}"
            for reason, count in sorted(counts.items())
        ]
        notes.append(
            "Fail-closed decisions are recorded as deny. "
            "They are not scored Nimble choices. This path does not emit flip rate or ECE."
        )
        return _result("unavailable", notes, decisions, observations)

    return _result("ok", ["every decision is a Nimble choice"], decisions, observations)


def _result(
    status: str,
    notes: list[str],
    decisions: list[dict[str, object]],
    observations: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "notes": notes,
        "decisions": decisions,
        "observations": observations,
    }


def _parse_case(raw: object, index: int) -> GateCase:
    if not isinstance(raw, Mapping):
        raise ValueError(f"cases[{index}] must be an object")
    pair_id = _text(raw.get("pairId"), f"cases[{index}].pairId")
    side = _text(raw.get("side"), f"cases[{index}].side")
    if side not in SIDES:
        raise ValueError(f"cases[{index}].side must be base or flipped")
    tool = _text(raw.get("tool"), f"cases[{index}].tool")
    policy = _text(raw.get("policy"), f"cases[{index}].policy")
    context = raw.get("context", "")
    if not isinstance(context, str):
        raise ValueError(f"cases[{index}].context must be a string")
    gold = _text(raw.get("gold"), f"cases[{index}].gold")
    if gold not in GOLDS:
        raise ValueError(f"cases[{index}].gold must be allow, deny, or escalate")
    args = raw.get("args", {})
    if not isinstance(args, Mapping):
        raise ValueError(f"cases[{index}].args must be an object")
    typed_side: Literal["base", "flipped"] = "base" if side == "base" else "flipped"
    return GateCase(
        pair_id=pair_id,
        side=typed_side,
        tool=tool,
        policy=policy,
        args=dict(args),
        context=context,
        gold=gold,
    )


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{label} must be a non-empty string")
    return value
