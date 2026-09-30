"""Typed gate decision returned to callers.

The public shape is ``{choice, probs, reasonCode}``. Probabilities are copied
from the TypeSafe SDK choice answer. They are empty when the SDK never
returned a choice.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

ChoiceLabel = Literal["allow", "deny", "escalate"]

CHOICES: frozenset[str] = frozenset({"allow", "deny", "escalate"})


class ReasonCode(StrEnum):
    """Stable reason codes for a gate decision."""

    NIMBLE_ALLOW = "nimble_allow"
    NIMBLE_DENY = "nimble_deny"
    NIMBLE_ESCALATE = "nimble_escalate"
    FAIL_CLOSED_LOW_CONFIDENCE = "fail_closed_low_confidence"
    FAIL_CLOSED_TIMEOUT = "fail_closed_timeout"
    FAIL_CLOSED_DOWN = "fail_closed_down"
    FAIL_CLOSED_CLOUD_MISCONFIGURED = "fail_closed_cloud_misconfigured"
    FAIL_CLOSED_SDK_ERROR = "fail_closed_sdk_error"
    FAIL_CLOSED_INVALID_RESPONSE = "fail_closed_invalid_response"
    FAIL_CLOSED_INVALID_CONFIG = "fail_closed_invalid_config"


_MODEL_REASONS: dict[str, ReasonCode] = {
    "allow": ReasonCode.NIMBLE_ALLOW,
    "deny": ReasonCode.NIMBLE_DENY,
    "escalate": ReasonCode.NIMBLE_ESCALATE,
}


def reason_for_choice(choice: str) -> ReasonCode:
    """Map an SDK choice label to the reason code that records it."""
    return _MODEL_REASONS[choice]


@dataclass(frozen=True, slots=True)
class GateDecision:
    """One allow / deny / escalate decision.

    ``reason_code`` is the Python name. ``reasonCode`` and ``to_dict()`` use
    the camelCase key from the gate contract.
    """

    choice: ChoiceLabel
    probs: Mapping[str, float]
    reason_code: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "probs", dict(self.probs))

    @property
    def reasonCode(self) -> str:
        return self.reason_code

    def to_dict(self) -> dict[str, object]:
        return {
            "choice": self.choice,
            "probs": dict(self.probs),
            "reasonCode": self.reason_code,
        }


def deny(reason_code: ReasonCode, probs: Mapping[str, float] | None = None) -> GateDecision:
    """Fail-closed deny. Escalate is never used on a failure path."""
    return GateDecision(choice="deny", probs=dict(probs or {}), reason_code=reason_code.value)
