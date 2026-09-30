"""Structured observation log.

``sideEffect`` is stored as given. This type does not derive it from
``choice``. See the package README for the log schema.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from gate_client.decision import ChoiceLabel

OBSERVATION_SCHEMA_VERSION = 1

OBSERVATION_LOG_FIELDS = (
    "schemaVersion",
    "choice",
    "probs",
    "reasonCode",
    "sideEffect",
    "toolName",
    "withinGrantedAuthority",
)


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    """One enforcement observation: the injected decision plus what the stub did."""

    choice: ChoiceLabel
    probs: Mapping[str, float]
    reason_code: str
    side_effect: bool
    tool_name: str
    within_granted_authority: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "probs", dict(self.probs))

    @property
    def reasonCode(self) -> str:
        return self.reason_code

    @property
    def sideEffect(self) -> bool:
        return self.side_effect

    @property
    def withinGrantedAuthority(self) -> bool:
        return self.within_granted_authority

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": OBSERVATION_SCHEMA_VERSION,
            "choice": self.choice,
            "probs": dict(self.probs),
            "reasonCode": self.reason_code,
            "sideEffect": self.side_effect,
            "toolName": self.tool_name,
            "withinGrantedAuthority": self.within_granted_authority,
        }


class ObservationLog:
    """Append-only log of enforcement observations."""

    def __init__(self) -> None:
        self._entries: list[ObservationRecord] = []

    def append(self, record: ObservationRecord) -> None:
        self._entries.append(record)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[ObservationRecord, ...]:
        return tuple(self._entries)

    def to_list(self) -> list[dict[str, object]]:
        return [record.to_dict() for record in self._entries]
