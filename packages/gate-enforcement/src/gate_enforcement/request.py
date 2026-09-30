"""Tool call presented to the enforcement seam."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolRequest:
    """One tool call the seam may or may not run.

    ``policy`` is the granted-policy text the gate client already scored.
    The seam does not send this request to Nimble.
    """

    tool_name: str
    policy: str
    args: Mapping[str, Any]
    context: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", dict(self.args))
