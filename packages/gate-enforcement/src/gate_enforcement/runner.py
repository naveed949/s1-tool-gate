"""Injectable stub tool runner.

Invocations are recorded inside ``__call__``. The observation log reads that
count. It does not infer a side effect from the gate choice.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from gate_enforcement.request import ToolRequest


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """One recorded call of the stub."""

    tool_name: str
    args: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", dict(self.args))


class StubToolRunner:
    """Test double for a tool. Each ``__call__`` is one observed side effect."""

    def __init__(self, impl: Callable[[ToolRequest], Any] | None = None) -> None:
        self._impl = impl
        self.invocations: list[ToolInvocation] = []

    @property
    def invocation_count(self) -> int:
        return len(self.invocations)

    def __call__(self, request: ToolRequest) -> Any:
        self.invocations.append(ToolInvocation(tool_name=request.tool_name, args=request.args))
        if self._impl is None:
            return {"ok": True, "tool": request.tool_name}
        return self._impl(request)
