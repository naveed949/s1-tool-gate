"""Granted-authority fixture for the stub seam.

Admission is an exact match on policy text and tool name. It is the boundary
inside which an allow may run the stub. It is not a policy language, not
argument mediation, and not AdaptiveSandbox.
"""

from __future__ import annotations

from dataclasses import dataclass

from gate_enforcement.request import ToolRequest


@dataclass(frozen=True, slots=True)
class GrantedAuthority:
    """Fixture describing the authority an allow is permitted to act inside."""

    policy: str
    tool_name: str

    def admits(self, request: ToolRequest) -> bool:
        """True when ``request`` matches this fixture exactly."""
        return request.policy == self.policy and request.tool_name == self.tool_name
