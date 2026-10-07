"""One-call entry point: Authorization header + tool name -> decision + audit fields."""

from __future__ import annotations

from dataclasses import dataclass

from gate_client.decision import GateDecision

from claims_gate.policy import ToolPolicy
from claims_gate.verify import (
    ClaimsFailure,
    VerifiedClaims,
    VerifierConfig,
    bearer_token,
    verify_access_token,
)


@dataclass(frozen=True, slots=True)
class ClaimsResult:
    decision: GateDecision
    tool_name: str
    required_scope: str | None
    subject: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        """Gate contract fields plus audit fields. Never includes the token."""
        out = self.decision.to_dict()
        out.update(
            {
                "tool": self.tool_name,
                "requiredScope": self.required_scope,
                "subject": self.subject,
                "detail": self.detail,
            }
        )
        return out


class ClaimsGate:
    """Verify the caller's access token, then apply the tool policy."""

    def __init__(self, verifier: VerifierConfig, policy: ToolPolicy) -> None:
        self._verifier = verifier
        self._policy = policy

    @property
    def policy(self) -> ToolPolicy:
        return self._policy

    def evaluate(
        self,
        authorization: str | None,
        tool_name: str,
        *,
        now: float | None = None,
    ) -> ClaimsResult:
        claims = verify_access_token(bearer_token(authorization), self._verifier, now=now)
        decision = self._policy.decide(claims, tool_name)
        if isinstance(claims, ClaimsFailure):
            subject, detail = None, claims.detail
        else:
            assert isinstance(claims, VerifiedClaims)
            subject, detail = claims.subject, decision.reason_code
        return ClaimsResult(
            decision=decision,
            tool_name=tool_name,
            required_scope=self._policy.required_scope(tool_name),
            subject=subject,
            detail=detail,
        )
