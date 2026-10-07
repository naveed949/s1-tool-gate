"""Map verified claims plus a tool name to a fail-closed gate decision.

The output is the repo's existing ``gate_client.GateDecision`` so it plugs
into ``gate_enforcement.EnforcementSeam`` unchanged. ``probs`` is ``{}``: this
is a deterministic rule, not a model score.

Order of checks (first failure wins):

1. token failure (unauthenticated, invalid, missing claim, expired, audience, issuer) -> deny
2. tool not in the policy map -> deny ``claims_unknown_tool``
3. token scopes lack the tool's required scope -> deny ``claims_insufficient_scope``
4. wallet-class tool -> ``escalate`` (default) or ``deny``; never allow
5. otherwise -> allow ``claims_allow``
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from gate_client.decision import GateDecision

from claims_gate.reasons import ClaimsReason
from claims_gate.verify import ClaimsFailure, VerifiedClaims

WalletDefault = Literal["escalate", "deny"]


def _decision(choice: Literal["allow", "deny", "escalate"], reason: ClaimsReason) -> GateDecision:
    return GateDecision(choice=choice, probs={}, reason_code=reason.value)


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """Tool -> required scope, plus the wallet-class tools that never silently allow."""

    tool_scopes: Mapping[str, str]
    wallet_tools: frozenset[str] = field(default_factory=frozenset)
    wallet_default: WalletDefault = "escalate"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tool_scopes", dict(self.tool_scopes))
        object.__setattr__(self, "wallet_tools", frozenset(self.wallet_tools))
        if self.wallet_default not in ("escalate", "deny"):
            raise ValueError("wallet_default must be 'escalate' or 'deny'; wallet tools never allow")
        unknown = self.wallet_tools - set(self.tool_scopes)
        if unknown:
            raise ValueError(f"wallet tools missing from tool_scopes: {sorted(unknown)}")

    def required_scope(self, tool_name: str) -> str | None:
        return self.tool_scopes.get(tool_name)

    def decide(self, claims: VerifiedClaims | ClaimsFailure, tool_name: str) -> GateDecision:
        if isinstance(claims, ClaimsFailure):
            return _decision("deny", claims.reason)
        if not isinstance(claims, VerifiedClaims):
            return _decision("deny", ClaimsReason.INVALID_TOKEN)
        required = self.required_scope(tool_name)
        if required is None:
            return _decision("deny", ClaimsReason.UNKNOWN_TOOL)
        if required not in claims.scopes:
            return _decision("deny", ClaimsReason.INSUFFICIENT_SCOPE)
        if tool_name in self.wallet_tools:
            if self.wallet_default == "escalate":
                return _decision("escalate", ClaimsReason.WALLET_ESCALATE)
            return _decision("deny", ClaimsReason.WALLET_DENIED)
        return _decision("allow", ClaimsReason.ALLOW)


def combine(claims_decision: GateDecision, nimble_decision: GateDecision | None = None) -> GateDecision:
    """Claims are the ceiling. A downstream System-1 (Nimble) decision can only narrow.

    A claims deny or escalate is final. On a claims allow the Nimble decision,
    if any, is returned as-is (its own fail-closed path already yields deny).
    """
    if claims_decision.choice != "allow" or nimble_decision is None:
        return claims_decision
    return nimble_decision
