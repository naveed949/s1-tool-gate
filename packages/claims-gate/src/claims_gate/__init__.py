"""Claims gate: verified OIDC/OAuth access-token claims -> fail-closed tool decisions.

Deterministic and local. It returns the same ``GateDecision`` shape as the
System-1 gate client so ``gate_enforcement.EnforcementSeam`` can enforce it.
It is a ceiling in front of Nimble (see ``combine``), not a replacement for
AdaptiveSandbox/gondolin.
"""

from claims_gate.gate import ClaimsGate, ClaimsResult
from claims_gate.kaia import KAIA_TOOL_SCOPES, KAIA_WALLET_TOOLS, kaia_policy
from claims_gate.policy import ToolPolicy, combine
from claims_gate.reasons import ClaimsReason
from claims_gate.verify import (
    ClaimsFailure,
    VerifiedClaims,
    VerifierConfig,
    bearer_token,
    verify_access_token,
)

__all__ = [
    "KAIA_TOOL_SCOPES",
    "KAIA_WALLET_TOOLS",
    "ClaimsFailure",
    "ClaimsGate",
    "ClaimsReason",
    "ClaimsResult",
    "ToolPolicy",
    "VerifiedClaims",
    "VerifierConfig",
    "bearer_token",
    "combine",
    "kaia_policy",
    "verify_access_token",
]
