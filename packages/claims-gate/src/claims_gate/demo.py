"""kaia-mcp integration demo: claims gate in front of the enforcement seam.

Each golden case is minted with a fresh TEST-ONLY key, evaluated by
``ClaimsGate`` with the kaia-mcp tool/scope fixture, then handed to
``gate_enforcement.EnforcementSeam`` with a stub that stands in for the
kaia-mcp tool handler. The stub records calls; it never touches a chain.
"""

from __future__ import annotations

from typing import Any

from claims_gate.gate import ClaimsGate
from claims_gate.golden import GOLDEN_NOW, authorization_for, load_cases
from claims_gate.kaia import KAIA_SOURCE, kaia_policy
from claims_gate.testkit import TEST_AUDIENCE, TEST_ISSUER, TestSigner
from claims_gate.verify import VerifierConfig

POLICY_LABEL = "kaia-mcp OIDC scopes (claims-gate)"
NON_CLAIMS = [
    "deterministic claims check, not a Nimble score",
    "stub tool, not a live kaia-mcp call",
    "this is not AdaptiveSandbox",
]


def run_demo(*, wallet_default: str = "escalate") -> dict[str, Any]:
    from gate_enforcement import EnforcementSeam, EscalationChannel, GrantedAuthority, ObservationLog, ToolRequest

    trusted = TestSigner.generate()
    untrusted = TestSigner.generate()
    gate = ClaimsGate(
        VerifierConfig(jwks=trusted.jwks(), issuer=TEST_ISSUER, audience=TEST_AUDIENCE),
        kaia_policy(wallet_default),
    )
    calls: list[str] = []

    def kaia_stub(request: Any) -> str:
        calls.append(request.tool_name)
        return f"stub:{request.tool_name}"

    log = ObservationLog()
    escalation = EscalationChannel()
    seam = EnforcementSeam(kaia_stub, log=log, escalation=escalation)

    rows = []
    for case in load_cases():
        auth = authorization_for(case, trusted, untrusted, GOLDEN_NOW)
        result = gate.evaluate(auth, case.tool, now=GOLDEN_NOW)
        before_esc = len(escalation.submissions)
        enforced = seam.enforce(
            result.decision,
            ToolRequest(tool_name=case.tool, policy=POLICY_LABEL, args={}, context=f"golden:{case.id}"),
            GrantedAuthority(policy=POLICY_LABEL, tool_name=case.tool),
        )
        record = enforced.record.to_dict()
        expected_choice, expected_reason = case.expected_choice, case.expected_reason
        if case.tool in gate.policy.wallet_tools and expected_choice == "escalate" and wallet_default == "deny":
            expected_choice, expected_reason = "deny", "claims_wallet_denied"
        ok = (
            result.decision.choice == expected_choice
            and result.decision.reason_code == expected_reason
            and record["sideEffect"] == (expected_choice == "allow")
        )
        rows.append(
            {
                "id": case.id,
                "tool": case.tool,
                "requiredScope": result.required_scope,
                "expected": {"choice": expected_choice, "reasonCode": expected_reason},
                "decision": result.decision.to_dict(),
                "subject": result.subject,
                "sideEffect": record["sideEffect"],
                "escalated": len(escalation.submissions) > before_esc,
                "pass": ok,
            }
        )

    passed = sum(r["pass"] for r in rows)
    return {
        "schemaVersion": 1,
        "fixture": KAIA_SOURCE,
        "issuer": TEST_ISSUER,
        "audience": TEST_AUDIENCE,
        "now": GOLDEN_NOW,
        "walletDefault": wallet_default,
        "cases": rows,
        "summary": {
            "total": len(rows),
            "passed": passed,
            "allow": sum(r["decision"]["choice"] == "allow" for r in rows),
            "deny": sum(r["decision"]["choice"] == "deny" for r in rows),
            "escalate": sum(r["decision"]["choice"] == "escalate" for r in rows),
            "stubCalls": calls,
            "walletStubCalls": sum(1 for c in calls if c in gate.policy.wallet_tools),
        },
        "nonClaims": NON_CLAIMS,
    }
