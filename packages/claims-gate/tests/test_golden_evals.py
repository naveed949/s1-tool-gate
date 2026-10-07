"""Golden evals: literal expected decisions for the kaia-mcp fixture.

Tokens are minted at test time with a fresh TEST-ONLY RSA key. ``now`` is fixed.
"""

from __future__ import annotations

import pytest

from claims_gate import ClaimsGate, VerifierConfig, kaia_policy
from claims_gate.golden import GOLDEN_NOW, GoldenCase, authorization_for, load_cases
from claims_gate.testkit import TEST_AUDIENCE, TEST_ISSUER, TestSigner

# The six required categories, pinned here as well as in kaia_golden.json so an
# edit to the JSON alone cannot quietly change a required outcome.
REQUIRED = {
    "allow-read": ("allow", "claims_allow"),
    "deny-scope-encode": ("deny", "claims_insufficient_scope"),
    "expired": ("deny", "claims_expired"),
    "wrong-audience": ("deny", "claims_audience_mismatch"),
    "unauthenticated": ("deny", "claims_unauthenticated"),
    "wallet-escalate": ("escalate", "claims_wallet_escalate"),
}

CASES = load_cases()


@pytest.fixture(scope="module")
def signers() -> tuple[TestSigner, TestSigner]:
    return TestSigner.generate(), TestSigner.generate()


@pytest.fixture(scope="module")
def gate(signers: tuple[TestSigner, TestSigner]) -> ClaimsGate:
    trusted, _ = signers
    return ClaimsGate(VerifierConfig(jwks=trusted.jwks(), issuer=TEST_ISSUER, audience=TEST_AUDIENCE), kaia_policy())


def test_required_categories_are_present_with_literal_expectations() -> None:
    by_id = {c.id: c for c in CASES}
    for case_id, (choice, reason) in REQUIRED.items():
        assert case_id in by_id, case_id
        assert (by_id[case_id].expected_choice, by_id[case_id].expected_reason) == (choice, reason)


def test_case_ids_are_unique() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_golden_case(case: GoldenCase, gate: ClaimsGate, signers: tuple[TestSigner, TestSigner]) -> None:
    trusted, untrusted = signers
    result = gate.evaluate(authorization_for(case, trusted, untrusted, GOLDEN_NOW), case.tool, now=GOLDEN_NOW)
    assert result.decision.to_dict() == {"choice": case.expected_choice, "probs": {}, "reasonCode": case.expected_reason}


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_wallet_tool_is_never_allowed(case: GoldenCase, gate: ClaimsGate, signers: tuple[TestSigner, TestSigner]) -> None:
    trusted, untrusted = signers
    result = gate.evaluate(authorization_for(case, trusted, untrusted, GOLDEN_NOW), "generate_wallet", now=GOLDEN_NOW)
    assert result.decision.choice != "allow"
