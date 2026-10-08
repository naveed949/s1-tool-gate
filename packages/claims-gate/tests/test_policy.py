from __future__ import annotations

import pytest
from gate_client.decision import GateDecision

from claims_gate import (
    ClaimsFailure,
    ClaimsGate,
    ClaimsReason,
    ToolPolicy,
    VerifiedClaims,
    VerifierConfig,
    bearer_token,
    combine,
    kaia_policy,
    verify_access_token,
)
from claims_gate.kaia import KAIA_READ_TOOLS, KAIA_TOOL_SCOPES, KAIA_WALLET_TOOLS
from claims_gate.testkit import TEST_AUDIENCE, TEST_ISSUER, TestSigner, build_claims

NOW = 1_800_000_000


@pytest.fixture(scope="module")
def signer() -> TestSigner:
    return TestSigner.generate()


def _config(signer: TestSigner) -> VerifierConfig:
    return VerifierConfig(jwks=signer.jwks(), issuer=TEST_ISSUER, audience=TEST_AUDIENCE)


def _claims(scopes: set[str]) -> VerifiedClaims:
    return VerifiedClaims("s", TEST_ISSUER, (TEST_AUDIENCE,), frozenset(scopes), NOW + 60)


def test_kaia_fixture_matches_kaia_mcp_253d6c8() -> None:
    assert len(KAIA_READ_TOOLS) == 24
    assert len(KAIA_TOOL_SCOPES) == 26
    assert KAIA_TOOL_SCOPES["encode_function_data"] == "kaia:encode"
    assert KAIA_TOOL_SCOPES["generate_wallet"] == "kaia:wallet"
    assert {KAIA_TOOL_SCOPES[t] for t in KAIA_READ_TOOLS} == {"kaia:read"}
    assert KAIA_WALLET_TOOLS == frozenset({"generate_wallet"})


def test_wallet_default_deny_variant() -> None:
    d = kaia_policy("deny").decide(_claims({"kaia:wallet"}), "generate_wallet")
    assert d.to_dict() == {"choice": "deny", "probs": {}, "reasonCode": "claims_wallet_denied"}


def test_wallet_default_cannot_be_allow() -> None:
    with pytest.raises(ValueError):
        ToolPolicy(tool_scopes={"w": "x"}, wallet_tools=frozenset({"w"}), wallet_default="allow")  # type: ignore[arg-type]


def test_wallet_tool_must_be_mapped() -> None:
    with pytest.raises(ValueError):
        ToolPolicy(tool_scopes={}, wallet_tools=frozenset({"w"}))


@pytest.mark.parametrize("reason", list(ClaimsReason))
def test_every_failure_reason_denies(reason: ClaimsReason) -> None:
    d = kaia_policy().decide(ClaimsFailure(reason, "x"), "get_kaia_balance")
    assert d.choice == "deny"
    assert d.reason_code == reason.value


def test_non_claims_input_denies() -> None:
    assert kaia_policy().decide(object(), "get_kaia_balance").choice == "deny"  # type: ignore[arg-type]


@pytest.mark.parametrize("alg", ["none", "HS256", "hs512"])
def test_verifier_rejects_symmetric_and_none(signer: TestSigner, alg: str) -> None:
    with pytest.raises(ValueError):
        VerifierConfig(jwks=signer.jwks(), issuer=TEST_ISSUER, audience=TEST_AUDIENCE, algorithms=(alg,))


def test_verifier_requires_issuer_and_audience(signer: TestSigner) -> None:
    with pytest.raises(ValueError):
        VerifierConfig(jwks=signer.jwks(), issuer="", audience=TEST_AUDIENCE)


def test_audience_list_containing_resource_is_accepted(signer: TestSigner) -> None:
    token = signer.mint(build_claims(now=NOW, aud=["other", TEST_AUDIENCE], scope="kaia:read"))
    out = verify_access_token(token, _config(signer), now=NOW)
    assert isinstance(out, VerifiedClaims)
    assert out.scopes == frozenset({"kaia:read"})


def test_non_string_scope_is_missing_claim(signer: TestSigner) -> None:
    claims = build_claims(now=NOW)
    claims["scope"] = ["kaia:read"]
    out = verify_access_token(signer.mint(claims), _config(signer), now=NOW)
    assert isinstance(out, ClaimsFailure) and out.reason is ClaimsReason.MISSING_CLAIM


def test_hs256_token_signed_with_public_key_material_is_rejected(signer: TestSigner) -> None:
    import jwt

    forged = jwt.encode(build_claims(now=NOW, scope="kaia:read"), "attacker-chosen-hmac-secret-32-bytes!!", algorithm="HS256", headers={"kid": signer.kid})
    out = verify_access_token(forged, _config(signer), now=NOW)
    assert isinstance(out, ClaimsFailure) and out.reason is ClaimsReason.INVALID_TOKEN


def test_bearer_parsing() -> None:
    assert bearer_token(None) is None
    assert bearer_token("") is None
    assert bearer_token("Bearer ") is None
    assert bearer_token("Basic abc") is None
    assert bearer_token("bearer abc") == "abc"


def test_result_dict_never_contains_token(signer: TestSigner) -> None:
    token = signer.mint(build_claims(now=NOW, scope="kaia:read"))
    gate = ClaimsGate(_config(signer), kaia_policy())
    out = gate.evaluate(f"Bearer {token}", "get_kaia_balance", now=NOW).to_dict()
    assert token not in repr(out)
    assert out["subject"] == "partner-agent-1"
    assert out["requiredScope"] == "kaia:read"


def test_combine_claims_is_a_ceiling() -> None:
    allow = GateDecision("allow", {}, "claims_allow")
    deny = GateDecision("deny", {}, "claims_expired")
    esc = GateDecision("escalate", {}, "claims_wallet_escalate")
    nimble_allow = GateDecision("allow", {"allow": 0.9}, "nimble_allow")
    nimble_esc = GateDecision("escalate", {"escalate": 0.7}, "nimble_escalate")
    assert combine(deny, nimble_allow) is deny
    assert combine(esc, nimble_allow) is esc
    assert combine(allow, nimble_esc) is nimble_esc
    assert combine(allow, None) is allow


def test_broken_jwks_denies(signer: TestSigner) -> None:
    token = signer.mint(build_claims(now=NOW, scope="kaia:read"))
    config = VerifierConfig(jwks={"keys": [{"kty": "RSA", "kid": signer.kid}]}, issuer=TEST_ISSUER, audience=TEST_AUDIENCE)
    out = verify_access_token(token, config, now=NOW)
    assert isinstance(out, ClaimsFailure) and out.reason is ClaimsReason.INVALID_TOKEN
