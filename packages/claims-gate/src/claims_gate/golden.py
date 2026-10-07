"""Golden eval cases for the kaia-mcp fixture (literal expected decisions).

The case table lives in ``kaia_golden.json`` next to this module so the
pytest evals and ``python -m claims_gate demo`` read the same file.
Tokens are minted at run time with a fresh TEST-ONLY key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from claims_gate.testkit import TestSigner, build_claims, unsigned_token

GOLDEN_NOW = 1_800_000_000


@dataclass(frozen=True)
class GoldenCase:
    id: str
    tool: str
    token: dict[str, Any] | None
    authorization: str | None
    expected_choice: str
    expected_reason: str


def load_cases() -> list[GoldenCase]:
    raw = json.loads(resources.files("claims_gate").joinpath("kaia_golden.json").read_text())
    out = []
    for c in raw["cases"]:
        out.append(
            GoldenCase(
                id=c["id"],
                tool=c["tool"],
                token=c.get("token"),
                authorization=c.get("authorization"),
                expected_choice=c["expected"]["choice"],
                expected_reason=c["expected"]["reasonCode"],
            )
        )
    return out


def authorization_for(case: GoldenCase, trusted: TestSigner, untrusted: TestSigner, now: float) -> str | None:
    """Build the Authorization header value for a case. ``None`` means no header."""
    if case.token is None:
        return case.authorization
    spec = dict(case.token)
    signer = spec.pop("signer", "trusted")
    kid = spec.pop("kid", None)
    omit = set(spec.pop("omit", []))
    kwargs: dict[str, Any] = {
        "now": now,
        "scope": spec.pop("scope", None),
        "scp": spec.pop("scp", None),
        "exp_in": spec.pop("expIn", 600),
        "nbf_in": spec.pop("nbfIn", None),
    }
    for key in ("sub", "iss", "aud"):
        if key in spec:
            kwargs[key] = spec.pop(key)
    if spec:
        raise ValueError(f"{case.id}: unknown token fields {sorted(spec)}")
    claims = build_claims(**kwargs)
    for key in omit:
        claims.pop(key, None)
    if signer == "trusted":
        token = trusted.mint(claims, kid=kid)
    elif signer == "untrusted":
        token = untrusted.mint(claims, kid=kid)
    elif signer == "none":
        token = unsigned_token(claims)
    else:
        raise ValueError(f"{case.id}: unknown signer {signer}")
    return f"Bearer {token}"
