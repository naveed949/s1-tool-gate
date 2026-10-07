"""Verify an OAuth/OIDC access token (JWT) and extract the claims the gate uses.

Verification is fail-closed: any failure returns a ``ClaimsFailure`` and the
policy layer turns that into a deny. ``now`` is injected so expiry checks are
deterministic in tests and evals.

The raw token is never logged or returned.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import jwt

from claims_gate.reasons import ClaimsReason

DEFAULT_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256")
REQUIRED_CLAIMS: tuple[str, ...] = ("sub", "iss", "aud", "exp")


@dataclass(frozen=True, slots=True)
class VerifiedClaims:
    """Claims from a token whose signature, issuer, audience, and expiry checked out."""

    subject: str
    issuer: str
    audience: tuple[str, ...]
    scopes: frozenset[str]
    expires_at: float


@dataclass(frozen=True, slots=True)
class ClaimsFailure:
    """Why a token was not accepted. ``detail`` never contains the token."""

    reason: ClaimsReason
    detail: str


@dataclass(frozen=True, slots=True)
class VerifierConfig:
    """Trust anchors for one resource server (the MCP server behind the gate)."""

    jwks: Mapping[str, Any]
    issuer: str
    audience: str
    algorithms: Sequence[str] = DEFAULT_ALGORITHMS
    leeway_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience:
            raise ValueError("issuer and audience are required")
        if any(a.lower() == "none" or a.upper().startswith("HS") for a in self.algorithms):
            raise ValueError("only asymmetric algorithms are allowed; 'none' and HS* are rejected")


def bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an ``Authorization: Bearer <token>`` value."""
    if not authorization:
        return None
    scheme, _, value = authorization.strip().partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _scopes(payload: Mapping[str, Any]) -> frozenset[str] | None:
    if "scope" in payload:
        raw = payload["scope"]
        if not isinstance(raw, str):
            return None
        return frozenset(s for s in raw.split(" ") if s)
    if "scp" in payload:
        raw = payload["scp"]
        if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
            return None
        return frozenset(raw)
    return None


def verify_access_token(
    token: str | None,
    config: VerifierConfig,
    *,
    now: float | None = None,
) -> VerifiedClaims | ClaimsFailure:
    """Verify ``token`` against ``config``. Never raises for a bad token."""
    if not token:
        return ClaimsFailure(ClaimsReason.UNAUTHENTICATED, "no bearer token")
    current = time.time() if now is None else now

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return ClaimsFailure(ClaimsReason.INVALID_TOKEN, "malformed token")
    alg = header.get("alg")
    if alg not in config.algorithms:
        return ClaimsFailure(ClaimsReason.INVALID_TOKEN, f"algorithm not allowed: {alg!r}")

    try:
        keyset = jwt.PyJWKSet.from_dict(dict(config.jwks))
    except jwt.PyJWTError:
        return ClaimsFailure(ClaimsReason.INVALID_TOKEN, "jwks unusable")
    kid = header.get("kid")
    candidates = [k for k in keyset.keys if kid is None or k.key_id == kid]
    if kid is None and len(keyset.keys) != 1:
        return ClaimsFailure(ClaimsReason.INVALID_TOKEN, "token has no kid and jwks is ambiguous")
    if not candidates:
        return ClaimsFailure(ClaimsReason.INVALID_TOKEN, "unknown signing key")

    try:
        payload = jwt.decode(
            token,
            candidates[0].key,
            algorithms=[alg],
            audience=config.audience,
            issuer=config.issuer,
            options={
                "require": list(REQUIRED_CLAIMS),
                # Time checks are done below against the injected clock.
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
    except jwt.MissingRequiredClaimError as err:
        return ClaimsFailure(ClaimsReason.MISSING_CLAIM, f"missing claim: {err.claim}")
    except jwt.InvalidAudienceError:
        return ClaimsFailure(ClaimsReason.AUDIENCE_MISMATCH, "audience does not match this resource")
    except jwt.InvalidIssuerError:
        return ClaimsFailure(ClaimsReason.ISSUER_MISMATCH, "issuer is not trusted")
    except jwt.PyJWTError as err:
        return ClaimsFailure(ClaimsReason.INVALID_TOKEN, type(err).__name__)

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        return ClaimsFailure(ClaimsReason.MISSING_CLAIM, "missing claim: sub")
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return ClaimsFailure(ClaimsReason.MISSING_CLAIM, "invalid claim: exp")
    if current >= exp + config.leeway_seconds:
        return ClaimsFailure(ClaimsReason.EXPIRED, "token expired")
    nbf = payload.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)) or isinstance(nbf, bool):
            return ClaimsFailure(ClaimsReason.MISSING_CLAIM, "invalid claim: nbf")
        if current < nbf - config.leeway_seconds:
            return ClaimsFailure(ClaimsReason.NOT_YET_VALID, "token not yet valid")
    scopes = _scopes(payload)
    if scopes is None:
        return ClaimsFailure(ClaimsReason.MISSING_CLAIM, "missing claim: scope")

    aud = payload["aud"]
    audience = (aud,) if isinstance(aud, str) else tuple(aud)
    return VerifiedClaims(
        subject=sub,
        issuer=payload["iss"],
        audience=audience,
        scopes=scopes,
        expires_at=float(exp),
    )
