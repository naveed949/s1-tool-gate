"""Stable reason codes for claims-gate decisions.

Every code except ``claims_allow`` and ``claims_wallet_escalate`` is a deny.
"""

from __future__ import annotations

from enum import StrEnum


class ClaimsReason(StrEnum):
    ALLOW = "claims_allow"
    UNAUTHENTICATED = "claims_unauthenticated"
    INVALID_TOKEN = "claims_invalid_token"
    MISSING_CLAIM = "claims_missing_claim"
    EXPIRED = "claims_expired"
    NOT_YET_VALID = "claims_not_yet_valid"
    AUDIENCE_MISMATCH = "claims_audience_mismatch"
    ISSUER_MISMATCH = "claims_issuer_mismatch"
    UNKNOWN_TOOL = "claims_unknown_tool"
    INSUFFICIENT_SCOPE = "claims_insufficient_scope"
    WALLET_ESCALATE = "claims_wallet_escalate"
    WALLET_DENIED = "claims_wallet_denied"
    # Live proxy only (claims_gate.proxy).
    JWKS_UNAVAILABLE = "claims_jwks_unavailable"
    TOKEN_REVOKED = "claims_token_revoked"
    INTROSPECTION_UNAVAILABLE = "claims_introspection_unavailable"
    MALFORMED_REQUEST = "claims_malformed_request"
