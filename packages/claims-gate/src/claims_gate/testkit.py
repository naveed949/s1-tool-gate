"""TEST-ONLY signing keys and tokens for evals, the demo, and the verify skill.

Keys are generated at run time (in memory, or into a caller-chosen scratch
directory). No private key is committed to the repo. Nothing here talks to a
network or a real identity provider. The issuer uses the reserved ``.invalid``
TLD so it can never resolve.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TEST_ISSUER = "https://idp.test.invalid"
TEST_AUDIENCE = "kaia-mcp"
TEST_KID = "s1-test-key-1"
TEST_SUBJECT = "partner-agent-1"
PRIVATE_KEY_FILENAME = "test-signing-key.TEST-ONLY.pem"


@dataclass(frozen=True)
class TestSigner:
    """An RSA key pair used only to mint test tokens."""

    __test__ = False  # not a pytest class

    private_key: rsa.RSAPrivateKey
    kid: str = TEST_KID

    @classmethod
    def generate(cls, kid: str = TEST_KID) -> "TestSigner":
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=2048), kid)

    def jwk(self) -> dict[str, Any]:
        data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        data.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return data

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk()]}

    def mint(self, claims: Mapping[str, Any], *, kid: str | None = None) -> str:
        return jwt.encode(dict(claims), self.private_key, algorithm="RS256", headers={"kid": kid or self.kid})

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @classmethod
    def from_pem(cls, pem: bytes, kid: str = TEST_KID) -> "TestSigner":
        key = serialization.load_pem_private_key(pem, password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        return cls(key, kid)


def unsigned_token(claims: Mapping[str, Any]) -> str:
    """An ``alg: none`` token. The gate must reject it."""
    return jwt.encode(dict(claims), None, algorithm="none")


def build_claims(
    *,
    now: float,
    sub: str | None = TEST_SUBJECT,
    iss: str | None = TEST_ISSUER,
    aud: str | list[str] | None = TEST_AUDIENCE,
    exp_in: float | None = 600,
    nbf_in: float | None = None,
    scope: str | None = None,
    scp: Iterable[str] | None = None,
) -> dict[str, Any]:
    claims: dict[str, Any] = {"iat": int(now)}
    if sub is not None:
        claims["sub"] = sub
    if iss is not None:
        claims["iss"] = iss
    if aud is not None:
        claims["aud"] = aud
    if exp_in is not None:
        claims["exp"] = int(now + exp_in)
    if nbf_in is not None:
        claims["nbf"] = int(now + nbf_in)
    if scope is not None:
        claims["scope"] = scope
    if scp is not None:
        claims["scp"] = list(scp)
    return claims


def init_dir(directory: Path) -> TestSigner:
    """Write a TEST-ONLY key, its JWKS, and the issuer/audience config into ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    signer = TestSigner.generate()
    key_path = directory / PRIVATE_KEY_FILENAME
    key_path.write_bytes(signer.private_pem())
    key_path.chmod(0o600)
    (directory / "jwks.json").write_text(json.dumps(signer.jwks(), indent=2) + "\n")
    (directory / "config.json").write_text(
        json.dumps({"issuer": TEST_ISSUER, "audience": TEST_AUDIENCE, "kid": signer.kid}, indent=2) + "\n"
    )
    return signer


def load_dir(directory: Path) -> TestSigner:
    return TestSigner.from_pem((directory / PRIVATE_KEY_FILENAME).read_bytes())
