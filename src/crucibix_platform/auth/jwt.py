"""OIDC token verification behind a port, so Keycloak (default) is swappable for Cognito/etc.

The verifier validates the JWT signature against the IdP's JWKS and maps standard + Crucibix
claims into an ``AuthContext``. Keycloak enriches tokens with ``tenant``, ``roles`` and a
``privileges`` claim (or clients call identity-access ``GET /me``); both are supported here.
"""

from __future__ import annotations

import uuid
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient

from crucibix_platform.auth.context import AuthContext
from crucibix_platform.domain.errors import AccessDenied


class TokenVerifier(Protocol):
    def verify(self, token: str, *, correlation_id: str | None = None) -> AuthContext: ...


class OidcTokenVerifier:
    """Validates RS256 OIDC access tokens against the IdP JWKS."""

    def __init__(self, jwks_url: str, issuer: str, audience: str | None = None) -> None:
        self._jwks = PyJWKClient(jwks_url)
        self._issuer = issuer
        self._audience = audience

    def verify(self, token: str, *, correlation_id: str | None = None) -> AuthContext:
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
                options={"verify_aud": self._audience is not None},
            )
        except jwt.PyJWTError as exc:  # invalid signature / expired / wrong issuer
            raise AccessDenied(f"Invalid token: {exc}", missing_privilege=None) from exc
        return claims_to_auth_context(claims, correlation_id=correlation_id)


def claims_to_auth_context(claims: dict[str, Any], *, correlation_id: str | None = None) -> AuthContext:
    tenant = claims.get("tenant") or claims.get("tenant_id")
    return AuthContext(
        subject=uuid.UUID(str(claims["sub"])),
        email=str(claims.get("email", "")),
        tenant_id=uuid.UUID(str(tenant)) if tenant else None,
        roles=frozenset(claims.get("roles", [])),
        privileges=frozenset(claims.get("privileges", [])),
        is_platform_operator=bool(claims.get("is_platform_operator", False)),
        correlation_id=correlation_id,
    )
