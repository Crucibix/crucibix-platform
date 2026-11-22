"""FastAPI dependencies for authn/authz. Handlers declare the privilege they need:

    @router.get("/investors", dependencies=[Depends(require_privilege("investors:read"))])

Tenant scope is implicit: the AuthContext carries the tenant; repositories filter by it.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Request

from crucibix_platform.auth.context import AuthContext
from crucibix_platform.auth.jwt import TokenVerifier
from crucibix_platform.domain.errors import AccessDenied
from crucibix_platform.tenancy.context import set_request_context


async def current_auth(request: Request) -> AuthContext:
    """Extract + verify the bearer token into an AuthContext and bind request context."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise AccessDenied("Missing bearer token")
    token = header.removeprefix("Bearer ").strip()
    verifier: TokenVerifier = request.app.state.token_verifier
    correlation_id = request.headers.get("X-Correlation-Id") or request.headers.get("X-Request-Id")
    auth: AuthContext = verifier.verify(token, correlation_id=correlation_id)
    set_request_context(tenant_id=auth.tenant_id, correlation_id=auth.correlation_id, subject=auth.subject)
    return auth


CurrentAuth = Annotated[AuthContext, Depends(current_auth)]


def require_privilege(privilege: str) -> Callable[[AuthContext], Coroutine[Any, Any, AuthContext]]:
    """Dependency factory enforcing a single privilege (matches the contract's
    ``x-required-privilege``)."""

    async def _dep(auth: CurrentAuth) -> AuthContext:
        if not auth.has_privilege(privilege):
            raise AccessDenied(f"Requires privilege '{privilege}'", missing_privilege=privilege)
        return auth

    return _dep
