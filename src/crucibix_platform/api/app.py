"""The shared FastAPI application factory. Every service calls ``create_app`` with its routers
and gets consistent errors, auth, middleware, health, and observability for free."""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, FastAPI

from crucibix_platform.api.errors import register_exception_handlers
from crucibix_platform.api.health import router as health_router
from crucibix_platform.api.middleware import install_middleware
from crucibix_platform.auth.jwt import OidcTokenVerifier, TokenVerifier
from crucibix_platform.config import PlatformSettings
from crucibix_platform.observability.otel import configure_observability


def create_app(
    settings: PlatformSettings,
    *,
    routers: Sequence[APIRouter] = (),
    token_verifier: TokenVerifier | None = None,
    api_prefix: str = "/v1",
) -> FastAPI:
    app = FastAPI(
        title=f"Crucibix {settings.service_name}",
        version="1.0.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.state.settings = settings
    app.state.token_verifier = token_verifier or OidcTokenVerifier(
        jwks_url=settings.oidc_jwks_url, issuer=settings.oidc_issuer, audience=settings.oidc_audience
    )

    configure_observability(app, settings)
    install_middleware(app)
    register_exception_handlers(app)

    app.include_router(health_router)
    for router in routers:
        app.include_router(router, prefix=api_prefix)
    return app
