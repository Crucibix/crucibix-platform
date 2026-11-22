"""Base settings every service extends. Values come from env (12-factor); secrets are injected
at runtime from AWS Secrets Manager/SSM, never committed."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class PlatformSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CRUCIBIX_", extra="ignore")

    service_name: str = "service"
    environment: str = "dev"  # dev | staging | prod
    log_level: str = "INFO"

    # Persistence
    database_url: str = "postgresql+psycopg://localhost/postgres"

    # AuthN (Keycloak / OIDC)
    oidc_issuer: str = "https://auth.crucibix.com/realms/crucibix"
    oidc_jwks_url: str = "https://auth.crucibix.com/realms/crucibix/protocol/openid-connect/certs"
    oidc_audience: str | None = None

    # Eventing
    event_bus_name: str = "crucibix"
    aws_region: str = "ap-south-1"
    # Set to the LocalStack edge (e.g. http://localhost:4566) for local-dev; None → real AWS.
    aws_endpoint_url: str | None = None

    # Observability
    otel_exporter_otlp_endpoint: str | None = None
