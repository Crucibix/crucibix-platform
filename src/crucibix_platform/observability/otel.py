"""Observability bootstrap. Keeps OpenTelemetry optional at import time so unit tests don't
need a collector; wired fully when ``otel_exporter_otlp_endpoint`` is set (staging/prod)."""

from __future__ import annotations

import logging

import structlog
from fastapi import FastAPI

from crucibix_platform.config import PlatformSettings


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )


def configure_observability(app: FastAPI, settings: PlatformSettings) -> None:
    configure_logging(settings.log_level)
    if not settings.otel_exporter_otlp_endpoint:
        return
    try:  # pragma: no cover - exercised only when an endpoint is configured
        from opentelemetry.instrumentation.fastapi import (  # type: ignore[import-not-found]
            FastAPIInstrumentor,
        )

        FastAPIInstrumentor.instrument_app(app)
    except Exception:  # pragma: no cover
        structlog.get_logger("otel").warning("otel_instrumentation_unavailable")
