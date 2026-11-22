"""Cross-cutting HTTP middleware: correlation id propagation + structured access logging."""

from __future__ import annotations

import time
import uuid

import structlog
from fastapi import FastAPI, Request, Response

from crucibix_platform.tenancy.context import current_tenant_id

log = structlog.get_logger("http")


def install_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def _correlation_and_logging(request: Request, call_next):  # type: ignore[no-untyped-def]
        correlation_id = (
            request.headers.get("X-Correlation-Id")
            or request.headers.get("X-Request-Id")
            or str(uuid.uuid4())
        )
        start = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers["X-Correlation-Id"] = correlation_id
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            correlation_id=correlation_id,
            tenant_id=str(current_tenant_id()) if current_tenant_id() else None,
        )
        return response
