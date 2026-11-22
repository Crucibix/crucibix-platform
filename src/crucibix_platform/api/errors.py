"""Map domain/validation errors to RFC 9457 ``application/problem+json`` consistently
across every service."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from crucibix_platform.domain.errors import AccessDenied, DomainError

PROBLEM_MEDIA_TYPE = "application/problem+json"


def problem(status: int, code: str, detail: str, **extra: Any) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"https://errors.crucibix.com/{code}",
        "title": code.replace("_", " ").title(),
        "status": status,
        "detail": detail,
    }
    body.update({k: v for k, v in extra.items() if v is not None})
    return JSONResponse(status_code=status, content=body, media_type=PROBLEM_MEDIA_TYPE)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain(_: Request, exc: DomainError) -> JSONResponse:
        extra: dict[str, Any] = {}
        if isinstance(exc, AccessDenied):
            extra["missingPrivilege"] = exc.missing_privilege
        return problem(exc.http_status, exc.code, exc.message, **extra)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return problem(422, "validation_error", "Request validation failed", errors=exc.errors())
