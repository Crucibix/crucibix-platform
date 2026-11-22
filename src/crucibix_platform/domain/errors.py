"""Domain error hierarchy. These are framework-agnostic; the API layer maps them to
RFC 9457 problem+json responses (see crucibix_platform.api.errors)."""

from __future__ import annotations


class DomainError(Exception):
    """Base for all domain/application errors. `code` is a stable machine token."""

    code: str = "domain_error"
    http_status: int = 400

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


class InvariantViolation(DomainError):
    code = "invariant_violation"
    http_status = 409


class EntityNotFound(DomainError):
    code = "not_found"
    http_status = 404


class Conflict(DomainError):
    code = "conflict"
    http_status = 409


class ValidationError(DomainError):
    code = "validation_error"
    http_status = 422


class AccessDenied(DomainError):
    code = "forbidden"
    http_status = 403

    def __init__(self, message: str = "Forbidden", *, missing_privilege: str | None = None) -> None:
        super().__init__(message)
        self.missing_privilege = missing_privilege
