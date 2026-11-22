"""Crucibix platform: shared FastAPI + hexagonal/DDD building blocks for all services."""
from crucibix_platform.api.app import create_app
from crucibix_platform.auth.context import AuthContext
from crucibix_platform.auth.dependencies import CurrentAuth, current_auth, require_privilege
from crucibix_platform.config import PlatformSettings
from crucibix_platform.domain.base import AggregateRoot, DomainEvent, Entity, ValueObject
from crucibix_platform.domain.errors import (
    AccessDenied,
    Conflict,
    DomainError,
    EntityNotFound,
    InvariantViolation,
    ValidationError,
)

__all__ = [
    "create_app", "PlatformSettings", "AuthContext", "CurrentAuth", "current_auth",
    "require_privilege", "AggregateRoot", "Entity", "ValueObject", "DomainEvent",
    "DomainError", "AccessDenied", "Conflict", "EntityNotFound", "InvariantViolation",
    "ValidationError",
]
