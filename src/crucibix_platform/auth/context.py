"""The authorization context carried on every authenticated request.

Mirrors identity-access's ``AuthorizationContext`` (effective privileges = role privileges ∩
entitled modules). Services never recompute it; they trust the token/claims and enforce
required privileges + tenant scope with the dependencies in ``auth.dependencies``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AuthContext:
    subject: uuid.UUID
    email: str
    tenant_id: uuid.UUID | None  # None for platform operators / pre-tenant routes
    roles: frozenset[str] = field(default_factory=frozenset)
    privileges: frozenset[str] = field(default_factory=frozenset)  # effective privileges
    is_platform_operator: bool = False
    correlation_id: str | None = None

    def has_privilege(self, privilege: str) -> bool:
        return privilege in self.privileges

    def require_tenant(self) -> uuid.UUID:
        if self.tenant_id is None:
            raise PermissionError("No active tenant on this request")
        return self.tenant_id
