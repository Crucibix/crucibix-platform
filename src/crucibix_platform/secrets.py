"""SecretResolver adapters — resolve a Secrets Manager reference (ARN/name) to its live value.

Shared across the fleet (promoted out of ``crucibix-orders``): the resolved value is used transiently
for a single outbound auth call and is NEVER persisted into domain state or logged.
``EnvSecretResolver`` (local/test) reads from the process environment by a sanitized form of the
reference; ``SecretsManagerResolver`` reads AWS Secrets Manager (lazy boto3, requires the ``aws``
extra). Secrets are always *references* in config — the raw value is never committed or inlined.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Protocol

_SANITIZE = re.compile(r"[^A-Za-z0-9]+")


class SecretResolver(Protocol):
    def resolve(self, reference: str | None) -> str | None: ...


def _env_key(reference: str) -> str:
    name = reference.split(":secret:", 1)[-1] if ":secret:" in reference else reference
    return "CRUCIBIX_SECRET_" + _SANITIZE.sub("_", name).strip("_").upper()


class EnvSecretResolver:
    """Resolve a reference from the environment (local-dev / tests). Returns ``None`` if unset."""

    def resolve(self, reference: str | None) -> str | None:
        if not reference:
            return None
        return os.environ.get(_env_key(reference))


class SecretsManagerResolver:
    """Resolve a reference from AWS Secrets Manager, cached briefly. Requires the ``aws`` extra."""

    def __init__(
        self,
        *,
        region: str,
        endpoint_url: str | None = None,
        ttl_seconds: int = 60,
        client: Any | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, str | None]] = {}
        if client is not None:
            self._client = client
        else:
            import boto3  # lazy: only needed for the real adapter

            self._client = boto3.client("secretsmanager", region_name=region, endpoint_url=endpoint_url)

    def resolve(self, reference: str | None) -> str | None:
        if not reference:
            return None
        now = time.monotonic()
        cached = self._cache.get(reference)
        if cached is not None and now - cached[0] < self._ttl:
            return cached[1]
        resp = self._client.get_secret_value(SecretId=reference)
        value: str | None = resp.get("SecretString")
        self._cache[reference] = (now, value)
        return value


__all__ = ["SecretResolver", "EnvSecretResolver", "SecretsManagerResolver"]
