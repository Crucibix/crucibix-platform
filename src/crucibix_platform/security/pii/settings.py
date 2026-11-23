"""Settings mixin for PII field encryption.

A service that stores PII extends this instead of :class:`~crucibix_platform.config.PlatformSettings`
directly. All env vars carry the platform ``CRUCIBIX_`` prefix, e.g. ``pii_master_key`` ←
``CRUCIBIX_PII_MASTER_KEY``. The master key / KMS key id are **references or injected secrets**, never
committed — supply them via the environment (local) or AWS Secrets Manager / the KMS key policy (prod).
"""

from __future__ import annotations

from crucibix_platform.config import PlatformSettings


class PiiEncryptionSettings(PlatformSettings):
    """The ``CRUCIBIX_PII_*`` knobs selecting and configuring the KEK adapter."""

    # KEK adapter: "local" (AES-GCM master key, dev/compose) | "aws" (AWS KMS).
    pii_kms_mode: str = "local"
    # LOCAL mode: base64 of a 32-byte master key. Required outside dev; dev mints an ephemeral key
    # (and logs a warning) when unset, so data does NOT survive a restart.
    pii_master_key: str | None = None
    pii_local_key_id: str = "local"
    # AWS mode: the customer master key id/ARN used for GenerateDataKey / Decrypt.
    pii_kms_key_id: str | None = None


__all__ = ["PiiEncryptionSettings"]
