"""Wire a :class:`~crucibix_platform.security.pii.kms.KmsPort` from service settings.

:func:`build_kms` is the single entry point a service's composition root calls. It is the only piece
that knows about environments: in ``aws`` mode it returns an :class:`AwsKms` bound to the configured
CMK; in ``local`` mode it uses the configured master key, and *only in dev* falls back to an ephemeral
key (with a warning) so a developer can boot with zero config.

The resulting port is handed to the key store (identity-access) to mint/unwrap per-org DEKs; this
library deliberately does not build the keyring here (that needs the org + persisted versions).
"""

from __future__ import annotations

from typing import Any

import structlog

from crucibix_platform.security.pii.errors import PiiConfigError
from crucibix_platform.security.pii.kms import AwsKms, KmsPort, LocalKms
from crucibix_platform.security.pii.settings import PiiEncryptionSettings

_log = structlog.get_logger(__name__)


def build_kms(settings: PiiEncryptionSettings, *, client: Any | None = None) -> KmsPort:
    """Build the KEK adapter selected by ``settings``. ``client`` injects a KMS client (aws mode)."""
    mode = settings.pii_kms_mode
    if mode == "aws":
        if not settings.pii_kms_key_id:
            raise PiiConfigError("CRUCIBIX_PII_KMS_KEY_ID is required when CRUCIBIX_PII_KMS_MODE=aws")
        return AwsKms(
            key_id=settings.pii_kms_key_id,
            region=settings.aws_region,
            endpoint_url=settings.aws_endpoint_url,
            client=client,
        )
    if mode == "local":
        if settings.pii_master_key:
            return LocalKms.from_base64(settings.pii_master_key, key_id=settings.pii_local_key_id)
        if settings.environment == "dev":
            _log.warning(
                "pii.kms.ephemeral_master_key",
                detail="CRUCIBIX_PII_MASTER_KEY unset in dev — minting an ephemeral key; "
                "encrypted data will NOT survive a restart",
            )
            return LocalKms.generate(key_id=settings.pii_local_key_id)
        raise PiiConfigError("CRUCIBIX_PII_MASTER_KEY is required outside dev when pii_kms_mode=local")
    raise PiiConfigError(f"unknown pii_kms_mode {mode!r} (expected 'local' or 'aws')")


__all__ = ["build_kms"]
