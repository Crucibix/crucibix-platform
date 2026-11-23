"""Per-org PII field encryption — envelope encryption with rotation, for the whole fleet.

The compliance gate (gap #15) requires sensitive columns — ``investor_pii``, ``employee_pii``,
``salary``, ``patient_pii`` and the like — to be encrypted at rest with a **per-org** key. This
package is the shared, service-agnostic kernel; the identity-access *org keyring API* (DEK storage +
a rotation endpoint) is a separate service that wires these pieces to a key store.

**Envelope encryption.** A per-org 256-bit **DEK** encrypts field values (AES-256-GCM, random nonce,
org+version bound as AAD). The DEK is itself wrapped by a **KEK** via a :class:`KmsPort`
(:class:`LocalKms` for dev, :class:`AwsKms` for prod) so only the wrapped DEK is persisted. The decrypt
hot path uses a cached unwrapped DEK — no KEK/network call per value. Any tamper / wrong key / wrong
org / malformed envelope **raises** (:class:`PiiDecryptionError`); plaintext is never returned on failure.

Layers:

* :mod:`~crucibix_platform.security.pii.kms` — :class:`KmsPort` + :class:`WrappedDek` /
  :class:`GeneratedDek`, and the :class:`LocalKms` / :class:`AwsKms` adapters.
* :mod:`~crucibix_platform.security.pii.keyring` — :class:`OrgKeyring` (pure per-org DEK-version model
  with an unwrap cache) + :class:`DekVersion` (the persistable shape).
* :mod:`~crucibix_platform.security.pii.cipher` — :class:`EnvelopeCipher` (field encrypt/decrypt +
  :meth:`~EnvelopeCipher.rotate`), the :class:`Ciphertext` envelope, and :class:`RotationResult`.
* :mod:`~crucibix_platform.security.pii.types` — the :class:`EncryptedType` SQLAlchemy column +
  :func:`pii_encryption` to bind the active per-org cipher.
* :mod:`~crucibix_platform.security.pii.settings` / :mod:`~crucibix_platform.security.pii.factory` —
  the ``CRUCIBIX_PII_*`` settings mixin and :func:`build_kms`.

Adopt it in a service (model + per-request binding)::

    from crucibix_platform.security.pii import EncryptedType, pii_encryption, EnvelopeCipher, OrgKeyring

    class Employee(Base, TenantScopedMixin):
        __tablename__ = "employees"
        employee_pii: Mapped[str] = mapped_column(EncryptedType())
        salary: Mapped[int] = mapped_column(EncryptedType(serializer=str, deserializer=int))

    cipher = EnvelopeCipher(OrgKeyring.load(org_id, kms, versions, current))  # from the key store
    with pii_encryption(cipher):   # bind once per unit of work (tenant known)
        session.add(Employee(organization_id=org_id, employee_pii="…", salary=90_000))
        session.commit()           # employee_pii + salary encrypted with THIS org's DEK
"""

from __future__ import annotations

from crucibix_platform.security.pii.cipher import Ciphertext, EnvelopeCipher, RotationResult
from crucibix_platform.security.pii.errors import (
    KmsError,
    PiiConfigError,
    PiiContextError,
    PiiDecryptionError,
    PiiEncryptionError,
    PiiError,
    UnknownKeyVersion,
)
from crucibix_platform.security.pii.factory import build_kms
from crucibix_platform.security.pii.keyring import DekVersion, OrgKeyring
from crucibix_platform.security.pii.kms import (
    DEK_BYTES,
    AwsKms,
    GeneratedDek,
    KmsPort,
    LocalKms,
    WrappedDek,
)
from crucibix_platform.security.pii.settings import PiiEncryptionSettings
from crucibix_platform.security.pii.types import (
    EncryptedType,
    bind_cipher,
    current_cipher,
    pii_encryption,
    require_cipher,
    unbind_cipher,
)

__all__ = [
    # KMS / KEK
    "KmsPort",
    "LocalKms",
    "AwsKms",
    "WrappedDek",
    "GeneratedDek",
    "DEK_BYTES",
    # keyring
    "OrgKeyring",
    "DekVersion",
    # cipher
    "EnvelopeCipher",
    "Ciphertext",
    "RotationResult",
    # SQLAlchemy column + context
    "EncryptedType",
    "pii_encryption",
    "bind_cipher",
    "unbind_cipher",
    "current_cipher",
    "require_cipher",
    # settings / factory
    "PiiEncryptionSettings",
    "build_kms",
    # errors
    "PiiError",
    "PiiConfigError",
    "KmsError",
    "PiiEncryptionError",
    "PiiDecryptionError",
    "UnknownKeyVersion",
    "PiiContextError",
]
