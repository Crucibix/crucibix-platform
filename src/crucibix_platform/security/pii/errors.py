"""Error hierarchy for PII field encryption.

These are *infrastructure/security* errors, not domain errors (they deliberately do NOT subclass
:class:`crucibix_platform.domain.errors.DomainError`): a decryption or KMS failure is an internal
integrity/configuration problem, never something to surface to an API caller as a 4xx. The cardinal
rule is that any integrity or key failure **raises** — the library never silently returns plaintext
or a partial result.
"""

from __future__ import annotations


class PiiError(Exception):
    """Base for every PII-encryption failure."""


class PiiConfigError(PiiError):
    """The encryption stack is misconfigured (e.g. no master key outside dev, missing KMS key id)."""


class KmsError(PiiError):
    """A KMS (key-encryption-key) operation failed — wrap/unwrap, wrong KEK, or a malformed key."""


class PiiEncryptionError(PiiError):
    """A field value could not be encrypted."""


class PiiDecryptionError(PiiError):
    """A field value could not be decrypted — wrong org/DEK, tampered ciphertext, a malformed
    envelope, or an unknown key version. Raised instead of ever returning plaintext."""


class UnknownKeyVersion(KmsError):
    """A ciphertext referenced a DEK version the keyring does not hold."""


class PiiContextError(PiiError):
    """A :class:`~crucibix_platform.security.pii.types.EncryptedType` column was read or written with
    no active per-org cipher bound to the context (see ``pii_encryption``/``bind_cipher``)."""


__all__ = [
    "PiiError",
    "PiiConfigError",
    "KmsError",
    "PiiEncryptionError",
    "PiiDecryptionError",
    "UnknownKeyVersion",
    "PiiContextError",
]
