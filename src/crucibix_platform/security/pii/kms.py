"""The KMS port and its adapters — the KEK (key-encryption-key) half of envelope encryption.

A **DEK** (data-encryption key, 256-bit AES) encrypts field values; the KEK wraps (encrypts) the DEK
so only the wrapped form is ever persisted by the key store. :class:`KmsPort` is the seam:

* :func:`KmsPort.generate_dek` mints a fresh DEK and returns both its plaintext (used in memory only,
  then cached) and its wrapped form (persisted).
* :func:`KmsPort.unwrap` turns a stored wrapped DEK back into plaintext — the **one** call on the
  decrypt path, and the keyring caches its result so the hot path never hits the KEK again.

Two adapters:

* :class:`LocalKms` — a local-dev/test KEK: a 32-byte master key from config wraps DEKs with
  AES-256-GCM. No AWS, no network. **Not for production** beyond local compose.
* :class:`AwsKms` — AWS KMS (``GenerateDataKey``/``Decrypt``); the KEK never leaves KMS. Requires the
  ``aws`` extra (boto3). Injectable client makes it unit-testable without AWS.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crucibix_platform.security.pii.errors import KmsError

DEK_BYTES = 32  # AES-256
_WRAP_NONCE_BYTES = 12  # GCM standard nonce


@dataclass(frozen=True, slots=True)
class WrappedDek:
    """A DEK encrypted under a KEK — the only form that is ever persisted.

    ``key_id`` records which KEK wrapped it (the AWS KMS key id/ARN, or the LocalKms key id), so the
    right KEK is used to unwrap and a mismatch is caught rather than silently mis-decrypting.
    """

    key_id: str
    ciphertext: bytes


@dataclass(frozen=True, slots=True)
class GeneratedDek:
    """A freshly minted DEK: the plaintext (in-memory use only, then cached) + its wrapped form."""

    plaintext: bytes
    wrapped: WrappedDek


class KmsPort(Protocol):
    """Wrap/unwrap a per-org DEK. Implemented by :class:`LocalKms` and :class:`AwsKms`."""

    def generate_dek(self) -> GeneratedDek: ...
    def unwrap(self, wrapped: WrappedDek) -> bytes: ...


class LocalKms:
    """Local-dev/test KEK: an in-process 32-byte master key wraps DEKs with AES-256-GCM.

    The master key is config-supplied (``CRUCIBIX_PII_MASTER_KEY``, base64 of 32 bytes) so wrapped
    DEKs survive restarts; :meth:`generate` mints an ephemeral one for throwaway tests. The wrapped
    blob is ``nonce || ct`` and the ``key_id`` is bound as AES-GCM associated data, so a blob wrapped
    under a different key id (or a tampered one) fails to unwrap instead of returning garbage.
    """

    def __init__(self, master_key: bytes, *, key_id: str = "local") -> None:
        if len(master_key) != DEK_BYTES:
            raise KmsError(f"LocalKms master key must be {DEK_BYTES} bytes, got {len(master_key)}")
        self._master = master_key
        self._key_id = key_id

    @classmethod
    def from_base64(cls, value: str, *, key_id: str = "local") -> LocalKms:
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise KmsError("LocalKms master key is not valid base64") from exc
        return cls(raw, key_id=key_id)

    @classmethod
    def generate(cls, *, key_id: str = "local") -> LocalKms:
        """Mint an ephemeral master key — for tests / throwaway dev only (data dies with the process)."""
        return cls(os.urandom(DEK_BYTES), key_id=key_id)

    def generate_dek(self) -> GeneratedDek:
        dek = os.urandom(DEK_BYTES)
        nonce = os.urandom(_WRAP_NONCE_BYTES)
        ct = AESGCM(self._master).encrypt(nonce, dek, self._key_id.encode())
        return GeneratedDek(plaintext=dek, wrapped=WrappedDek(self._key_id, nonce + ct))

    def unwrap(self, wrapped: WrappedDek) -> bytes:
        if wrapped.key_id != self._key_id:
            raise KmsError(f"wrapped DEK uses KEK {wrapped.key_id!r}, this LocalKms is {self._key_id!r}")
        blob = wrapped.ciphertext
        nonce, ct = blob[:_WRAP_NONCE_BYTES], blob[_WRAP_NONCE_BYTES:]
        try:
            return AESGCM(self._master).decrypt(nonce, ct, wrapped.key_id.encode())
        except InvalidTag as exc:
            raise KmsError("could not unwrap DEK (wrong master key or tampered wrapped DEK)") from exc


class AwsKms:
    """AWS KMS KEK adapter. The customer master key never leaves KMS; we only ship it DEKs to wrap
    and wrapped DEKs to unwrap. Requires the ``aws`` extra (boto3). Pass ``client`` to inject a stub
    in tests; otherwise a ``kms`` client is created lazily.
    """

    def __init__(
        self,
        *,
        key_id: str,
        region: str,
        endpoint_url: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._key_id = key_id
        if client is not None:
            self._client = client
        else:
            import boto3  # lazy: only needed for the real adapter

            self._client = boto3.client("kms", region_name=region, endpoint_url=endpoint_url)

    def generate_dek(self) -> GeneratedDek:
        resp = self._client.generate_data_key(KeyId=self._key_id, KeySpec="AES_256")
        plaintext: bytes = resp["Plaintext"]
        if len(plaintext) != DEK_BYTES:
            raise KmsError(f"KMS returned a {len(plaintext)}-byte DEK, expected {DEK_BYTES}")
        # resp["KeyId"] is the fully-qualified ARN of the CMK that wrapped it.
        return GeneratedDek(plaintext=plaintext, wrapped=WrappedDek(resp["KeyId"], resp["CiphertextBlob"]))

    def unwrap(self, wrapped: WrappedDek) -> bytes:
        try:
            resp = self._client.decrypt(CiphertextBlob=wrapped.ciphertext, KeyId=wrapped.key_id)
        except Exception as exc:  # boto3 ClientError et al. — normalise to our hierarchy
            raise KmsError(f"KMS decrypt failed for KEK {wrapped.key_id!r}") from exc
        plaintext: bytes = resp["Plaintext"]
        return plaintext


__all__ = [
    "DEK_BYTES",
    "WrappedDek",
    "GeneratedDek",
    "KmsPort",
    "LocalKms",
    "AwsKms",
]
