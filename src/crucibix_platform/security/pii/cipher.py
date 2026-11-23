"""Field-level envelope encryption: :class:`EnvelopeCipher` + the :class:`Ciphertext` envelope.

A cipher is bound to one org's :class:`~crucibix_platform.security.pii.keyring.OrgKeyring`. It
encrypts/decrypts individual field values with that org's current DEK using **AES-256-GCM** (AEAD):

* a fresh random 96-bit nonce per value (never reused),
* the org id + key version bound as associated data (AAD), so a value cannot be decrypted under a
  different org or silently replayed against a different key version, and
* the key version stored in the envelope — the reference the keyring resolves to the (wrapped) DEK.

Any integrity failure — tampered ciphertext, wrong org, wrong/unknown DEK, malformed envelope —
raises :class:`~crucibix_platform.security.pii.errors.PiiDecryptionError`. The cipher **never**
returns plaintext on failure.

Rotation: :meth:`EnvelopeCipher.rotate` mints a new DEK version on the keyring and re-encrypts the
values you hand it to that new version; values still under an older version keep decrypting until
re-encrypted (incrementally via :meth:`EnvelopeCipher.reencrypt`).
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crucibix_platform.security.pii.errors import KmsError, PiiDecryptionError
from crucibix_platform.security.pii.keyring import DekVersion, OrgKeyring

_MAGIC = "cbx1"  # envelope format tag — bump if the wire format ever changes
_NONCE_BYTES = 12  # 96-bit GCM nonce


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _field_aad(organization_id: uuid.UUID, key_version: int) -> bytes:
    """Associated data bound into every field's AES-GCM tag: the org + the DEK version."""
    return f"{_MAGIC}:{organization_id}:{key_version}".encode()


@dataclass(frozen=True, slots=True)
class Ciphertext:
    """A self-describing encrypted field value.

    ``key_version`` is the reference the keyring resolves to the wrapped DEK; ``nonce`` + ``blob``
    are the AES-GCM nonce and ciphertext-with-tag. :meth:`serialize` renders a compact, DB-portable
    token (``cbx1:<version>:<nonce>:<blob>``, base64url) for storage in a text column.
    """

    key_version: int
    nonce: bytes
    blob: bytes

    def serialize(self) -> str:
        return f"{_MAGIC}:{self.key_version}:{_b64e(self.nonce)}:{_b64e(self.blob)}"

    @classmethod
    def deserialize(cls, token: str) -> Ciphertext:
        parts = token.split(":")
        if len(parts) != 4 or parts[0] != _MAGIC:
            raise PiiDecryptionError("malformed PII envelope (bad prefix or structure)")
        try:
            version = int(parts[1])
            nonce = _b64d(parts[2])
            blob = _b64d(parts[3])
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise PiiDecryptionError("malformed PII envelope (unparseable fields)") from exc
        if len(nonce) != _NONCE_BYTES:
            raise PiiDecryptionError("malformed PII envelope (bad nonce length)")
        return cls(key_version=version, nonce=nonce, blob=blob)


@dataclass(frozen=True, slots=True)
class RotationResult:
    """The outcome of :meth:`EnvelopeCipher.rotate`: the new version + the re-encrypted values
    (in the same order they were supplied)."""

    version: DekVersion
    reencrypted: tuple[Ciphertext, ...]


class EnvelopeCipher:
    """Per-org field encryption over an :class:`OrgKeyring`."""

    def __init__(self, keyring: OrgKeyring) -> None:
        self._keyring = keyring

    @property
    def organization_id(self) -> uuid.UUID:
        return self._keyring.organization_id

    @property
    def keyring(self) -> OrgKeyring:
        return self._keyring

    # ── raw bytes ────────────────────────────────────────────────────────────────────────────────
    def encrypt(self, plaintext: bytes) -> Ciphertext:
        version = self._keyring.current_version
        dek = self._keyring.dek(version)
        nonce = os.urandom(_NONCE_BYTES)
        aad = _field_aad(self.organization_id, version)
        blob = AESGCM(dek).encrypt(nonce, plaintext, aad)
        return Ciphertext(key_version=version, nonce=nonce, blob=blob)

    def decrypt(self, ciphertext: Ciphertext) -> bytes:
        aad = _field_aad(self.organization_id, ciphertext.key_version)
        try:
            dek = self._keyring.dek(ciphertext.key_version)
            return AESGCM(dek).decrypt(ciphertext.nonce, ciphertext.blob, aad)
        except InvalidTag as exc:
            raise PiiDecryptionError(
                "PII decryption failed: wrong org/key or tampered ciphertext"
            ) from exc
        except KmsError as exc:  # unknown version, unwrap failure, bad DEK length
            raise PiiDecryptionError(f"PII decryption failed: {exc}") from exc

    # ── str convenience (UTF-8) ──────────────────────────────────────────────────────────────────
    def encrypt_str(self, plaintext: str) -> Ciphertext:
        return self.encrypt(plaintext.encode("utf-8"))

    def decrypt_str(self, ciphertext: Ciphertext) -> str:
        try:
            return self.decrypt(ciphertext).decode("utf-8")
        except UnicodeDecodeError as exc:  # decrypted but not text — treat as an integrity failure
            raise PiiDecryptionError("PII plaintext is not valid UTF-8") from exc

    # ── rotation ─────────────────────────────────────────────────────────────────────────────────
    def reencrypt(self, ciphertext: Ciphertext) -> Ciphertext:
        """Decrypt under whatever version it carries, re-encrypt under the current version.

        A no-op-shaped call when the value is already current (it still re-nonces). Used for lazy /
        incremental re-encryption outside a full :meth:`rotate`.
        """
        return self.encrypt(self.decrypt(ciphertext))

    def rotate(self, values: Iterable[Ciphertext] = ()) -> RotationResult:
        """Mint a new DEK version (now current) and re-encrypt ``values`` to it.

        Values not passed here keep their old version and still decrypt (the old DEK is retained);
        re-encrypt them later with :meth:`reencrypt`.
        """
        new_version = self._keyring.rotate()
        reencrypted = tuple(self.reencrypt(c) for c in values)
        return RotationResult(version=new_version, reencrypted=reencrypted)


__all__ = ["Ciphertext", "RotationResult", "EnvelopeCipher"]
