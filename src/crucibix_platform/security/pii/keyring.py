"""The per-org keyring — a pure DEK-version model the key store (identity-access) will wire later.

An :class:`OrgKeyring` holds one organization's DEK versions. Each :class:`DekVersion` is the
*persistable* shape (version number + wrapped DEK — never plaintext). The keyring unwraps a version's
DEK through the :class:`~crucibix_platform.security.pii.kms.KmsPort` **once** and caches the plaintext
in memory, so after the first touch the decrypt hot path makes no KEK/network call.

This module is deliberately free of any DB, HTTP or framework code: identity-access will persist
:meth:`OrgKeyring.versions` / :attr:`OrgKeyring.current_version` in its key store and rebuild a
keyring with :meth:`OrgKeyring.load`. Field encryption itself lives in
:class:`~crucibix_platform.security.pii.cipher.EnvelopeCipher`, which wraps a keyring.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from crucibix_platform.security.pii.errors import KmsError, UnknownKeyVersion
from crucibix_platform.security.pii.kms import DEK_BYTES, KmsPort, WrappedDek


@dataclass(frozen=True, slots=True)
class DekVersion:
    """One versioned, wrapped DEK — the unit the key store persists per org."""

    version: int
    wrapped: WrappedDek


class OrgKeyring:
    """A mutable in-memory view of one org's DEK versions, with a lazily-unwrapped DEK cache.

    Construct it with :meth:`create` (mint the first DEK) or :meth:`load` (rebuild from persisted
    versions). :meth:`rotate` mints a new current version; older versions are retained so values
    encrypted under them keep decrypting until re-encrypted.
    """

    def __init__(
        self,
        organization_id: uuid.UUID,
        kms: KmsPort,
        versions: Sequence[DekVersion],
        current_version: int,
    ) -> None:
        if not versions:
            raise KmsError("an OrgKeyring must have at least one DEK version")
        self._org = organization_id
        self._kms = kms
        self._versions: dict[int, DekVersion] = {v.version: v for v in versions}
        if current_version not in self._versions:
            raise KmsError(f"current_version {current_version} is not among the keyring's versions")
        self._current = current_version
        self._dek_cache: dict[int, bytes] = {}

    @classmethod
    def create(cls, organization_id: uuid.UUID, kms: KmsPort) -> OrgKeyring:
        """Mint a brand-new keyring for an org with a single version (v1) as current."""
        gen = kms.generate_dek()
        v1 = DekVersion(1, gen.wrapped)
        keyring = cls(organization_id, kms, [v1], 1)
        keyring._dek_cache[1] = gen.plaintext  # seed: no unwrap needed for the version we just made
        return keyring

    @classmethod
    def load(
        cls,
        organization_id: uuid.UUID,
        kms: KmsPort,
        versions: Sequence[DekVersion],
        current_version: int,
    ) -> OrgKeyring:
        """Rebuild a keyring from persisted versions (the key store's rows)."""
        return cls(organization_id, kms, versions, current_version)

    @property
    def organization_id(self) -> uuid.UUID:
        return self._org

    @property
    def current_version(self) -> int:
        return self._current

    def versions(self) -> tuple[DekVersion, ...]:
        """All versions, ascending — what the key store persists for this org."""
        return tuple(self._versions[v] for v in sorted(self._versions))

    def dek(self, version: int) -> bytes:
        """The plaintext DEK for ``version``. Unwraps via the KEK once, then serves from cache."""
        cached = self._dek_cache.get(version)
        if cached is not None:
            return cached
        dv = self._versions.get(version)
        if dv is None:
            raise UnknownKeyVersion(f"keyring for {self._org} has no DEK version {version}")
        dek = self._kms.unwrap(dv.wrapped)
        if len(dek) != DEK_BYTES:
            raise KmsError(f"unwrapped DEK for v{version} is {len(dek)} bytes, expected {DEK_BYTES}")
        self._dek_cache[version] = dek
        return dek

    def rotate(self) -> DekVersion:
        """Mint the next DEK version and make it current. Prior versions stay for decryption.

        Re-encrypting existing values to the new version is the cipher's job
        (:meth:`~crucibix_platform.security.pii.cipher.EnvelopeCipher.rotate`), since that needs the
        field-level crypto. This method only grows the keyring.
        """
        gen = self._kms.generate_dek()
        new_version = max(self._versions) + 1
        dv = DekVersion(new_version, gen.wrapped)
        self._versions[new_version] = dv
        self._dek_cache[new_version] = gen.plaintext
        self._current = new_version
        return dv


__all__ = ["DekVersion", "OrgKeyring"]
