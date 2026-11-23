"""SQLAlchemy column support for PII — the :class:`EncryptedType` ``TypeDecorator`` + its context.

Apply :class:`EncryptedType` to a PII column (``investor_pii``, ``employee_pii``, ``salary``,
``patient_pii``, …) and values are transparently encrypted on write and decrypted on read. The
ciphertext is stored as a portable ``Text`` token (see
:class:`~crucibix_platform.security.pii.cipher.Ciphertext`).

**Carrying the org context.** A column type has no idea which tenant a row belongs to, and the right
DEK is per-org — so the active :class:`~crucibix_platform.security.pii.cipher.EnvelopeCipher` is
carried in a :class:`~contextvars.ContextVar`, exactly like the request tenant in
:mod:`crucibix_platform.tenancy`. A service binds the org's cipher for the unit of work::

    with pii_encryption(cipher_for(auth.tenant_id)):
        investor = repo.get(investor_id)   # employee_pii decrypted with THIS org's DEK
        ...

Reading or writing an :class:`EncryptedType` column with no bound cipher raises
:class:`~crucibix_platform.security.pii.errors.PiiContextError` — it never reads/writes plaintext.
``None`` always maps to ``None`` (a NULL column is not encrypted).

``salary``-style non-string columns pass a ``serializer``/``deserializer`` pair, e.g.
``EncryptedType(serializer=str, deserializer=int)``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any

from sqlalchemy import Dialect, Text
from sqlalchemy.types import TypeDecorator

from crucibix_platform.security.pii.cipher import Ciphertext, EnvelopeCipher
from crucibix_platform.security.pii.errors import PiiContextError

_active_cipher: ContextVar[EnvelopeCipher | None] = ContextVar("crucibix_pii_cipher", default=None)


def current_cipher() -> EnvelopeCipher | None:
    """The cipher bound to the current context, or ``None``."""
    return _active_cipher.get()


def require_cipher() -> EnvelopeCipher:
    cipher = _active_cipher.get()
    if cipher is None:
        raise PiiContextError(
            "no active PII cipher — wrap the unit of work in pii_encryption(cipher) / bind_cipher()"
        )
    return cipher


def bind_cipher(cipher: EnvelopeCipher) -> Token[EnvelopeCipher | None]:
    """Bind ``cipher`` to the context; returns the token to pass to :func:`unbind_cipher`.

    Prefer the :func:`pii_encryption` context manager; use this pair directly when binding/unbinding
    straddle a framework boundary (e.g. a FastAPI dependency's setup/teardown).
    """
    return _active_cipher.set(cipher)


def unbind_cipher(token: Token[EnvelopeCipher | None]) -> None:
    _active_cipher.reset(token)


@contextmanager
def pii_encryption(cipher: EnvelopeCipher) -> Iterator[EnvelopeCipher]:
    """Bind ``cipher`` as the active per-org PII cipher for the duration of the block."""
    token = _active_cipher.set(cipher)
    try:
        yield cipher
    finally:
        _active_cipher.reset(token)


def _identity(value: str) -> Any:
    return value


class EncryptedType(TypeDecorator[Any]):
    """A column whose Python value is encrypted at rest with the context's per-org cipher.

    Stored as ``Text`` (a base64url envelope token), so it is portable across Postgres and SQLite.
    """

    impl = Text
    # Security type carrying per-instance (de)serializers and reading an ambient cipher — never let
    # SQLAlchemy cache a compiled form keyed only by the type class.
    cache_ok = False

    def __init__(
        self,
        *,
        serializer: Callable[[Any], str] = str,
        deserializer: Callable[[str], Any] = _identity,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._serializer = serializer
        self._deserializer = deserializer

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return require_cipher().encrypt_str(self._serializer(value)).serialize()

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        plaintext = require_cipher().decrypt_str(Ciphertext.deserialize(value))
        return self._deserializer(plaintext)


__all__ = [
    "EncryptedType",
    "pii_encryption",
    "bind_cipher",
    "unbind_cipher",
    "current_cipher",
    "require_cipher",
]
