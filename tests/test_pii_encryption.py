"""Tests for the per-org PII field-encryption kernel (``crucibix_platform.security.pii``).

Covers: envelope round-trip (bytes + str), random nonce, wrong-org / wrong-DEK / tampered-ciphertext
/ malformed-envelope all raising (never returning plaintext), DEK-version rotation (old still
decrypts, re-encrypt moves to the new version), the keyring's unwrap cache (no KEK call on the hot
path), the LocalKms / AwsKms KEK adapters, the settings-driven factory, and the ``EncryptedType``
SQLAlchemy column round-tripping through a real (SQLite) session.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from crucibix_platform.security.pii import (
    AwsKms,
    Ciphertext,
    EncryptedType,
    EnvelopeCipher,
    GeneratedDek,
    KmsError,
    LocalKms,
    OrgKeyring,
    PiiConfigError,
    PiiContextError,
    PiiDecryptionError,
    PiiEncryptionSettings,
    UnknownKeyVersion,
    WrappedDek,
    build_kms,
    pii_encryption,
)
from crucibix_platform.security.pii.kms import KmsPort

ORG_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
ORG_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


def _kms() -> LocalKms:
    return LocalKms.generate(key_id="test-kek")


def _cipher(org: uuid.UUID = ORG_A, kms: KmsPort | None = None) -> EnvelopeCipher:
    return EnvelopeCipher(OrgKeyring.create(org, kms or _kms()))


# ── envelope round-trip ──────────────────────────────────────────────────────────────────────────
def test_round_trip_bytes_and_str() -> None:
    cipher = _cipher()
    assert cipher.decrypt(cipher.encrypt(b"\x00\x01\x02secret")) == b"\x00\x01\x02secret"
    assert cipher.decrypt_str(cipher.encrypt_str("Priya Sharma · 90210")) == "Priya Sharma · 90210"


def test_nonce_is_random_but_both_decrypt() -> None:
    cipher = _cipher()
    c1 = cipher.encrypt_str("same value")
    c2 = cipher.encrypt_str("same value")
    assert c1.nonce != c2.nonce
    assert c1.blob != c2.blob  # different nonce -> different ciphertext (not a deterministic cipher)
    assert cipher.decrypt_str(c1) == cipher.decrypt_str(c2) == "same value"


def test_serialize_round_trip_is_portable_text() -> None:
    cipher = _cipher()
    token = cipher.encrypt_str("patient#42").serialize()
    assert token.startswith("cbx1:1:")
    assert cipher.decrypt_str(Ciphertext.deserialize(token)) == "patient#42"


# ── failure modes: always raise, never leak plaintext ──────────────────────────────────────────────
def test_wrong_org_fails() -> None:
    a = _cipher(ORG_A)
    b = _cipher(ORG_B)
    ct = a.encrypt_str("org A only")
    with pytest.raises(PiiDecryptionError):
        b.decrypt_str(ct)


def test_wrong_dek_same_org_fails() -> None:
    # Same org id, but an independently-minted DEK (as if a mis-wired keyring).
    a = _cipher(ORG_A)
    other = _cipher(ORG_A)
    ct = a.encrypt_str("secret")
    with pytest.raises(PiiDecryptionError):
        other.decrypt_str(ct)


def test_tampered_ciphertext_fails() -> None:
    cipher = _cipher()
    ct = cipher.encrypt_str("do not tamper")
    flipped = bytearray(ct.blob)
    flipped[-1] ^= 0x01
    with pytest.raises(PiiDecryptionError):
        cipher.decrypt(Ciphertext(ct.key_version, ct.nonce, bytes(flipped)))


def test_tampered_nonce_fails() -> None:
    cipher = _cipher()
    ct = cipher.encrypt_str("x")
    bad = bytearray(ct.nonce)
    bad[0] ^= 0xFF
    with pytest.raises(PiiDecryptionError):
        cipher.decrypt(Ciphertext(ct.key_version, bytes(bad), ct.blob))


@pytest.mark.parametrize("token", ["", "plain", "cbx1:1:onlythree", "xxxx:1:aa:bb", "cbx1:x:aa:bb"])
def test_malformed_envelope_fails(token: str) -> None:
    with pytest.raises(PiiDecryptionError):
        Ciphertext.deserialize(token)


def test_unknown_key_version_fails() -> None:
    cipher = _cipher()
    good = cipher.encrypt_str("v1")
    with pytest.raises(PiiDecryptionError):
        cipher.decrypt(Ciphertext(key_version=99, nonce=good.nonce, blob=good.blob))


# ── rotation ───────────────────────────────────────────────────────────────────────────────────────
def test_rotation_old_decrypts_new_version_used() -> None:
    cipher = _cipher()
    old = cipher.encrypt_str("before rotation")
    assert old.key_version == 1

    result = cipher.rotate()  # mint v2, no values to re-encrypt
    assert result.version.version == 2
    assert cipher.keyring.current_version == 2

    # Old value (v1) still decrypts; new encryptions use v2.
    assert cipher.decrypt_str(old) == "before rotation"
    fresh = cipher.encrypt_str("after rotation")
    assert fresh.key_version == 2
    assert cipher.decrypt_str(fresh) == "after rotation"


def test_rotation_reencrypts_given_values() -> None:
    cipher = _cipher()
    values = [cipher.encrypt_str(f"v{i}") for i in range(3)]
    assert all(v.key_version == 1 for v in values)

    result = cipher.rotate(values)
    assert result.version.version == 2
    assert [c.key_version for c in result.reencrypted] == [2, 2, 2]
    assert [cipher.decrypt_str(c) for c in result.reencrypted] == ["v0", "v1", "v2"]
    # Originals (still v1) remain decryptable until dropped.
    assert [cipher.decrypt_str(v) for v in values] == ["v0", "v1", "v2"]


def test_reencrypt_moves_to_current_version() -> None:
    cipher = _cipher()
    v1 = cipher.encrypt_str("s")
    cipher.rotate()
    cipher.rotate()  # current is now v3
    v3 = cipher.reencrypt(v1)
    assert v3.key_version == 3
    assert cipher.decrypt_str(v3) == "s"


def test_keyring_versions_persistable_shape() -> None:
    cipher = _cipher()
    cipher.rotate()
    versions = cipher.keyring.versions()
    assert [v.version for v in versions] == [1, 2]
    assert all(isinstance(v.wrapped, WrappedDek) for v in versions)


# ── keyring unwrap cache: no KEK call on the hot path ──────────────────────────────────────────────
class _CountingKms:
    """Wraps a real KEK and counts unwrap (= the would-be network) calls."""

    def __init__(self, inner: KmsPort) -> None:
        self._inner = inner
        self.unwraps = 0

    def generate_dek(self) -> GeneratedDek:
        return self._inner.generate_dek()

    def unwrap(self, wrapped: WrappedDek) -> bytes:
        self.unwraps += 1
        return self._inner.unwrap(wrapped)


def test_create_seeds_cache_no_unwrap_on_hot_path() -> None:
    kms = _CountingKms(_kms())
    cipher = EnvelopeCipher(OrgKeyring.create(ORG_A, kms))
    ct = cipher.encrypt_str("hot")
    for _ in range(50):
        assert cipher.decrypt_str(ct) == "hot"
    assert kms.unwraps == 0  # the DEK we just generated was cached — never unwrapped


def test_loaded_keyring_unwraps_once_then_caches() -> None:
    kms = _CountingKms(_kms())
    seed = EnvelopeCipher(OrgKeyring.create(ORG_A, kms))
    ct = seed.encrypt_str("persisted")
    versions = seed.keyring.versions()
    current = seed.keyring.current_version

    # Reload from persisted versions (fresh, cold cache) — as identity-access would per request.
    reloaded = EnvelopeCipher(OrgKeyring.load(ORG_A, kms, versions, current))
    before = kms.unwraps
    for _ in range(20):
        assert reloaded.decrypt_str(ct) == "persisted"
    assert kms.unwraps - before == 1  # exactly one unwrap, then served from cache


# ── LocalKms KEK ────────────────────────────────────────────────────────────────────────────────────
def test_localkms_wrap_unwrap_round_trip() -> None:
    kms = _kms()
    gen = kms.generate_dek()
    assert len(gen.plaintext) == 32
    assert kms.unwrap(gen.wrapped) == gen.plaintext


def test_localkms_rejects_bad_master_length() -> None:
    with pytest.raises(KmsError):
        LocalKms(os.urandom(16))


def test_localkms_unwrap_wrong_kek_fails() -> None:
    k1 = LocalKms.generate(key_id="kek-1")
    k2 = LocalKms.generate(key_id="kek-2")
    gen = k1.generate_dek()
    with pytest.raises(KmsError):
        k2.unwrap(gen.wrapped)  # different key id -> refused


def test_localkms_from_base64_round_trip_and_bad_input() -> None:
    raw = os.urandom(32)
    kms = LocalKms.from_base64(base64.b64encode(raw).decode())
    gen = kms.generate_dek()
    assert kms.unwrap(gen.wrapped) == gen.plaintext
    with pytest.raises(KmsError):
        LocalKms.from_base64("not base64 !!!")


def test_tampered_wrapped_dek_unwrap_fails() -> None:
    kms = _kms()
    gen = kms.generate_dek()
    bad = bytearray(gen.wrapped.ciphertext)
    bad[-1] ^= 0x01
    with pytest.raises(KmsError):
        kms.unwrap(WrappedDek(gen.wrapped.key_id, bytes(bad)))


# ── AwsKms KEK (stubbed boto3 client) ─────────────────────────────────────────────────────────────
class _FakeKmsClient:
    """Mimics the boto3 kms client's GenerateDataKey/Decrypt by wrapping with a backing LocalKms."""

    def __init__(self) -> None:
        self._backing = LocalKms.generate(key_id="arn:aws:kms:ap-south-1:0:key/cmk-1")

    def generate_data_key(self, *, KeyId: str, KeySpec: str) -> dict[str, object]:
        assert KeySpec == "AES_256"
        gen = self._backing.generate_dek()
        return {"Plaintext": gen.plaintext, "CiphertextBlob": gen.wrapped.ciphertext, "KeyId": KeyId}

    def decrypt(self, *, CiphertextBlob: bytes, KeyId: str) -> dict[str, object]:
        return {"Plaintext": self._backing.unwrap(WrappedDek(KeyId, CiphertextBlob))}


def test_awskms_round_trip_with_stub_client() -> None:
    client = _FakeKmsClient()
    kms = AwsKms(key_id="arn:aws:kms:ap-south-1:0:key/cmk-1", region="ap-south-1", client=client)
    cipher = EnvelopeCipher(OrgKeyring.create(ORG_A, kms))
    ct = cipher.encrypt_str("via KMS")
    assert cipher.decrypt_str(ct) == "via KMS"
    # And a cold reload unwraps through the KMS client.
    reloaded = EnvelopeCipher(
        OrgKeyring.load(ORG_A, kms, cipher.keyring.versions(), cipher.keyring.current_version)
    )
    assert reloaded.decrypt_str(ct) == "via KMS"


def test_awskms_decrypt_error_is_kmserror() -> None:
    class _Boom:
        def decrypt(self, **_: object) -> dict[str, object]:
            raise RuntimeError("AccessDeniedException")

    kms = AwsKms(key_id="k", region="ap-south-1", client=_Boom())
    with pytest.raises(KmsError):
        kms.unwrap(WrappedDek("k", b"blob"))


# ── factory ─────────────────────────────────────────────────────────────────────────────────────────
def test_factory_local_from_master_key() -> None:
    raw = base64.b64encode(os.urandom(32)).decode()
    kms = build_kms(PiiEncryptionSettings(environment="prod", pii_kms_mode="local", pii_master_key=raw))
    assert isinstance(kms, LocalKms)


def test_factory_local_requires_key_outside_dev() -> None:
    with pytest.raises(PiiConfigError):
        build_kms(PiiEncryptionSettings(environment="prod", pii_kms_mode="local", pii_master_key=None))


def test_factory_dev_ephemeral_ok() -> None:
    kms = build_kms(PiiEncryptionSettings(environment="dev", pii_kms_mode="local"))
    assert isinstance(kms, LocalKms)


def test_factory_aws_requires_key_id() -> None:
    with pytest.raises(PiiConfigError):
        build_kms(PiiEncryptionSettings(pii_kms_mode="aws", pii_kms_key_id=None))


def test_factory_aws_builds_with_injected_client() -> None:
    kms = build_kms(
        PiiEncryptionSettings(pii_kms_mode="aws", pii_kms_key_id="cmk-1"), client=_FakeKmsClient()
    )
    assert isinstance(kms, AwsKms)


def test_factory_unknown_mode() -> None:
    with pytest.raises(PiiConfigError):
        build_kms(PiiEncryptionSettings(pii_kms_mode="rot13"))


# ── EncryptedType through a real SQLAlchemy session ───────────────────────────────────────────────
class _Base(DeclarativeBase):
    pass


class Patient(_Base):
    __tablename__ = "patients"
    id: Mapped[int] = mapped_column(primary_key=True)
    patient_pii: Mapped[str] = mapped_column(EncryptedType())
    salary: Mapped[int] = mapped_column(EncryptedType(serializer=str, deserializer=int))
    note: Mapped[str | None] = mapped_column(EncryptedType(), nullable=True)


def test_encrypted_type_round_trips_through_session() -> None:
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    cipher = _cipher(ORG_A)

    with pii_encryption(cipher), Session(engine) as s:
        s.add(Patient(id=1, patient_pii="Sam Lee, DOB 1990-01-01", salary=125_000, note=None))
        s.commit()

    with pii_encryption(cipher), Session(engine) as s:
        row = s.get(Patient, 1)
        assert row is not None
        assert row.patient_pii == "Sam Lee, DOB 1990-01-01"
        assert row.salary == 125_000  # deserialized back to int
        assert row.note is None


def test_encrypted_type_persists_ciphertext_not_plaintext() -> None:
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    cipher = _cipher(ORG_A)
    with pii_encryption(cipher), Session(engine) as s:
        s.add(Patient(id=1, patient_pii="TOP SECRET", salary=1, note=None))
        s.commit()

    # Read the raw stored string without decrypting -> it must be an opaque envelope.
    with engine.connect() as conn:
        stored = conn.exec_driver_sql("SELECT patient_pii FROM patients WHERE id = 1").scalar_one()
    assert "TOP SECRET" not in stored
    assert stored.startswith("cbx1:")


def test_encrypted_type_without_bound_cipher_raises() -> None:
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    with Session(engine) as s:  # no pii_encryption(...) binding
        s.add(Patient(id=1, patient_pii="x", salary=1, note=None))
        with pytest.raises(StatementError) as exc:
            s.commit()
        assert isinstance(exc.value.orig, PiiContextError)


def test_encrypted_type_wrong_org_cannot_read() -> None:
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    with pii_encryption(_cipher(ORG_A)), Session(engine) as s:
        s.add(Patient(id=1, patient_pii="org A PII", salary=1, note=None))
        s.commit()
    # A different org's cipher must not be able to decrypt it.
    with pii_encryption(_cipher(ORG_B)), Session(engine) as s:
        with pytest.raises(PiiDecryptionError):
            _ = s.get(Patient, 1)


def test_errors_are_not_domain_errors() -> None:
    from crucibix_platform.domain.errors import DomainError

    assert not issubclass(PiiDecryptionError, DomainError)
    assert not issubclass(UnknownKeyVersion, DomainError)
