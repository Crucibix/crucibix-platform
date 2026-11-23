"""Security building blocks shared across the fleet.

Currently hosts :mod:`crucibix_platform.security.pii` — per-org PII field encryption (envelope
encryption with a KMS-wrapped data key, rotation, and a SQLAlchemy column type). Import from the
subpackage directly, e.g. ``from crucibix_platform.security.pii import EnvelopeCipher``.
"""
