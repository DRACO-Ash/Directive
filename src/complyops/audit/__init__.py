"""Tamper-evident audit log for the compliance operations console (AUD-001)."""

from .chain import AuditChain, AuditEntry, ChainVerdict, verify_chain
from .hashing import (
    FIELD_ORDER,
    GENESIS_HASH,
    HASH_LENGTH,
    AuditHashError,
    canonical_payload,
    entry_hash,
    is_hash,
)

__all__ = [
    "FIELD_ORDER",
    "GENESIS_HASH",
    "HASH_LENGTH",
    "AuditChain",
    "AuditEntry",
    "AuditHashError",
    "ChainVerdict",
    "canonical_payload",
    "entry_hash",
    "is_hash",
    "verify_chain",
]
