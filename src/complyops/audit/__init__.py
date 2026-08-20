"""Tamper-evident audit log for the compliance operations console (AUD-001)."""

from .anchor import Anchor, AnchorError, read_anchor, write_anchor
from .chain import AuditChain, AuditEntry, ChainVerdict, verify_log, verify_sample
from .hashing import (
    FIELD_ORDER,
    GENESIS_HASH,
    HASH_LENGTH,
    AuditHashError,
    canonical_payload,
    entry_hash,
    hashes_equal,
    is_hash,
)
from .keys import AuditKeyError, key_id, signing_key, verification_keys
from .validation import FIELD_LIMITS, AuditFieldError, check_key_id, normalise_fields

__all__ = [
    "FIELD_LIMITS",
    "FIELD_ORDER",
    "GENESIS_HASH",
    "HASH_LENGTH",
    "Anchor",
    "AnchorError",
    "AuditChain",
    "AuditEntry",
    "AuditFieldError",
    "AuditHashError",
    "AuditKeyError",
    "ChainVerdict",
    "canonical_payload",
    "check_key_id",
    "entry_hash",
    "hashes_equal",
    "is_hash",
    "key_id",
    "normalise_fields",
    "read_anchor",
    "signing_key",
    "verification_keys",
    "verify_log",
    "verify_sample",
    "write_anchor",
]
