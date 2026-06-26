"""sk_pqc — sovereign, app-agnostic hybrid post-quantum crypto primitives.

WHAT THIS IS
    A small, dependency-light Python library of *vetted* hybrid post-quantum
    cryptographic building blocks: a hybrid **X25519 + ML-KEM-768** key
    encapsulation mechanism (FIPS 203), the PQXDH-style message/envelope seal
    built on it, a metadata-sealing routing envelope, per-epoch group + 1:1 DM
    key ratchets, an anonymous-queue addressing + deniable-auth primitive, and a
    crypto-agility suite registry. It is the Python sibling of the public Dart
    ``sk_pqc`` package and is byte-for-byte interoperable with it (shared KAT).

WHAT IT IS FOR
    Drop hybrid post-quantum confidentiality into any app WITHOUT pulling in a
    messaging framework. The primitives never hand-roll lattice/curve math — the
    ML-KEM-768 leg is liboqs (via ``oqs``), the X25519 leg + HKDF + AES-256-GCM
    are ``cryptography`` (pyca). Hybrid means the derived secret is secure if
    EITHER the classical X25519 leg OR the ML-KEM-768 leg holds. No
    "quantum-proof" claims — see ``honest-claims`` in the README.

The KEM never silently downgrades: if the liboqs backend is missing the hybrid
operations raise :class:`~sk_pqc.pqkem.PqKemUnavailable` (a hard error). The
pure-pyca pieces (combiner KAT, suite registry, anon-queue codec/MAC, key
derivation) work with no PQ backend at all.
"""

from __future__ import annotations

__version__ = "0.1.0"

# ---- Hybrid KEM (X25519 + ML-KEM-768, FIPS 203) ---------------------------
from .pqkem import (
    CIPHERTEXT_LEN,
    HKDF_INFO,
    PRIVATE_KEY_LEN,
    PUBLIC_KEY_LEN,
    SUITE_ID,
    HybridKeyPair,
    PqKemError,
    PqKemFormatError,
    PqKemUnavailable,
    hybrid_decap,
    hybrid_encap,
    hybrid_keypair,
    is_available,
)

# ---- Crypto-agility suite registry ----------------------------------------
from .crypto_suites import (
    CryptoSuite,
    SuiteKind,
    SuiteStatus,
    active_suites,
    all_suites,
    get_suite,
    is_quantum_resistant,
    suite_status,
)

# ---- PQXDH-style DM / envelope seal ---------------------------------------
from .pqdm import (
    DowngradeDetected,
    PqDmError,
    PqDmFormatError,
    PrekeyBundle,
    negotiate_suite,
    open_sealed,
    seal,
)

# ---- Metadata-sealing routing envelope ------------------------------------
from .pqroute import (
    PqRouteError,
    PqRouteFormatError,
    PqRouteOpenError,
    open_routed,
    read_route_header,
    seal_routed,
)

# ---- Anonymous-queue addressing + deniable auth ---------------------------
from .anon_queue import (
    AnonQueueError,
    AnonQueueFormatError,
    auth_tag,
    decode_aqid,
    encode_aqid,
    new_queue_pair,
    verify_tag,
)

# ---- Epoch ratchets (group + 1:1 DM) --------------------------------------
from .group_ratchet import (
    EpochRatchet,
    GroupRatchetError,
    derive_message_key,
    new_epoch_secret,
    unwrap_epoch_secret,
    wrap_epoch_secret,
)
from .dm_ratchet import (
    DmRatchet,
    DmRatchetError,
    derive_dm_message_key,
    unwrap_dm_epoch_secret,
    wrap_dm_epoch_secret,
)

__all__ = [
    "__version__",
    # pqkem
    "HybridKeyPair",
    "PqKemError",
    "PqKemFormatError",
    "PqKemUnavailable",
    "hybrid_keypair",
    "hybrid_encap",
    "hybrid_decap",
    "is_available",
    "SUITE_ID",
    "PUBLIC_KEY_LEN",
    "PRIVATE_KEY_LEN",
    "CIPHERTEXT_LEN",
    "HKDF_INFO",
    # crypto_suites
    "CryptoSuite",
    "SuiteKind",
    "SuiteStatus",
    "get_suite",
    "all_suites",
    "active_suites",
    "suite_status",
    "is_quantum_resistant",
    # pqdm
    "PrekeyBundle",
    "PqDmError",
    "PqDmFormatError",
    "DowngradeDetected",
    "seal",
    "open_sealed",
    "negotiate_suite",
    # pqroute
    "PqRouteError",
    "PqRouteFormatError",
    "PqRouteOpenError",
    "seal_routed",
    "open_routed",
    "read_route_header",
    # anon_queue
    "AnonQueueError",
    "AnonQueueFormatError",
    "new_queue_pair",
    "encode_aqid",
    "decode_aqid",
    "auth_tag",
    "verify_tag",
    # group_ratchet
    "EpochRatchet",
    "GroupRatchetError",
    "derive_message_key",
    "new_epoch_secret",
    "wrap_epoch_secret",
    "unwrap_epoch_secret",
    # dm_ratchet
    "DmRatchet",
    "DmRatchetError",
    "derive_dm_message_key",
    "wrap_dm_epoch_secret",
    "unwrap_dm_epoch_secret",
]
