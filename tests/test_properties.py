"""Property-based tests for the sk_pqc crypto INVARIANTS (Hypothesis).

These complement the example-based suites with *generative* coverage of the
core security properties — the things that must hold for arbitrary valid keys,
arbitrary domain-separation labels, arbitrary epoch/index addressing, and
arbitrary single-byte tampering.

Invariants exercised:

  * **Hybrid KEM round-trip** — ``decap(encap(pk), sk) == shared`` for arbitrary
    valid hybrid keypairs and arbitrary HKDF ``info`` labels, and the secret is
    always 32 bytes. (Honest framing: the hybrid secret is safe if *either* the
    X25519 leg *or* the ML-KEM-768 leg holds — "either-leg", never
    "quantum-proof".)
  * **Tamper-evidence** — flipping any single byte of the ciphertext, or using a
    mismatched ``info`` label, makes the decapsulated secret differ from the
    sender's. (ML-KEM-768 uses *implicit rejection*, so a tampered ML-KEM leg
    does not raise — it yields a different secret; the X25519 leg likewise
    diverges. Either way the derived 32-byte secret no longer matches.)
  * **DM message-key derivation** — ``derive_dm_message_key`` is deterministic in
    ``(epoch_secret, epoch, index)`` and distinct for any two different
    ``(epoch, index)`` addresses; flipping any byte of the epoch secret changes
    the derived key.

The KEM properties require the liboqs/``oqs`` backend; they skip cleanly when it
is unavailable (never a silent classical downgrade — the library itself raises
``PqKemUnavailable`` in that case).
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sk_pqc.dm_ratchet import (
    EPOCH_SECRET_LEN,
    MESSAGE_KEY_LEN,
    DmRatchetError,
    derive_dm_message_key,
)
from sk_pqc.pqkem import (
    CIPHERTEXT_LEN,
    SHARED_SECRET_LEN,
    PqKemFormatError,
    hybrid_decap,
    hybrid_encap,
    hybrid_keypair,
    is_available,
)

_PQ = is_available()
pq_only = pytest.mark.skipif(
    not _PQ, reason="liboqs/oqs backend unavailable (hybrid KEM legs cannot run)"
)

# A small fixed pool of genuine hybrid keypairs. ML-KEM secret keys are not
# constructible from arbitrary bytes, so "arbitrary valid keys" means: draw from
# a pool of real, independently generated keypairs. Generated once at import so
# the property runs stay light (no per-example native keygen storm).
_KEYPAIRS = [hybrid_keypair() for _ in range(6)] if _PQ else []

# Hypothesis bytes strategies sized to the wire formats.
_info = st.binary(max_size=48)
_epoch_secrets = st.binary(min_size=EPOCH_SECRET_LEN, max_size=EPOCH_SECRET_LEN)
# Bound epoch/index to 64 bits: they are folded through ">Q" (mod 2**64), so two
# values that differ only above 2**64 would legitimately collide. Stay in range.
_u64 = st.integers(min_value=0, max_value=2**64 - 1)

# Native KEM timing varies; disable the per-example deadline and the
# function-scoped-fixture / large-base-example health checks for these.
_kem_settings = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.data_too_large],
)


# ---------------------------------------------------------------------------
# Hybrid KEM — round-trip
# ---------------------------------------------------------------------------


@pq_only
@_kem_settings
@given(kp_idx=st.integers(min_value=0, max_value=5), info=_info)
def test_hybrid_kem_roundtrips(kp_idx: int, info: bytes) -> None:
    """decap(encap(pk)) reproduces the sender's secret for any valid key + info."""
    kp = _KEYPAIRS[kp_idx]
    ct, sender_secret = hybrid_encap(kp.public_key, info=info)
    recipient_secret = hybrid_decap(ct, kp.private_key, info=info)

    assert recipient_secret == sender_secret
    assert len(sender_secret) == SHARED_SECRET_LEN == 32
    assert len(ct) == CIPHERTEXT_LEN


@pq_only
@_kem_settings
@given(kp_idx=st.integers(min_value=0, max_value=5), info=_info)
def test_hybrid_kem_fresh_encaps_differ(kp_idx: int, info: bytes) -> None:
    """Each encapsulation to the same pk is fresh (ephemeral X25519) -> new ct."""
    kp = _KEYPAIRS[kp_idx]
    ct1, ss1 = hybrid_encap(kp.public_key, info=info)
    ct2, ss2 = hybrid_encap(kp.public_key, info=info)
    # Ephemeral legs make ciphertext (and thus the secret) overwhelmingly unique.
    assert ct1 != ct2
    assert ss1 != ss2
    # ...but each still round-trips to its own secret.
    assert hybrid_decap(ct1, kp.private_key, info=info) == ss1
    assert hybrid_decap(ct2, kp.private_key, info=info) == ss2


# ---------------------------------------------------------------------------
# Hybrid KEM — tamper-evidence
# ---------------------------------------------------------------------------


@pq_only
@_kem_settings
@given(
    kp_idx=st.integers(min_value=0, max_value=5),
    pos=st.integers(min_value=0, max_value=CIPHERTEXT_LEN - 1),
    mask=st.integers(min_value=1, max_value=255),
)
def test_hybrid_kem_single_byte_tamper_breaks_secret(
    kp_idx: int, pos: int, mask: int
) -> None:
    """Flipping ANY single ciphertext byte makes decap diverge from the sender.

    Length is preserved (no PqKemFormatError); the divergence comes from the
    X25519 leg changing and/or ML-KEM's implicit rejection yielding a different
    secret. Either way the derived 32-byte secret no longer matches.
    """
    kp = _KEYPAIRS[kp_idx]
    ct, sender_secret = hybrid_encap(kp.public_key)

    tampered = bytearray(ct)
    tampered[pos] ^= mask
    tampered = bytes(tampered)
    assert tampered != ct
    assert len(tampered) == CIPHERTEXT_LEN  # same length -> no format error

    got = hybrid_decap(tampered, kp.private_key)
    assert got != sender_secret


@pq_only
@_kem_settings
@given(
    kp_idx=st.integers(min_value=0, max_value=5),
    info_a=_info,
    info_b=_info,
)
def test_hybrid_kem_info_mismatch_breaks_secret(
    kp_idx: int, info_a: bytes, info_b: bytes
) -> None:
    """A decap with a different HKDF ``info`` label yields a different secret."""
    if info_a == info_b:
        return  # only meaningful when the labels actually differ
    kp = _KEYPAIRS[kp_idx]
    ct, sender_secret = hybrid_encap(kp.public_key, info=info_a)
    assert hybrid_decap(ct, kp.private_key, info=info_b) != sender_secret


@pq_only
@_kem_settings
@given(
    kp_idx=st.integers(min_value=0, max_value=5),
    delta=st.integers(min_value=-4, max_value=4).filter(lambda d: d != 0),
)
def test_hybrid_kem_wrong_length_ciphertext_raises(kp_idx: int, delta: int) -> None:
    """A wrong-*length* ciphertext is a hard format error (never a crash/secret)."""
    kp = _KEYPAIRS[kp_idx]
    ct, _ = hybrid_encap(kp.public_key)
    if delta > 0:
        bad = ct + b"\x00" * delta
    else:
        bad = ct[:delta]  # drop |delta| trailing bytes
    assert len(bad) != CIPHERTEXT_LEN
    with pytest.raises(PqKemFormatError):
        hybrid_decap(bad, kp.private_key)


# ---------------------------------------------------------------------------
# DM message-key derivation — determinism + distinctness + tamper
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(secret=_epoch_secrets, epoch=_u64, index=_u64)
def test_derive_dm_message_key_is_deterministic(
    secret: bytes, epoch: int, index: int
) -> None:
    """Same (epoch_secret, epoch, index) -> identical 32-byte key, every time."""
    k1 = derive_dm_message_key(secret, epoch, index)
    k2 = derive_dm_message_key(secret, epoch, index)
    assert k1 == k2
    assert len(k1) == MESSAGE_KEY_LEN == 32


@settings(max_examples=200)
@given(
    secret=_epoch_secrets,
    a=st.tuples(_u64, _u64),
    b=st.tuples(_u64, _u64),
)
def test_derive_dm_message_key_distinct_per_address(
    secret: bytes, a: tuple[int, int], b: tuple[int, int]
) -> None:
    """Any two different (epoch, index) addresses derive different keys."""
    if a == b:
        return  # only meaningful for distinct addresses
    ka = derive_dm_message_key(secret, a[0], a[1])
    kb = derive_dm_message_key(secret, b[0], b[1])
    assert ka != kb


@settings(max_examples=200)
@given(
    secret=_epoch_secrets,
    epoch=_u64,
    index=_u64,
    pos=st.integers(min_value=0, max_value=EPOCH_SECRET_LEN - 1),
    mask=st.integers(min_value=1, max_value=255),
)
def test_derive_dm_message_key_secret_tamper_changes_key(
    secret: bytes, epoch: int, index: int, pos: int, mask: int
) -> None:
    """Flipping any byte of the epoch secret changes the derived message key."""
    tampered = bytearray(secret)
    tampered[pos] ^= mask
    tampered = bytes(tampered)
    assert tampered != secret
    base = derive_dm_message_key(secret, epoch, index)
    assert derive_dm_message_key(tampered, epoch, index) != base


@settings(max_examples=50)
@given(
    bad=st.binary(max_size=64).filter(lambda b: len(b) != EPOCH_SECRET_LEN),
    epoch=_u64,
    index=_u64,
)
def test_derive_dm_message_key_wrong_secret_length_raises(
    bad: bytes, epoch: int, index: int
) -> None:
    """A wrong-length epoch secret is a hard error, not a derived key."""
    with pytest.raises(DmRatchetError):
        derive_dm_message_key(bad, epoch, index)
