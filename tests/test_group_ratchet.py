"""sk_pqc — group epoch-ratchet primitive tests (hybrid X25519+ML-KEM-768).

Covers the app-agnostic ratchet primitive:
    * per-message key derivation (distinct per index; deterministic; reorder-safe)
    * epoch advance (distinct epoch secrets => distinct keys)
    * hybrid epoch-secret wrap/unwrap round-trip (the PQ leg)
    * EpochRatchet state + re-key bounds (50-msg / 7-day)

These tests REQUIRE the liboqs-backed hybrid KEM (sk_pqc.pqkem); if it is not
importable they skip (a missing PQ backend is an environment gap, not a logic
failure).

NOTE: the upstream skchat suite also exercised ``GroupChat`` /
``GroupKeyDistributor`` / ``GroupMessageEncryptor`` integration (migration,
member add/remove re-key, FS/PCS over the full group object, self-report). Those
tests were app-coupled to skchat's ``group.py`` model and are intentionally not
carried into this app-agnostic package — sk_pqc owns the ratchet primitive, not
skchat's GroupChat. The crypto properties (FS across epochs, PCS from
independent epoch secrets) are exercised here at the primitive level.
"""

from __future__ import annotations

import pytest

pqkem = pytest.importorskip("sk_pqc.pqkem")
gr = pytest.importorskip("sk_pqc.group_ratchet")

if not pqkem.is_available():  # liboqs missing -> skip the whole module
    pytest.skip("liboqs/oqs backend unavailable", allow_module_level=True)


def _hybrid_keypair_hex() -> tuple[str, str]:
    kp = pqkem.hybrid_keypair()
    return kp.public_key.hex(), kp.private_key.hex()


# ---------------------------------------------------------------------------
# 1. Per-message key derivation
# ---------------------------------------------------------------------------


def test_message_keys_distinct_per_index():
    secret = gr.new_epoch_secret()
    k0 = gr.derive_message_key(secret, epoch=1, index=0)
    k1 = gr.derive_message_key(secret, epoch=1, index=1)
    k2 = gr.derive_message_key(secret, epoch=1, index=2)
    assert len({k0, k1, k2}) == 3
    assert all(len(k) == 32 for k in (k0, k1, k2))


def test_message_key_deterministic():
    secret = gr.new_epoch_secret()
    a = gr.derive_message_key(secret, 5, 7)
    b = gr.derive_message_key(secret, 5, 7)
    assert a == b


def test_message_key_index_addressable_no_chain_state():
    """Any index derivable independently (loss/reorder tolerant)."""
    secret = gr.new_epoch_secret()
    # Deriving index 9 first, then 0, must match deriving them in order.
    k9_first = gr.derive_message_key(secret, 1, 9)
    k0 = gr.derive_message_key(secret, 1, 0)
    k9_again = gr.derive_message_key(secret, 1, 9)
    assert k9_first == k9_again
    assert k0 != k9_first


# ---------------------------------------------------------------------------
# 2. Distinct epochs => distinct keys (forward secrecy across the boundary)
# ---------------------------------------------------------------------------


def test_distinct_epochs_distinct_keys_same_index():
    secret = gr.new_epoch_secret()
    e1 = gr.derive_message_key(secret, epoch=1, index=0)
    e2 = gr.derive_message_key(secret, epoch=2, index=0)
    assert e1 != e2


def test_distinct_epoch_secrets_distinct_keys():
    s1 = gr.new_epoch_secret()
    s2 = gr.new_epoch_secret()
    assert s1 != s2  # PCS: independent epoch secrets
    assert gr.derive_message_key(s1, 1, 0) != gr.derive_message_key(s2, 1, 0)


# ---------------------------------------------------------------------------
# 3. Hybrid wrap/unwrap round-trip (the PQ leg)
# ---------------------------------------------------------------------------


def test_epoch_secret_wrap_unwrap_roundtrip():
    pub_hex, priv_hex = _hybrid_keypair_hex()
    secret = gr.new_epoch_secret()
    payload = gr.wrap_epoch_secret(secret, bytes.fromhex(pub_hex))
    assert len(payload) == gr.WRAPPED_PAYLOAD_LEN
    recovered = gr.unwrap_epoch_secret(payload, bytes.fromhex(priv_hex))
    assert recovered == secret


def test_unwrap_with_wrong_key_fails():
    pub_hex, _ = _hybrid_keypair_hex()
    _, other_priv = _hybrid_keypair_hex()
    secret = gr.new_epoch_secret()
    payload = gr.wrap_epoch_secret(secret, bytes.fromhex(pub_hex))
    with pytest.raises(gr.GroupRatchetError):
        gr.unwrap_epoch_secret(payload, bytes.fromhex(other_priv))


def test_pq_material_rides_in_wrapped_payload():
    """The per-epoch wrap carries the ~1.1 KB ML-KEM ciphertext (paid once per
    epoch, not per message)."""
    pub_hex, _ = _hybrid_keypair_hex()
    payload = gr.wrap_epoch_secret(gr.new_epoch_secret(), bytes.fromhex(pub_hex))
    assert len(payload) == gr.WRAPPED_PAYLOAD_LEN
    assert len(payload) > pqkem.CIPHERTEXT_LEN  # contains the 1120 B PQ ct


# ---------------------------------------------------------------------------
# 4. EpochRatchet state + bounds
# ---------------------------------------------------------------------------


def test_ratchet_next_outbound_advances():
    r = gr.EpochRatchet(epoch=1, epoch_secret=gr.new_epoch_secret())
    i0, k0 = r.next_outbound_key()
    i1, k1 = r.next_outbound_key()
    assert (i0, i1) == (0, 1)
    assert k0 != k1
    assert r.message_index == 2


def test_ratchet_should_rekey_on_msg_bound():
    r = gr.EpochRatchet(epoch=1, epoch_secret=gr.new_epoch_secret(), rekey_msg_bound=3)
    assert not r.should_rekey()
    for _ in range(3):
        r.next_outbound_key()
    assert r.should_rekey()


def test_ratchet_should_rekey_on_age_bound():
    import time

    r = gr.EpochRatchet(
        epoch=1,
        epoch_secret=gr.new_epoch_secret(),
        rekey_age_seconds=0,  # immediately stale
        epoch_started_at=time.time() - 10,
    )
    assert r.should_rekey()
