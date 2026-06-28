#!/usr/bin/env python3
"""1:1 DM epoch-ratchet two-party roundtrip — Alice <-> Bob.

Demonstrates the Level-3 running ratchet (RFC-0001 P1): a per-conversation epoch
secret is distributed ONCE per epoch over the hybrid KEM (x25519-mlkem768), and
per-message keys derive symmetrically + index-addressably from it. Periodic rekey
starts a fresh independent epoch — forward secrecy across the boundary,
post-compromise security within (a leaked epoch secret heals at the next PQ rekey).

The ~1.1 KB of ML-KEM ciphertext is paid ONCE per epoch, not per message
(the Apple-PQ3 insight: per-message PQ does not pay for itself).

Run:

    SK_PQC_LIBOQS=$HOME/.local/lib/liboqs.so \
    LD_LIBRARY_PATH=$HOME/.local/lib \
    python examples/dm_ratchet_roundtrip.py
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sk_pqc import (
    DmRatchet,
    hybrid_keypair,
    is_available,
)
from sk_pqc.dm_ratchet import (
    new_epoch_secret,
    unwrap_dm_epoch_secret,
    wrap_dm_epoch_secret,
)


def send(ratchet: DmRatchet, plaintext: bytes) -> tuple[int, bytes, bytes]:
    """Alice: take the next outbound key, AES-256-GCM seal, ship (index, nonce, ct)."""
    index, key = ratchet.next_outbound_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return index, nonce, ct


def receive(ratchet: DmRatchet, index: int, nonce: bytes, ct: bytes) -> bytes:
    """Bob: derive the key for the carried index (loss/reorder tolerant), open."""
    key = ratchet.message_key(index=index)
    return AESGCM(key).decrypt(nonce, ct, None)


def main() -> None:
    if not is_available():
        raise SystemExit(
            "PQ backend (liboqs via `oqs`) unavailable — install `sk-pqc[pq]`."
        )

    # Bob publishes a long-term hybrid prekey.
    bob = hybrid_keypair()

    # --- Epoch 0: Alice mints an epoch secret + wraps it to Bob's hybrid key ---
    e0 = new_epoch_secret()
    payload = wrap_dm_epoch_secret(e0, bob.public_key)  # ~1.2 KB, sent ONCE
    print(f"epoch-0 wrap payload: {len(payload)} bytes (hybrid ct + nonce + sealed)")

    bob_e0 = unwrap_dm_epoch_secret(payload, bob.private_key)
    assert bob_e0 == e0  # both sides now hold the same epoch secret

    alice = DmRatchet(epoch=0, epoch_secret=e0)
    bob_r = DmRatchet(epoch=0, epoch_secret=bob_e0)

    # Several messages keyed symmetrically off the one epoch secret (no per-msg PQ).
    for text in (b"hi bob", b"how's the sovereign net?", b"pq ratchet works"):
        idx, nonce, ct = send(alice, text)
        got = receive(bob_r, idx, nonce, ct)
        print(f"  msg[{idx}] -> {got!r}")
        assert got == text

    # Out-of-order delivery: index-addressable keys mean reorder is fine.
    i0, n0, c0 = send(alice, b"first")
    i1, n1, c1 = send(alice, b"second")
    assert receive(bob_r, i1, n1, c1) == b"second"  # opened before msg i0
    assert receive(bob_r, i0, n0, c0) == b"first"
    print("  out-of-order delivery: OK (index-addressable)")

    # --- Epoch 1: periodic rekey (forward secrecy + post-compromise security) ---
    assert alice.should_rekey() is False
    e1 = new_epoch_secret()
    assert e1 != e0  # independent — a leaked e0 reveals only epoch 0
    payload1 = wrap_dm_epoch_secret(e1, bob.public_key)
    bob_e1 = unwrap_dm_epoch_secret(payload1, bob.private_key)
    alice_1 = DmRatchet(epoch=1, epoch_secret=e1)
    bob_1 = DmRatchet(epoch=1, epoch_secret=bob_e1)

    idx, nonce, ct = send(alice_1, b"new epoch, healed channel")
    assert receive(bob_1, idx, nonce, ct) == b"new epoch, healed channel"

    # The old epoch-0 message key cannot open an epoch-1 message (PCS).
    old_key = alice.message_key(index=0)
    new_key = alice_1.message_key(index=0)
    assert old_key != new_key
    print("  rekey to epoch 1: OK (prior epoch key is dead — PCS)")

    print("\nOK — DM ratchet two-party roundtrip succeeded.")


if __name__ == "__main__":
    main()
