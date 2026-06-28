#!/usr/bin/env python3
"""Hybrid KEM encap/decap roundtrip — the smallest end-to-end sk_pqc program.

A recipient publishes a long-term hybrid public key. A sender encapsulates to it,
producing a ciphertext + a 32-byte shared secret. The recipient decapsulates the
ciphertext with its private key and recovers the SAME shared secret. That shared
secret is then usable directly as an AES-256-GCM key.

The derived secret is confidential if EITHER the classical X25519 leg OR the
ML-KEM-768 leg (FIPS 203) holds — "hybrid", not "quantum-proof". See the README
honest-claims section.

Run (with a prebuilt liboqs so `oqs` doesn't self-build):

    SK_PQC_LIBOQS=$HOME/.local/lib/liboqs.so \
    LD_LIBRARY_PATH=$HOME/.local/lib \
    python examples/hybrid_kem_roundtrip.py
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sk_pqc import (
    CIPHERTEXT_LEN,
    PRIVATE_KEY_LEN,
    PUBLIC_KEY_LEN,
    SUITE_ID,
    hybrid_decap,
    hybrid_encap,
    hybrid_keypair,
    is_available,
)


def main() -> None:
    if not is_available():
        raise SystemExit(
            "PQ backend (liboqs via `oqs`) unavailable — install `sk-pqc[pq]` and "
            "point OQS_INSTALL_PATH/SK_PQC_LIBOQS at a liboqs shared library."
        )

    print(f"suite: {SUITE_ID}")

    # 1. Recipient generates a long-term hybrid keypair and publishes the pubkey.
    recipient = hybrid_keypair()
    assert len(recipient.public_key) == PUBLIC_KEY_LEN
    assert len(recipient.private_key) == PRIVATE_KEY_LEN
    print(
        f"public key:  {len(recipient.public_key)} bytes "
        f"(x25519 32 + ml-kem-768 1184)"
    )
    print(f"private key: {len(recipient.private_key)} bytes")

    # 2. Sender encapsulates to the recipient's public key.
    ciphertext, sender_secret = hybrid_encap(recipient.public_key)
    assert len(ciphertext) == CIPHERTEXT_LEN
    print(
        f"ciphertext:  {len(ciphertext)} bytes "
        f"(x25519 eph 32 + ml-kem-768 ct 1088)"
    )
    print(f"sender secret:    {sender_secret.hex()}")

    # 3. Recipient decapsulates and recovers the SAME 32-byte shared secret.
    recipient_secret = hybrid_decap(ciphertext, recipient.private_key)
    print(f"recipient secret: {recipient_secret.hex()}")
    assert sender_secret == recipient_secret, "shared secrets must match!"
    print("shared secrets match: True")

    # 4. Use the shared secret directly as an AES-256-GCM key.
    aead = AESGCM(sender_secret)
    nonce = os.urandom(12)
    blob = aead.encrypt(nonce, b"hello, post-quantum world", b"demo-aad")
    plain = AESGCM(recipient_secret).decrypt(nonce, blob, b"demo-aad")
    print(f"aead roundtrip: {plain!r}")
    assert plain == b"hello, post-quantum world"

    print("\nOK — hybrid KEM roundtrip + AEAD succeeded.")


if __name__ == "__main__":
    main()
