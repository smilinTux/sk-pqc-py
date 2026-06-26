"""sk_pqc — hybrid DM/envelope sealing tests (sk_pqc.pqdm).

Covers the PQXDH-style seal:
    * prekey-bundle negotiation (hybrid advertised vs classical-only downgrade)
    * hybrid seal -> open round-trip (encap -> AES-256-GCM -> decap)
    * downgrade-lock: a tampered/forced suite mismatch is DETECTED on open
    * malformed input raises (never crashes)

These tests REQUIRE the liboqs-backed hybrid KEM (sk_pqc.pqkem); they skip if
it is unavailable (an environment gap, not a logic failure).

NOTE: the upstream skcomms suite also exercised ``EnvelopeCrypto`` integration
(``skcomms.models`` / ``skcomms.crypto``). Those tests were app-coupled to
skcomms and are intentionally NOT carried into this app-agnostic package — the
pqdm primitive itself is what sk_pqc owns and tests here.
"""

from __future__ import annotations

import pytest

pqkem = pytest.importorskip("sk_pqc.pqkem")
pqdm = pytest.importorskip("sk_pqc.pqdm")

if not pqkem.is_available():
    pytest.skip("liboqs/oqs backend unavailable", allow_module_level=True)

from sk_pqc.pqdm import (  # noqa: E402
    HYBRID_SUITE,
    DowngradeDetected,
    PqDmFormatError,
    PrekeyBundle,
    negotiate_suite,
    open_sealed,
    seal,
)


def _hybrid_bundle() -> tuple[PrekeyBundle, bytes]:
    kp = pqkem.hybrid_keypair()
    return (
        PrekeyBundle(suite=HYBRID_SUITE, hybrid_public_hex=kp.public_key.hex()),
        kp.private_key,
    )


# ---------------------------------------------------------------------------
# Negotiation
# ---------------------------------------------------------------------------


def test_negotiate_hybrid_when_both_advertise():
    bundle, _ = _hybrid_bundle()
    assert bundle.is_hybrid is True
    assert negotiate_suite(True, bundle) == HYBRID_SUITE


def test_negotiate_classical_when_peer_has_no_prekey():
    classical = PrekeyBundle.from_dict(None)
    assert classical.is_hybrid is False
    assert negotiate_suite(True, classical) == pqdm.CLASSICAL_SUITE


def test_negotiate_classical_when_local_unsupported():
    bundle, _ = _hybrid_bundle()
    assert negotiate_suite(False, bundle) == pqdm.CLASSICAL_SUITE


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_seal_open_roundtrip():
    bundle, priv = _hybrid_bundle()
    sealed = seal(b"top secret HNDL payload", bundle, sender="a", recipient="b")
    out = open_sealed(sealed, priv, sender="a", recipient="b")
    assert out == b"top secret HNDL payload"


def test_seal_is_nondeterministic_but_both_open():
    bundle, priv = _hybrid_bundle()
    s1 = seal(b"x", bundle, sender="a", recipient="b")
    s2 = seal(b"x", bundle, sender="a", recipient="b")
    assert s1 != s2  # fresh ephemeral + nonce each time
    assert open_sealed(s1, priv, sender="a", recipient="b") == b"x"
    assert open_sealed(s2, priv, sender="a", recipient="b") == b"x"


# ---------------------------------------------------------------------------
# Downgrade-lock
# ---------------------------------------------------------------------------


def test_downgrade_lock_detects_suite_mismatch():
    """An attacker that flips the recorded suite -> AAD won't authenticate."""
    bundle, priv = _hybrid_bundle()
    sealed = seal(b"secret", bundle, sender="a", recipient="b")
    # Recipient is tricked into believing a classical suite was negotiated.
    with pytest.raises(DowngradeDetected):
        open_sealed(
            sealed, priv, sender="a", recipient="b",
            expected_suite="x25519-pgp-wrap-v1",
        )


def test_downgrade_lock_detects_party_tamper():
    bundle, priv = _hybrid_bundle()
    sealed = seal(b"secret", bundle, sender="a", recipient="b")
    with pytest.raises(DowngradeDetected):
        open_sealed(sealed, priv, sender="MALLORY", recipient="b")


def test_tampered_ciphertext_detected():
    bundle, priv = _hybrid_bundle()
    sealed = bytearray(seal(b"secret", bundle, sender="a", recipient="b"))
    sealed[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(DowngradeDetected):
        open_sealed(bytes(sealed), priv, sender="a", recipient="b")


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


def test_seal_requires_hybrid_bundle():
    with pytest.raises(PqDmFormatError):
        seal(b"x", PrekeyBundle.from_dict(None))


def test_open_too_short_raises():
    bundle, priv = _hybrid_bundle()
    with pytest.raises(PqDmFormatError):
        open_sealed(b"too-short", priv)


def test_bad_prekey_length_raises():
    with pytest.raises(PqDmFormatError):
        PrekeyBundle(suite=HYBRID_SUITE, hybrid_public_hex="dead").hybrid_public()
