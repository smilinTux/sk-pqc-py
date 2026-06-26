"""sk_pqc — crypto-agility suite-registry tests.

Covers the registry shape + honesty rules:
    - default sig suite is classical.
    - everything *active* is classical/symmetric EXCEPT the verified hybrid
      primitives (the KEM + the hybrid sig), which are hybrid-pq.
    - planned hybrid suites exist but are inactive.
    - unknown suite ids are treated as classical (never reported quantum-resistant).

NOTE: the upstream skcomms suite also exercised ``SignedEnvelope`` round-trips
(``skcomms.envelope``). Those tests were app-coupled to skcomms's wire envelope
and are intentionally not carried into this app-agnostic package — sk_pqc owns
the registry, not skcomms's envelope object.
"""

from __future__ import annotations

from sk_pqc.crypto_suites import (
    DEFAULT_SIG_SUITE,
    SuiteKind,
    SuiteStatus,
    active_suites,
    all_suites,
    get_suite,
    is_quantum_resistant,
    suite_status,
)


def test_registry_default_sig_suite_is_classical():
    suite = get_suite(DEFAULT_SIG_SUITE)
    assert suite is not None
    assert suite.kind == SuiteKind.SIG
    assert suite.status == SuiteStatus.CLASSICAL
    assert suite.active is True
    assert not suite.is_quantum_resistant


# Verified active hybrid primitives: the Q1 KEM + the Q7 hybrid signature.
# Both are real, round-tripping primitives; everything else active stays
# classical/symmetric. Classical remains the default.
_ACTIVE_HYBRID_PRIMITIVES = {"x25519-mlkem768", "mldsa65-ed25519-v2"}


def test_registry_active_suites_are_never_hybrid_or_pq():
    """Honesty gate: only the verified hybrid primitives may be active hybrid
    suites; everything else active stays classical/symmetric."""
    for suite in active_suites():
        if suite.suite_id in _ACTIVE_HYBRID_PRIMITIVES:
            assert suite.status == SuiteStatus.HYBRID_PQ
            continue
        assert suite.status in (SuiteStatus.CLASSICAL, SuiteStatus.SYMMETRIC), (
            f"{suite.suite_id} is active but status={suite.status}"
        )


def test_registry_has_planned_inactive_hybrid_suites():
    hybrid = get_suite("x25519-mlkem768-v2")
    assert hybrid is not None
    assert hybrid.status == SuiteStatus.HYBRID_PQ
    assert hybrid.active is False          # planned, not live
    assert hybrid.is_quantum_resistant     # would be QR once active
    assert "FIPS 203" in hybrid.fips_refs
    assert hybrid.replaces == "rsa-pgp-wrap-v1"


def test_registry_kem_primitive_is_active_hybrid():
    s = get_suite("x25519-mlkem768")
    assert s is not None
    assert s.kind == SuiteKind.KEM
    assert s.status == SuiteStatus.HYBRID_PQ
    assert s.active is True
    assert s.is_quantum_resistant
    assert "FIPS 203" in s.fips_refs


def test_registry_shape_and_serialization():
    for suite in all_suites():
        d = suite.to_dict()
        assert set(d) >= {
            "suite_id", "kind", "status", "primitives",
            "fips_refs", "active", "quantum_resistant",
        }
        assert d["quantum_resistant"] == suite.is_quantum_resistant


def test_unknown_suite_is_treated_classical():
    assert suite_status("totally-made-up") == SuiteStatus.CLASSICAL
    assert not is_quantum_resistant("totally-made-up")
