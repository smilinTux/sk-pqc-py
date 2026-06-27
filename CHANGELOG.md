# Changelog

All notable changes to `sk-pqc` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until `1.0.0`, the wire
format and the HKDF combiner are **frozen across the `0.x` line** — any breaking
change to them ships under a new suite id, not a patch.

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-06-27

Initial release — **published to PyPI** as
[`sk-pqc`](https://pypi.org/project/sk-pqc/) (`pip install sk-pqc`). Companion
packages: pub.dev [`sk_pqc`](https://pub.dev/packages/sk_pqc) and crates.io
[`sk-pqc`](https://crates.io/crates/sk-pqc) — all import as `sk_pqc`.

### Added

- **`pqkem`** — hybrid post-quantum KEM, suite id `x25519-mlkem768` (X25519 +
  ML-KEM-768, FIPS 203). `hybrid_keypair` / `hybrid_encap` / `hybrid_decap`,
  `is_available`, and the size constants. ML-KEM-768 leg = liboqs (`oqs`); X25519 leg
  + HKDF combiner + AES-256-GCM = pyca `cryptography`.
- **HKDF-SHA256 hybrid combiner** — the only original cryptographic code:
  `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss, salt=b"", info=b"sk_pqc/x25519-mlkem768/v1")`,
  X25519 first, concatenate-then-KDF (never XOR, never pure-PQ).
- **`pqdm`** — PQXDH-style one-shot seal (`seal` / `open_sealed` / `negotiate_suite`)
  with a **downgrade-lock AAD** that makes a silent classical downgrade detectable
  (`DowngradeDetected`).
- **`pqroute`** — `pqroute1` metadata-sealing routing envelope (`seal_routed` /
  `open_routed` / `read_route_header`): a relay reads a tamper-evident next-hop
  header but cannot read the hybrid-sealed inner.
- **`group_ratchet`** — per-epoch group key schedule (epoch secret distributed once
  via the hybrid KEM; index-addressable per-message keys, loss/reorder tolerant).
- **`dm_ratchet`** — the 1:1 pairwise analogue, with distinct HKDF domain labels so a
  DM key can never collide with a group key.
- **`anon_queue`** — `aqid:` addressing + deniable HMAC-SHA256 authenticator
  (addressing + deniable-auth only; not a transport).
- **`crypto_suites`** — crypto-agility registry mapping suite-ids → primitives +
  quantum-resistance status + FIPS refs, with the honest `is_quantum_resistant`
  predicate.
- **Never silently downgrades** — hybrid operations raise `PqKemUnavailable` when
  liboqs is missing; the pure-pyca pieces (combiner KAT, registry, anon-queue
  codec/MAC, key derivation) work with no PQ backend at all.
- **Cross-implementation interop** — a shared JSON KAT vector
  (`tests/vectors/hybrid_kem_x25519_mlkem768.json`, ML-KEM leg anchored to NIST ACVP
  FIPS 203 keyGen) recovered identically by the Python, Dart (`sk_pqc`), and Rust
  (`sk-pqc`) implementations.
- **Packaging** — PyPI publishing via Trusted Publishing (OIDC), `pq` and `test`
  extras, Apache-2.0 license, full doc set (README, SOP, SECURITY, CONTRIBUTING,
  CODE_OF_CONDUCT, docs/ARCHITECTURE).

### Known limitations

- **KEM only** — no signatures (ML-DSA / SLH-DSA, FIPS 204/205, tier T3 are future
  work). This library authenticates nothing by itself.
- **Experimental · pre-1.0 · NOT independently security-audited** — no third-party
  audit, fuzzing, or formal review yet.
- The PQ leg requires a native liboqs (`pip install "sk-pqc[pq]"`); proven on Linux
  desktop with liboqs 0.14.0.

[Unreleased]: https://github.com/smilinTux/sk-pqc-py/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/smilinTux/sk-pqc-py/releases/tag/v0.1.0
