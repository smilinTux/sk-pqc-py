# Security Policy — sk-pqc (Python)

`sk-pqc` is a library of **hybrid post-quantum** cryptographic primitives centred on
the suite `x25519-mlkem768` (X25519 + ML-KEM-768, FIPS 203). Because it is
cryptographic infrastructure, please read the **honest-claim posture** and the
**threat model** below before relying on it or reporting an issue.

> ⚠️ **Experimental · pre-1.0 · NOT independently security-audited.** No third-party
> security audit, fuzzing, or formal review has been performed. The primitives bind
> vetted libraries (liboqs / ML-KEM, pyca `cryptography`); the original code is the
> wiring. **Review it yourself before production use.**

---

## Honest claims (what this library does and does NOT promise)

Per the sk-standards
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/sk-standards), every security
claim is scoped to **surface + FIPS number + hybrid-vs-classical**.

- ✅ **Quantum-resistant / post-quantum key encapsulation.** The 32-byte derived
  secret is secure if **either** the X25519 leg **or** the ML-KEM-768 leg holds.
- ✅ Targets the **FIPS 203 ML-KEM-768** tier (internet default; matches TLS
  `X25519MLKEM768` and Signal PQXDH).
- ✅ Neutralises **Harvest-Now-Decrypt-Later (HNDL)** for any key wrapped through the
  combiner — this is **maturity tier T2 (Hybrid KEM)**.
- ✅ **Never silently downgrades.** A missing liboqs backend raises `PqKemUnavailable`
  (a hard error), and `pqdm` binds the negotiated suite into the AEAD AAD so a forced
  classical downgrade is **detectable** (`DowngradeDetected`), never silent.
- ❌ **Not** "quantum-proof," "quantum-safe," or "unbreakable." Lattice cryptography
  is young; these words are never used.
- ❌ **Not** a signature scheme. It is **KEM-only** — it authenticates **nothing** by
  itself. ML-DSA / SLH-DSA (FIPS 204/205, tier T3) are **future work**. Pair `sk-pqc`
  with a signature scheme (e.g. `sk_pgp`) for authenticated key exchange, or you are
  exposed to a man-in-the-middle.
- ❌ **Not** the CNSA-2.0 ceiling (ML-KEM-1024) — that tier is reserved for a
  sovereign root.
- ❌ `anon_queue` is **addressing + deniable auth only**, not a transport, not
  anonymity by itself.

---

## Threat model

### In scope (what the hybrid KEM defends)

- **HNDL on the key-exchange secret.** A future cryptographically-relevant quantum
  computer (CRQC) that records today's ciphertext cannot recover the shared secret
  without breaking **both** legs (X25519 *and* ML-KEM-768). By Mosca's Inequality,
  long-shelf-life secrets are already past the migration threshold — hence T2 now.
- **Classical break of one primitive.** A future cryptanalytic break of X25519 alone
  leaves ML-KEM-768 standing, and vice-versa.
- **Silent classical downgrade.** `pqdm` folds the negotiated suite into the AEAD AAD
  *and* the wrap-key HKDF `info`, so a MITM that strips the hybrid prekey changes the
  bytes the sender seals under — the recipient's open fails or the recorded suite no
  longer reads hybrid. Detection is the self-report.
- **Wire tampering / corrupt ciphertext.** ML-KEM-768 uses **implicit rejection** — a
  tampered ciphertext yields a pseudo-random secret that simply won't match; the
  library does **not** crash. Malformed lengths raise `PqKemFormatError`, never an
  uncaught exception.

### Out of scope (you MUST handle these elsewhere)

- **Authentication / MITM.** KEM-only. An active attacker who substitutes a public
  key is not detected by `sk-pqc`. Authenticate the public key out-of-band or with a
  signature scheme (`sk_pgp` / a future hybrid ML-DSA layer).
- **Transport security.** TLS, tailnet, DTLS-SRTP media legs are not this library's
  surface. `pqroute` seals the *next-hop header is tamper-evident, the inner is
  hybrid-sealed* — but the relay still learns the next hop, by design.
- **Key storage / lifecycle.** The 2432-byte private key is the caller's
  responsibility to store and zeroise. `sk-pqc` does not persist keys.
- **Side channels in the bound libraries.** Constant-time guarantees come from
  **liboqs** (ML-KEM-768) and **pyca/cryptography** (X25519 / HKDF / AES-GCM).
  `sk-pqc` adds no secret-dependent branching in the wiring, but does not re-audit the
  primitives.
- **Metadata beyond the sealed inner.** `pqroute` and `anon_queue` reduce
  correlation but are not a full anonymity system; a global passive adversary is out
  of scope.

### Trust roots / dependencies

| Leg | Library | Assurance basis |
|---|---|---|
| ML-KEM-768 | [liboqs](https://github.com/open-quantum-safe/liboqs) via [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python) (`oqs`) | Open Quantum Safe; you build/bundle the native binary (proven on 0.14.0) |
| X25519 (DHKEM) | `cryptography` (pyca) | RFC 7748 / RFC 9180 |
| HKDF-SHA256 (combiner) | `cryptography` (pyca) | RFC 5869; verified vs KAT in `tests/test_pqkem.py` |
| AES-256-GCM (bulk) | `cryptography` (pyca) | SP 800-38D; quantum-acceptable (Grover only halves to ~128-bit) |
| HMAC-SHA256 (deniable auth) | `cryptography` (pyca) | RFC 2104; repudiable by construction |

**We bind vetted libraries; we never hand-roll the lattice or curve primitives.** The
**only** original cryptographic code is the HKDF-SHA256 hybrid combiner
(`src/sk_pqc/pqkem.py::_combine`), and it is `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` —
concatenate-then-KDF, **never XOR, never pure-PQ**.

---

## The one invariant that must never change

```
shared_secret = HKDF-SHA256( IKM = X25519_ss ‖ MLKEM768_ss,   # X25519 FIRST
                             salt = b"", info, L = 32 )
```

Any change to the combiner, the byte order, or the fixed wire-format lengths (1216B
public / 2432B private / 1120B ciphertext / 32B secret) **breaks every peer** and is
a **security-relevant** change. It MUST go through a suite-id bump (`x25519-mlkem768`
→ a new id) and the full cross-impl vector gate — never a silent edit. See
[SOP.md](SOP.md) §Architecture and the Release flow.

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ current |
| < 0.1.0 | ❌ pre-release |

Until 1.0, only the latest published `0.x` line receives security fixes. The wire
format and combiner are frozen across `0.x`; any break ships under a new suite id with
the Dart (`sk_pqc`) and Rust (`sk-pqc`) siblings updated in lockstep.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

- Report privately via the repository's **GitHub Security Advisories** ("Report a
  vulnerability" on the Security tab of
  [`smilinTux/sk-pqc-py`](https://github.com/smilinTux/sk-pqc-py)), or
- email the maintainers (smilinTux / SKWorld) at the address listed on the GitHub org.

Please include: affected version, Python version, liboqs version, a minimal
reproduction, and — if it concerns the combiner or wire format — a failing vector
against `tests/vectors/hybrid_kem_x25519_mlkem768.json`.

**Coordinated disclosure.** We aim to acknowledge within **72 hours** and to ship a
fix or mitigation within **90 days**, coordinating a disclosure date with you. Issues
in a **bound upstream** (liboqs, liboqs-python, pyca cryptography) will be forwarded
upstream and tracked here. Credit is given unless you ask otherwise.

### What we especially want to hear about

- Combiner deviations (XOR, wrong concat order, missing domain separation).
- Wire-format / length confusion that could cause cross-impl secret divergence.
- A path where a malformed input crashes instead of raising `PqKemFormatError` /
  `PqDmFormatError` / `PqRouteFormatError` / `AnonQueueFormatError`.
- A silent classical downgrade that does **not** surface as `DowngradeDetected`.
- Any place a claim in the docs overstates assurance (e.g. implies authentication,
  CNSA-2.0, or a "quantum-safe" guarantee).

---

**License:** Apache-2.0. **Standards:** FIPS 203 (ML-KEM); FIPS 204/205 cited for
out-of-scope signatures; RFC 5869 (HKDF); RFC 7748 / RFC 9180 (X25519 / DHKEM);
SP 800-38D (AES-GCM); NIST CSWP 39 (crypto-agility).
