# Architecture — sk-pqc (Python)

This document is the **data-flow** view of `sk-pqc`, per the sk-standards
[DATA_FLOW_STANDARD](https://github.com/smilinTux/sk-standards): it traces concrete
sealing paths **hop by hop**, naming the module, the operation, and the **crypto
posture** (what protects the bytes) at each step. For the static module dependency
graph and the encap/decap sequence see [../SOP.md](../SOP.md) §Architecture; for
per-module summaries see [../README.md](../README.md).

Everything asymmetric/PQ funnels through one module — **`pqkem`** — and one original
construction, the **HKDF-SHA256 hybrid combiner**. Every higher layer is *wiring*
over `pqkem` + AES-256-GCM + HKDF.

---

## Layering

```mermaid
graph TD
    A["Application: skcomms / skchat client"]
    A --> PQDM["pqdm — one-shot hybrid seal (downgrade-lock)"]
    A --> PQR["pqroute — metadata-sealing routing envelope"]
    A --> GR["group_ratchet — group epoch key schedule"]
    A --> DMR["dm_ratchet — 1:1 DM epoch key schedule"]
    A --> AQ["anon_queue — aqid: addressing + deniable auth"]
    A --> REG["crypto_suites — agility registry + honest self-report"]

    PQDM --> KEM["pqkem — hybrid X25519 + ML-KEM-768 (FIPS 203)"]
    PQR --> KEM
    GR --> KEM
    DMR --> KEM
    REG -. "describes / status" .-> KEM

    KEM --> COMB["_combine — HKDF-SHA256(X25519_ss ‖ MLKEM_ss)<br/>THE only original crypto"]

    style KEM fill:#1f6feb,stroke:#0b3d91,color:#fff
    style COMB fill:#51cf66,stroke:#2b8a3e,color:#000
```

---

## Data-flow 1 — the one-shot seal (`pqdm`) and the downgrade-lock

The marquee path: Alice seals a body to Bob's published hybrid prekey
(`PrekeyBundle`). The **negotiated suite is bound into both** the AEAD AAD **and** the
wrap-key HKDF `info` — so a MITM that strips the hybrid prekey to force a classical
downgrade changes the bytes the sender seals under, and the downgrade cannot be
*silent*. The box style is the **crypto posture** at that hop.

```mermaid
flowchart TD
    PT["plaintext body<br/>(in the clear, in Alice's process)"]:::plain

    subgraph pqdm["pqdm :: seal(body, bundle, sender, recipient)"]
        NS["negotiate_suite(local_hybrid, peer_hybrid)<br/>→ x25519-mlkem768 | x25519-pgp-wrap-v1"]:::logic
        ENCAP["pqkem.hybrid_encap(bundle.hybrid_public)<br/>X25519 eph-static DH ⊕ ML-KEM-768 encap (FIPS 203)<br/>ss = HKDF(X25519_ss ‖ MLKEM_ss)"]:::hybrid
        AAD["downgrade_lock_aad(negotiated_suite, sender, recipient)<br/>= canonical JSON (sorted, compact)"]:::aad
        WK["wrap_key = HKDF-SHA256(ss,<br/>info = skcomms/pqdm/wrap/v1 | AAD)"]:::kdf
        SEAL["AES-256-GCM(wrap_key).encrypt(nonce, body, AAD)<br/>sealed = ct(1120) ‖ nonce(12) ‖ body_ct‖tag"]:::aead
    end

    BLOB["pqdm1: blob<br/>(stored / sent on the wire)"]:::wire

    PT --> SEAL
    NS --> AAD --> WK
    ENCAP --> WK --> SEAL --> BLOB
    AAD --> SEAL

    classDef plain fill:#fff3cd,stroke:#b8860b,color:#000
    classDef logic fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef hybrid fill:#1f6feb,stroke:#0b3d91,color:#fff
    classDef aad fill:#d1c4e9,stroke:#6f42c1,color:#000
    classDef kdf fill:#cfe2ff,stroke:#1f6feb,color:#000
    classDef aead fill:#d4edda,stroke:#2ea043,color:#000
    classDef wire fill:#212529,stroke:#000,color:#fff
```

On open, Bob reconstructs the AAD from the suite he believes was negotiated. If a MITM
forced a downgrade, the reconstructed AAD won't match — the AES-256-GCM open fails or
the recorded `negotiated_suite` no longer reads hybrid, surfacing as
**`DowngradeDetected`**. Detection is the self-report.

### Crypto posture per hop

| Hop | Module | Operation | Posture / what protects it |
| --- | --- | --- | --- |
| plaintext | (app) | body in process memory | **none** — cleartext, endpoint-trusted only |
| negotiate | `pqdm` | pick hybrid vs classical from both prekeys | control logic; result is bound into the AAD |
| hybrid encap | `pqkem` | X25519 ⊕ ML-KEM-768, `HKDF(X25519_ss ‖ MLKEM_ss)` | **hybrid PQ** — secure if **either** leg holds (FIPS 203) |
| downgrade-lock AAD | `pqdm` | canonical JSON of `{suite, sender, recipient}` | **AAD bind** — strips become detectable |
| wrap key | `pqdm` | HKDF-SHA256 over KEM secret, `pqdm/wrap` label + AAD | **KDF** — wrap key itself bound to the transcript |
| body seal | `pqdm` | AES-256-GCM(wrap_key) with AAD | **AEAD** — confidentiality + integrity (symmetric, quantum-acceptable) |
| wire | `pqdm` | `pqdm1:` framing | **wire** — coexists with classical PGP in the same field |

**Posture summary.** The KEM ciphertext (the only PQ material) rides once; the body is
sealed under a *symmetric* AES-256-GCM key (already quantum-acceptable). The recorded
blob is HNDL-resistant — secure unless **both** X25519 and ML-KEM-768 break.

---

## Data-flow 2 — the DM epoch ratchet (`dm_ratchet`)

For a stateful 1:1 conversation, the **per-epoch secret** is the only PQ-protected
material — wrapped once through the hybrid KEM and amortised across the epoch, while
each message gets a cheap, index-addressable **symmetric** key.

```mermaid
flowchart TD
    ES["new_epoch_secret()<br/>32 random bytes (os.urandom)"]:::secret

    subgraph dist["Epoch-secret distribution (once per epoch)"]
        WRAP["wrap_dm_epoch_secret(bob_hybrid_pub, epoch_secret)"]:::secret
        ENCAP["pqkem.hybrid_encap(bob_pub)<br/>ss = HKDF(X25519_ss ‖ MLKEM_ss)"]:::hybrid
        WK["wrap_key = HKDF-SHA256(ss,<br/>info = skchat/dm-ratchet/epoch-wrap/v1)"]:::kdf
        SEAL["AES-256-GCM(wrap_key).seal(epoch_secret)<br/>→ ct(1120) ‖ nonce ‖ wrapped"]:::aead
    end

    subgraph permsg["Per-message key (symmetric, cheap)"]
        MK["derive_dm_message_key(epoch_secret, epoch, index)<br/>HKDF-SHA256(IKM=epoch_secret,<br/>salt=skchat/dm-epoch/‖epoch,<br/>info=skchat/dm-ratchet/msg/v1/‖index)"]:::kdf
        BODY["AES-256-GCM(message_key).encrypt(body)"]:::aead
    end

    ES --> WRAP --> ENCAP --> WK --> SEAL
    ES --> MK --> BODY

    classDef secret fill:#f8d7da,stroke:#c0392b,color:#000
    classDef hybrid fill:#1f6feb,stroke:#0b3d91,color:#fff
    classDef kdf fill:#cfe2ff,stroke:#1f6feb,color:#000
    classDef aead fill:#d4edda,stroke:#2ea043,color:#000
```

The `group_ratchet` path is identical in shape with `group-ratchet` HKDF labels
instead of `dm-ratchet` ones — the **distinct domain labels guarantee a DM key can
never collide with a group key** (see [../SOP.md](../SOP.md) §3). Independent
per-epoch secrets give **forward secrecy** across epochs and **post-compromise
security** (a leaked epoch secret doesn't expose past or future epochs).

---

## Data-flow 3 — the routing envelope split (`pqroute1`)

`pqroute` separates what a relay **must** read (the next-hop header — tamper-evident
but visible) from what only the destination may read (the **hybrid-sealed** inner:
final destination + content). The relay learns the next hop *by design*; it cannot
read the inner.

```mermaid
flowchart LR
    subgraph seal["pqroute.seal_routed(...)"]
        HDR["route_header (next hop)<br/>plaintext but AEAD-bound"]:::logic
        AAD["aad = b'pqroute1' ‖ canonical(route_header)<br/>(binds the header — tamper-evident)"]:::aad
        EN["pqkem.hybrid_encap(dest_pub)<br/>ss = HKDF(X25519_ss ‖ MLKEM_ss)"]:::hybrid
        WK["wrap_key = HKDF-SHA256(ss,<br/>info = skcomms/pqroute/wrap/v1 | aad)"]:::kdf
        INNER["AES-256-GCM(wrap_key).encrypt(inner, aad)<br/>inner = {final_dest, content}"]:::aead
    end

    REL["Relay: read_route_header(envelope)<br/>(reads next hop; CANNOT open inner)"]:::wire
    DST["Destination: open_routed(envelope, dest_priv)"]:::wire

    HDR --> AAD --> WK
    EN --> WK --> INNER
    AAD --> INNER
    INNER --> REL --> DST

    classDef logic fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef aad fill:#d1c4e9,stroke:#6f42c1,color:#000
    classDef hybrid fill:#1f6feb,stroke:#0b3d91,color:#fff
    classDef kdf fill:#cfe2ff,stroke:#1f6feb,color:#000
    classDef aead fill:#d4edda,stroke:#2ea043,color:#000
    classDef wire fill:#212529,stroke:#000,color:#fff
```

A relay rewriting the header changes the AAD, so the destination's open fails — the
header is **tamper-evident**, the inner is **confidential to the destination only**.

---

## The honesty surface (`crypto_suites`)

Status is resolved **only** from the registry; the self-report only narrates what the
registry says. A classical or unknown suite can **never** be marked
quantum-resistant, and the forbidden marketing words can never reach a caller.

```mermaid
flowchart LR
    SID["suite_id on the wire<br/>(e.g. x25519-mlkem768)"]:::wire
    REG["crypto_suites.get_suite(id)<br/>(unknown ⇒ classical ⇒ never QR)"]:::logic
    RES["status · primitives · fips_refs"]:::logic
    PRED["is_quantum_resistant(suite_id)<br/>honest predicate — no caller hand-rolls this"]:::gate
    OUT["self-report → app surfaces<br/>'hybrid x25519-mlkem768 / FIPS 203 / secure if EITHER leg holds'"]:::wire
    SID --> REG --> RES --> PRED --> OUT

    classDef wire fill:#212529,stroke:#000,color:#fff
    classDef logic fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef gate fill:#2ea043,stroke:#15682b,color:#fff
```

---

## Cross-language note

Every label, length, AAD byte, and canonical-JSON rule shown above is shared verbatim
with the Dart (`sk_pqc`, pub.dev) and Rust (`sk-pqc`, crates.io) implementations. A
blob sealed by any one of the three opens in the other two; the deterministic
constructions are pinned by the shared parity vector
(`tests/vectors/hybrid_kem_x25519_mlkem768.json`) — see [../SOP.md](../SOP.md) §Test.
