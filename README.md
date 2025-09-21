# 🔐 Ilyazh-Web3E2E: Post-Quantum Hybrid Protocol Specification (v0.7)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Draft](https://img.shields.io/badge/status-draft-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

> **Version 0.7 — September 2025**
>
> A forward-secure, post-quantum hybrid protocol for authenticated key exchange and end-to-end (E2E) encrypted messaging, designed for decentralized environments.

---

## 📖 Table of Contents

1. [Introduction](#introduction)
2. [Threat Model](#threat-model)
3. [Security Goals](#security-goals)
4. [Protocol Overview](#protocol-overview)
5. [Detailed Specification](#detailed-specification)
   - [Cryptographic Primitives](#cryptographic-primitives)
   - [Peer Authentication & Session Establishment](#peer-authentication--session-establishment)
   - [Hybrid Key Encapsulation (KEM)](#hybrid-key-encapsulation-kem)
   - [Double Ratchet Algorithm](#double-ratchet-algorithm)
   - [Wire Format](#wire-format)
6. [Security Considerations](#security-considerations)
7. [Test Vectors](#test-vectors)
8. [Future Work & Roadmap](#future-work--roadmap)
9. [Acknowledgements](#acknowledgements)

---

## 1. Introduction

Ilyazh-Web3E2E is a cryptographic protocol designed for **robust, multi-layered security** in decentralized messaging. It targets the **Harvest-Now, Decrypt-Later** threat by combining classical and post-quantum primitives in a hybrid AKE (Authenticated Key Exchange). It prioritizes **verifiable security and transparency** using only standardized, community-vetted primitives.

## 2. Threat Model

- **Adversary:** Active, controls the network (read, modify, replay, delete packets).
- **Device Compromise:** Protocol minimizes impact on past/future communications.
- **Quantum Adversary:** Security preserved against large-scale quantum computers.

## 3. Security Goals

- **Confidentiality:** Messages indistinguishable from random.
- **Integrity & Authenticity:** Forgery/reordering undetectable.
- **Forward Secrecy:** Compromise of long-term keys ≠ past confidentiality.
- **Post-Quantum Security:** Resistant to quantum adversaries.

## 4. Protocol Overview

Session establishment (simplified):

```
Alice → Bob : Ephemeral_PK_A, Sig_A( Ephemeral_PK_A )
Bob   → Alice: Ephemeral_PK_B, Sig_B( Ephemeral_PK_B ), ML-KEM_Ct
```

- Hybrid secret = X25519 || ML-KEM-768 shared secret
- Derive `sid`, `root_key`, and chain keys via **HKDF-SHA384**
- Enter **Double Ratchet** for ongoing secure messaging

## 5. Detailed Specification

### Cryptographic Primitives

| Component   | Specification                                  |
|-------------|-----------------------------------------------|
| **KEM**     | Hybrid: **X25519** + **ML-KEM-768**           |
| **AEAD**    | **AES-256-GCM**                               |
| **KDF**     | **HKDF-SHA384** (domain-separated labels)      |
| **Signature** | Dual: **Ed25519** + **ML-DSA-65**            |

### Peer Authentication & Session Establishment

- Ephemeral KEM public keys signed with **both** Ed25519 and ML-DSA-65.
- Transcript binding (`t0 → t1 → t2`) prevents downgrade/UKS attacks.
- Session ID (`sid`) derived from transcript hash + hybrid secret.

### Hybrid Key Encapsulation (KEM)

```
ss = HKDF-Extract( salt=t2 , IKM = X25519(sk_A, pk_B) || ML-KEM.Decaps(sk_Apq, ct_B) )
```

### Double Ratchet Algorithm

- **Symmetric Ratchet:** `CK_{n+1}, MK = HKDF(CK_n, label_msg)`
- **DH Ratchet:** Periodic re-encapsulation to heal compromise.
- **Nonce discipline:** `R64 || C32` per epoch (random 64-bit prefix + 32-bit counter).

### Wire Format

```
struct CiphertextPayload {
  u8   version;     // 0x03 (v0.7)
  u16  suite_id;    // 0x0001
  u64  seq;         // message sequence number
  u96  nonce;       // R64 || C32
  bytes sid;        // 32B session identifier
  bytes enc_kem;    // optional PQ rekey
  bytes ciphertext; // AEAD ciphertext + tag
}
```

## 6. Security Considerations

- **Limits:**
  - Rekey every ≤ 2^20 messages or 24h.
  - Session expires after 2^32 messages.
- **Nonce reuse forbidden.**
- **Constant-time implementation required.**
- **CSPRNG required** for ephemeral keys and nonces.

## 7. Test Vectors

Example (conceptual hex):

- Alice Identity SK (Ed25519): `c5aa...`
- Alice Ephemeral SK (X25519 + ML-KEM): `7707...`
- Plaintext: `Hello, Web3!`
- AAD: `0300010000000000000001...`
- Payload: `030001...`

## 8. Future Work & Roadmap

- [ ] Formal verification (Tamarin / ProVerif)
- [ ] Rust constant-time reference implementation
- [ ] Performance benchmarks (IoT, mobile, WASM)
- [ ] Integration into [Stvor Messenger](https://github.com/sapogeth/Stvor)

## 9. Acknowledgements

- Prof. Henry Corrigan-Gibbs (MIT) for guidance on principled cryptographic design.
- Community feedback from IACR reviewers and Web3 security researchers.

---

**Author:** Ilyas Zhaisenbayev
