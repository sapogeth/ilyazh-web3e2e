# 🔐 Ilyazh-Web3E2E: A Post-Quantum Hybrid Encryption Protocol Specification

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Specification Draft](https://img.shields.io/badge/status-draft-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> **Version 0.3**
>
> A forward-secure, post-quantum hybrid protocol for authenticated key exchange and end-to-end (E2E) encrypted messaging, designed for decentralized environments.

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Terminology](#2-terminology)
3.  [Threat Model](#3-threat-model)
4.  [Security Goals](#4-security-goals)
5.  [Protocol Overview](#5-protocol-overview)
6.  [Detailed Specification](#6-detailed-specification)
    1.  [Cryptographic Primitives](#61-cryptographic-primitives)
    2.  [Peer Authentication & Session Establishment](#62-peer-authentication--session-establishment)
    3.  [Hybrid Key Encapsulation (KEM)](#63-hybrid-key-encapsulation-kem)
    4.  [Double Ratchet Algorithm](#64-double-ratchet-algorithm)
    5.  [Wire Format](#65-wire-format)
7.  [Security Considerations](#7-security-considerations)
8.  [Test Vectors](#8-test-vectors)
9.  [Future Work & Roadmap](#9-future-work--roadmap)
10. [Acknowledgements](#10-acknowledgements)

---

## 1. Introduction

Ilyazh-Web3E2E is a cryptographic protocol designed to provide robust, multi-layered security for peer-to-peer communication in the Web3 era. It addresses the dual threat of classical and quantum adversaries by implementing a hybrid key exchange mechanism and follows modern best practices to ensure confidentiality, integrity, and forward secrecy.

The protocol's philosophy prioritizes **verifiable security and transparency** over proprietary or obscure algorithms, using only standardized, community-vetted cryptographic primitives. This document serves as a technical specification for implementers and a basis for formal security analysis.

## 2. Terminology

-   **Party:** An endpoint in the communication (e.g., a user, device, or server).
-   **Identity Key:** A long-term public/private key pair used for signing, establishing a party's identity (e.g., `Ed25519`).
-   **Ephemeral Key:** A short-term public/private key pair generated for a single session to provide forward secrecy.
-   **Session:** A secure communication context between two parties.
-   **Chain Key (CK):** A key in the Double Ratchet used to derive subsequent Chain Keys and Message Keys.
-   **Message Key (MK):** A key used to encrypt a single message with an AEAD cipher.

## 3. Threat Model

The protocol is designed to be secure against a powerful, **active adversary** who has full control over the network. The adversary can read, modify, inject, replay, and delete packets at will. The compromise of a party's device is also considered, with the goal of minimizing the impact on past and future communications.

## 4. Security Goals

The protocol is designed to achieve the following formal security goals:

-   **Confidentiality:** The content of messages is computationally indistinguishable from random noise to any party other than the intended recipient.
-   **Integrity & Authenticity:** It is computationally infeasible for an adversary to modify, forge, or reorder messages without detection. If Party A accepts a message as coming from Party B, then B must have actually sent that message in that context.
-   **Forward Secrecy:** The compromise of a party's long-term Identity Keys or current session state does not compromise the confidentiality of past messages.
-   **Post-Quantum Security:** Confidentiality is maintained against an adversary with access to a large-scale quantum computer.

## 5. Protocol Overview

Ilyazh-Web3E2E is an **Authenticated Key Exchange (AKE)** protocol that establishes a secure, forward-secure session.

**Session Establishment Flow:**
Alice -> Bob : Ephemeral_PK_A, Sig(Ephemeral_PK_A, Identity_SK_A)
Bob   -> Alice: Ephemeral_PK_B, Sig(Ephemeral_PK_B, Identity_SK_B), KEM_Ciphertext(Ephemeral_PK_A)

This flow establishes an authenticated, hybrid shared secret which then initializes a Double Ratchet for ongoing communication.

## 6. Detailed Specification

### 6.1. Cryptographic Primitives

The primary recommended suite is:

| Component | Specification |
|---|---|
| **KEM** | Hybrid: **X25519** + **Kyber-768** |
| **AEAD** | **AES-256-GCM** |
| **KDF** | **HKDF-SHA256** |
| **Signature** | **Ed25519** (Migration path to **Dilithium3**) |

### 6.2. Peer Authentication & Session Establishment

Each party signs their ephemeral KEM public key with their long-term identity key. This prevents a MitM from substituting their own ephemeral key during the handshake.

### 6.3. Hybrid Key Encapsulation (KEM)

The initial shared secret (`ss`) for the Double Ratchet's root key is derived from the concatenated outputs of both the classical and post-quantum key exchanges.

`ss = HKDF-Extract(salt, X25519(sk_a, pk_b) || Kyber.Decaps(sk_a_pq, ct_b))`

### 6.4. Double Ratchet Algorithm

The protocol uses a standard Double Ratchet to manage session keys:
-   **Symmetric-key Ratchet:** After each message, a new Message Key (`MK`) is derived from the current Chain Key (`CK`), and the `CK` is updated: `CK_n+1 = HKDF(CK_n, ...)`
-   **DH Ratchet:** Periodically, a new KEM exchange is performed to update the root key, providing post-compromise security (healing).

### 6.5. Wire Format

A fixed binary format (e.g., CBOR) is specified. All header fields are authenticated as **Associated Data (AAD)** by AES-GCM.

struct CiphertextPayload {
u8  version;         // 0x01
u16 suite_id;        // 0x0001 for default suite
u64 seq;             // Message sequence number
u96 nonce;           // 32-bit counter || 64-bit random prefix
bytes enc_kem;       // KEM encapsulated key(s)
bytes ciphertext;    // AEAD ciphertext || 16-byte auth_tag
}


## 7. Security Considerations

-   **Limits & Invariants:**
    -   A session MUST be re-established after a maximum of `2^32` messages.
    -   A symmetric rekey (`CK` update) MUST occur at least every `2^20` messages or 24 hours.
    -   The GCM nonce **MUST NOT** be repeated for a given key. The `counter || random` structure is designed to make this practically impossible.
-   **Implementation:** All cryptographic operations MUST be implemented in **constant time**. All secret key material MUST be securely **zeroed** from memory after use.
-   **Randomness:** A Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) is required.

## 8. Test Vectors

This section provides test vectors for the default cipher suite to ensure implementation compatibility.

**(Example using conceptual hex values)**
-   **Alice Identity SK (Ed25519):** `c5aa...`
-   **Alice Ephemeral SK (X25519+Kyber768):** `7707...`
-   **Message Plaintext:** `Hello, Web3!`
-   **AAD:** `0100010000000000000001...`
-   **Final Payload (Hex):** `010001...`

*(A full implementation would include a script to generate and verify these vectors.)*

## 9. Future Work & Roadmap

-   [ ] **Formal Verification:** Model the protocol in **Tamarin** or **ProVerif** for a machine-checked security proof.
-   [ ] **Rust Implementation:** Develop a production-grade, constant-time reference implementation.
-   [ ] **Performance Benchmarking:** Analyze performance on mobile, IoT, and WebAssembly targets.
-   [ ] **Pilot Deployment:** Integrate the protocol into the [Stvor Messenger](https://github.com/sapogeth/Stvor) as a pilot.

## 10. Acknowledgements

This protocol's architecture was significantly improved by following the guidance of **Professor Henry Corrigan-Gibbs of MIT**, who recommended a deep dive into foundational cryptographic principles. The resulting design is a direct reflection of the lessons learned from the MIT 6.1600 course materials and subsequent expert feedback.

---

*Author:*
- Ilyas Zhaisenbayev
