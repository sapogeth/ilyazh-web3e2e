# 🔐 Ilyazh-Web3E2E: A Post-Quantum Hybrid Encryption Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Specification Draft](https://img.shields.io/badge/status-specification-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> A forward-secure, post-quantum hybrid protocol for authenticated key exchange and end-to-end (E2E) encrypted messaging in decentralized systems.

This repository contains the official Python proof-of-concept for the **Ilyazh-Web3E2E** protocol. It is designed for academic study, cryptanalysis, and to serve as a blueprint for production-grade implementations.

👉 **A full technical specification is available for review on [arXiv](https://arxiv.org/abs/XXXX.XXXXX) and [IACR ePrint](https://eprint.iacr.org/YYYY/XXX).** *(Note: Replace with your actual links after publication.)*

Version 1.0
Forward-secure, post-quantum hybrid protocol for authenticated key exchange and end-to-end encrypted messaging in decentralized systems.

🌍 Overview

Ilyazh-Web3E2E is a hybrid encryption protocol that combines:

X25519 (classical curve Diffie–Hellman)

Kyber-768 (post-quantum KEM, NIST standard)

AES-256-GCM (AEAD for confidentiality + integrity)

Double Ratchet (forward & post-compromise security, inspired by Signal)

📖 Full technical specification available on arXiv
.

This project demonstrates:

Post-quantum readiness for Web3 messengers and dApps.

Formal cryptographic design (IND-CCA, FS, PCS).

A path from research → implementation → deployment.

⚡ Quickstart Example
from ilyazh_protocol import generate_keys, encrypt, decrypt

# 1. Recipient generates key pair
recipient_sk, recipient_pk = generate_keys()

# 2. Sender encrypts message
message = "Hello, Web3!"
aad = b"context:stvor,tx:0x123"
ciphertext = encrypt(recipient_pk, message, aad)

# 3. Recipient decrypts
plaintext = decrypt(recipient_sk, ciphertext, aad)

print("Ciphertext:", ciphertext)
print("Decrypted:", plaintext)

🧩 Protocol Specification

The protocol defines a hybrid Authenticated Key Exchange (AKE):

Handshake Phase
ss = HKDF( X25519(skA, pkB) || Kyber.Decaps(skA_pq, ctB) )

Messaging Phase
Uses Double Ratchet with AES-256-GCM, achieving:

Confidentiality (IND-CCA)

Integrity & Authenticity

Forward Secrecy

Post-Compromise Security

Post-Quantum Security

👉 See 📄 Full Specification

🔒 Security Considerations

Nonce management: unique per message (random64 || counter32)

Limits: rekey every 2^20 messages or 24h; re-establish session after 2^32 msgs

Implementation: constant-time, zeroization of secrets

Randomness: CSPRNG required

📊 Benchmarks (Python PoC)
Metric	Value
Handshake latency	~150–200 ms
Throughput (AES-GCM)	~20–25 MB/s
📚 Roadmap

 Formal verification (Tamarin/ProVerif)

 Rust implementation

 WASM build for Web3 dApps

 Integration into Stvor Messenger

🙏 Acknowledgements

This design was inspired by MIT 6.1600: Foundations of Computer Security (Henry Corrigan-Gibbs) and research on the Signal Protocol.

Author: Ilyas Zhaisenbayev (Independent Researcher, 18 y.o.)
License: MIT (code), CC BY 4.0 (specification).
