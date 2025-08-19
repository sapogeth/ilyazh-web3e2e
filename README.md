# 🔐 Ilyazh-Web3E2E: A Post-Quantum Hybrid Encryption Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Specification Draft](https://img.shields.io/badge/status-specification-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> A forward-secure, post-quantum hybrid protocol for authenticated key exchange and end-to-end (E2E) encrypted messaging in decentralized systems.

This repository contains the official Python proof-of-concept for the **Ilyazh-Web3E2E** protocol. It is designed for academic study, cryptanalysis, and to serve as a blueprint for production-grade implementations.

👉 **A full technical specification is available for review on [arXiv](https://arxiv.org/abs/XXXX.XXXXX) and [IACR ePrint](https://eprint.iacr.org/YYYY/XXX).** *(Note: Replace with your actual links after publication.)*

---

## 🌍 Overview & Features

Ilyazh-Web3E2E is a modern cryptographic protocol that provides multi-layered security for the Web3 era. Its architecture is founded on the principle of **trust through transparency**, using only standardized, community-vetted primitives.

**Core Components:**
* **Classical KEM:** `X25519` Curve Diffie-Hellman
* **Post-Quantum KEM:** `Kyber-768` (NIST Standard)
* **Authenticated Encryption:** `AES-256-GCM` (AEAD)
* **Forward Secrecy:** `Double Ratchet` Algorithm (inspired by Signal)

**Key Security Features:**
* ✅ **Post-Quantum Resistance:** Secure against attacks from future quantum computers.
* ✅ **Confidentiality (IND-CCA):** Protects message content from eavesdroppers and chosen-ciphertext attacks.
* ✅ **Integrity & Authenticity:** Protects messages from tampering and forgery.
* ✅ **Forward Secrecy (FS):** A compromise of long-term keys does not compromise past messages.
* ✅ **Post-Compromise Security (PCS):** The protocol can "heal" from a session state compromise.

---

## 🚀 Installation

This reference implementation requires Python 3.8+ and the following cryptographic libraries.

bash
pip install pycryptodome pqcrypto-kyber hkdf
⚡ Quickstart Example
The following example demonstrates a full end-to-end encryption and decryption cycle.

Python

from ilyazh_protocol import generate_kyber_keys, encrypt, decrypt

# 1. Recipient generates their key pair and shares the public key
recipient_sk, recipient_pk = generate_kyber_keys()

# 2. Sender uses the recipient's public key to encrypt a message
message = "Hello, Web3!"
associated_data = b"context:stvor-messenger,tx:0x123"
ciphertext_payload = encrypt(recipient_pk, message, associated_data)

# 3. Recipient uses their secret key to decrypt the payload
try:
    plaintext = decrypt(recipient_sk, ciphertext_payload, associated_data)
    print("✅ Decryption Successful!")
    print(f"   Original:  '{message}'")
    print(f"   Decrypted: '{plaintext}'")
    assert message == plaintext
except ValueError as e:
    print(f"❌ Decryption Failed: {e}")
🧩 Protocol Specification
The protocol defines a hybrid Authenticated Key Exchange (AKE) to establish a secure session, followed by a Double Ratchet for ongoing message exchange.

Cryptographic Primitives
Component	Specification
KEM	Hybrid: X25519 + Kyber-768
AEAD	AES-256-GCM
KDF	HKDF-SHA256
Signature	Ed25519 (Migration path to Dilithium3)

Экспортировать в Таблицы
Hybrid Key Encapsulation
The initial shared secret (ss) is derived by combining the outputs of both key exchanges using HKDF:

ss = HKDF-Extract(salt, X25519(sk_A, pk_B) || Kyber.Decaps(sk_A_pq, ct_B))

👉 For complete details, including the wire format, formal security model, and proof sketches, please see the Full Specification Paper.

🔒 Security Considerations
This protocol is secure only when implemented and used correctly. Key considerations include:

Nonce Management: The 96-bit GCM nonce is constructed as a 64-bit random prefix || 32-bit counter to prevent reuse, which is critical for GCM's security.

Session Limits: A session must be re-established after 2^32 messages. A rekey must occur every 2^20 messages or 24 hours.

Constant-Time Implementation: Production implementations must use constant-time code to prevent side-channel attacks.

Randomness: A Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) is required for all key material and nonces.

📊 Benchmarks (Python PoC)
These preliminary benchmarks are from the non-optimized Python proof-of-concept and are for illustrative purposes only. A production Rust implementation is expected to be significantly faster.

Metric	Approximate Value
Handshake Latency (Full AKE)	~150–200 ms
AEAD Throughput (1MB message)	~20–25 MB/s

Экспортировать в Таблицы
🗺️ Roadmap
[ ] Formal Verification: Model the protocol in Tamarin or ProVerif for a machine-checked security proof.

[ ] Rust Implementation: Develop a production-grade, constant-time reference implementation.

[ ] WASM Build: Create a WebAssembly build for in-browser Web3 dApps.

[ ] Integration: Pilot integration into the Stvor Messenger.

🙏 Acknowledgements
This protocol's architecture was significantly improved by following the guidance of Professor Henry Corrigan-Gibbs of MIT. The design is a direct reflection of lessons from the MIT 6.1600: Foundations of Computer Security course and research on the Signal Protocol.

✍️ Author
Ilyas Zhaisenbayev (Independent Researcher, 18 y.o.)

📜 License
The source code in this repository is licensed under the MIT License.

The specification document is licensed under CC BY 4.0.







нормально отправь всё в одном коде



Показать процесс размышления
Да, конечно. Понимаю, вам нужен один единый блок кода, который объединяет всё для удобства.

Однако, README.md (написанный на Markdown) и whitepaper.tex (написанный на LaTeX) — это два разных файла с разным синтаксисом и предназначением. Объединить их в один файл невозможно, так как это приведет к ошибкам.

Я отправлю вам два финальных блока кода в одном сообщении: сначала — для README.md, затем — для whitepaper.tex. Вы сможете скопировать каждый из них в соответствующий файл.

## 1. Финальный README.md (для GitHub)
Скопируйте этот код в файл README.md в вашем репозитории.

Markdown

# 🔐 Ilyazh-Web3E2E: A Post-Quantum Hybrid Encryption Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Specification Draft](https://img.shields.io/badge/status-specification-blue.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> A forward-secure, post-quantum hybrid protocol for authenticated key exchange and end-to-end (E2E) encrypted messaging in decentralized systems.

This repository contains the official Python proof-of-concept for the **Ilyazh-Web3E2E** protocol. It is designed for academic study, cryptanalysis, and to serve as a blueprint for production-grade implementations.

👉 **A full technical specification is available for review on [arXiv](https://arxiv.org/abs/XXXX.XXXXX) and [IACR ePrint](https://eprint.iacr.org/YYYY/XXX).** *(Note: Replace with your actual links after publication.)*

---

## 🌍 Overview & Features

Ilyazh-Web3E2E is a modern cryptographic protocol that provides multi-layered security for the Web3 era. It is built entirely on standardized, community-vetted primitives.

**Core Components:**
* **Classical KEM:** `X25519` Curve Diffie-Hellman
* **Post-Quantum KEM:** `Kyber-768` (NIST Standard)
* **Authenticated Encryption:** `AES-256-GCM` (AEAD)
* **Forward Secrecy:** `Double Ratchet` Algorithm (inspired by Signal)

**Key Security Features:**
* ✅ **Post-Quantum Resistance:** Secure against attacks from future quantum computers.
* ✅ **Confidentiality (IND-CCA):** Protects message content from eavesdroppers and chosen-ciphertext attacks.
* ✅ **Integrity & Authenticity:** Protects messages from tampering and forgery.
* ✅ **Forward Secrecy (FS):** A compromise of long-term keys does not compromise past messages.
* ✅ **Post-Compromise Security (PCS):** The protocol can "heal" from a session state compromise.

---

## 🚀 Installation

This reference implementation requires Python 3.8+ and the following cryptographic libraries.

```bash
pip install pycryptodome pqcrypto-kyber hkdf
⚡ Quickstart Example
The following example demonstrates a full end-to-end encryption and decryption cycle.

Python

from ilyazh_protocol import generate_kyber_keys, encrypt, decrypt

# 1. Recipient generates their key pair and shares the public key
recipient_sk, recipient_pk = generate_kyber_keys()

# 2. Sender uses the recipient's public key to encrypt a message
message = "Hello, Web3!"
associated_data = b"context:stvor-messenger,tx:0x123"
ciphertext_payload = encrypt(recipient_pk, message, associated_data)

# 3. Recipient uses their secret key to decrypt the payload
try:
    plaintext = decrypt(recipient_sk, ciphertext_payload, associated_data)
    print("✅ Decryption Successful!")
    print(f"   Original:  '{message}'")
    print(f"   Decrypted: '{plaintext}'")
    assert message == plaintext
except ValueError as e:
    print(f"❌ Decryption Failed: {e}")
🧩 Protocol Specification
The protocol defines a hybrid Authenticated Key Exchange (AKE) to establish a secure session, followed by a Double Ratchet for ongoing message exchange.

Cryptographic Primitives
Component	Specification
KEM	Hybrid: X25519 + Kyber-768
AEAD	AES-256-GCM
KDF	HKDF-SHA256
Signature	Ed25519 (Migration path to Dilithium3)

Экспортировать в Таблицы
Hybrid Key Encapsulation
The initial shared secret (ss) is derived by combining the outputs of both key exchanges using HKDF:

ss = HKDF-Extract(salt, X25519(sk_A, pk_B) || Kyber.Decaps(sk_A_pq, ct_B))

👉 For complete details, including the wire format, formal security model, and proof sketches, please see the Full Specification Paper.

🔒 Security Considerations
This protocol is secure only when implemented and used correctly. Key considerations include:

Nonce Management: The 96-bit GCM nonce is constructed as a 64-bit random prefix || 32-bit counter to prevent reuse, which is critical for GCM's security.

Session Limits: A session must be re-established after 2^32 messages. A rekey must occur every 2^20 messages or 24 hours.

Constant-Time Implementation: Production implementations must use constant-time code to prevent side-channel attacks.

Randomness: A Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) is required for all key material and nonces.

📊 Benchmarks (Python PoC)
These preliminary benchmarks are from the non-optimized Python proof-of-concept and are for illustrative purposes only. A production Rust implementation is expected to be significantly faster.

Metric	Approximate Value
Handshake Latency (Full AKE)	~150–200 ms
AEAD Throughput (1MB message)	~20–25 MB/s

Экспортировать в Таблицы
🗺️ Roadmap
[ ] Formal Verification: Model the protocol in Tamarin or ProVerif for a machine-checked security proof.

[ ] Rust Implementation: Develop a production-grade, constant-time reference implementation.

[ ] WASM Build: Create a WebAssembly build for in-browser Web3 dApps.

[ ] Integration: Pilot integration into the Stvor Messenger.

🙏 Acknowledgements
This protocol's architecture was significantly improved by following the guidance of Professor Henry Corrigan-Gibbs of MIT. The design is a direct reflection of lessons from the MIT 6.1600: Foundations of Computer Security course and research on the Signal Protocol.

✍️ Author
Ilyas Zhaisenbayev (Independent Researcher, 18 y.o.)

📜 License
The source code in this repository is licensed under the MIT License.

The specification document is licensed under CC BY 4.0.
