# Wikidata Entry Draft for Svalinn Vault

**Note to editor**: This is a draft for creating a Wikidata item. Please adjust language and claims as needed to meet notability guidelines. I've written this in a neutral, encyclopedic style.

---

## Proposed Item: Svalinn Vault

### Label (English)
Svalinn Vault

### Description (English)
open-source post-quantum secure credential storage software

### Also known as
- reasonable-good-token-vault
- Svalinn

---

## Claims

### Instance of (P31)
- free and open-source software (Q506883)
- cryptographic software (Q1503442)

### Programmed in (P277)
- ATS (Q4651936) - Applied Type System
- Zig (Q66707326)
- Scheme (Q52965)
- Idris (Q15620689)

### Developer (P178)
- Jonathan D.A. Jewell (Q___) ← *May need to create this item first*

### License (P275)
- GNU Affero General Public License, version 3.0 or later (Q28130012)

### Source code repository URL (P1324)
- https://github.com/hyperpolymath/reasonable-good-token-vault

### Official website (P856)
- https://svalinn.hyperpolymath.dev

### Publication date (P577)
- 25 December 2025

### Software version identifier (P348)
- 0.1.0 (point in time: 25 December 2025)

### Operating system (P306)
- Linux (Q388)
- macOS (Q14116)
- Microsoft Windows (Q1406)
- Android (Q94)

### Uses (P2283)
- Kyber (Q___) ← *NIST ML-KEM, may need item*
- Dilithium (Q___) ← *NIST ML-DSA, may need item*
- AES (Q177512)
- BLAKE3 (Q89477127)
- Argon2 (Q19903652)

### Part of (P361)
- post-quantum cryptography (Q7233684)

### Field of work (P101)
- computer security (Q3510521)
- cryptography (Q8789)
- identity management (Q1652926)

---

## Description for Wikipedia article (if notable enough)

**Svalinn Vault** is a free and open-source credential storage system that uses post-quantum cryptography to protect SSH keys, PGP keys, and API tokens. It was developed by Jonathan D.A. Jewell and released in December 2025 under the GNU Affero General Public License.

The software is named after Svalinn, the shield that protects the earth from the sun in Norse mythology. It uses NIST-standardized post-quantum algorithms including ML-KEM (Kyber-1024) for key encapsulation and ML-DSA (Dilithium5) for digital signatures, combined with classical cryptographic primitives.

The system is notable for its "hostile environment" threat model, which assumes that all external systems may be compromised. It implements a dual-container architecture where credentials are stored as UUID fragments and only assembled at the moment of delivery.

The core is implemented in ATS (Applied Type System), a functional programming language with dependent types that allows security properties to be verified at compile time.

---

## Suggested sources for notability

1. arXiv preprint: "Svalinn Vault: A Post-Quantum Secure Identity Storage System" (cs.CR)
2. GitHub repository with open-source code
3. Coverage in security research community (pending)

---

## Notes for Wikidata editors

- This is a technical piece of software, so most claims relate to its technical characteristics
- The developer may need a separate Wikidata item if one doesn't exist
- The post-quantum cryptography algorithms (Kyber, Dilithium) may need separate items or disambiguation
- The software follows NIST FIPS 203 and FIPS 204 standards for post-quantum cryptography

---

## References to include

- NIST FIPS 203 (ML-KEM Standard)
- NIST FIPS 204 (ML-DSA Standard)
- GitHub repository
- arXiv preprint (when published)
