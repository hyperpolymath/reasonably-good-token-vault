<!-- SPDX-License-Identifier: MPL-2.0-or-later -->
<!-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk> -->

# TOPOLOGY.md — reasonably-good-token-vault

## Purpose

Post-quantum secure identity vault for SSH keys, API tokens, PGP keys, and digital credentials. Open source and formally verified with protection against future quantum computers via lattice-based cryptography. Provides unified credential management with compliance, encryption at rest, and audit logging for hyperpolymath infrastructure.

## Module Map

```
reasonably-good-token-vault/
├── src/                 # Core vault implementation
│   ├── crypto/         # Quantum-safe cryptography (lattice-based)
│   ├── storage/        # Encrypted credential storage
│   ├── identity/       # Identity management and verification
│   └── audit/          # Compliance and audit logging
├── tests/              # Security test suite
├── docs/               # Vault architecture and usage
└── Cargo.toml          # Rust package manifest
```

## Data Flow

```
[Credential Input] ──► [Lattice-Based Encryption] ──► [Storage] ──► [Encrypted at Rest]
                                                           ↓
                                                    [Audit Log] ──► [Compliance]
```

## Security Properties

- **Post-quantum**: Resistant to quantum computer attacks
- **Formally verified**: Cryptographic proofs of correctness
- **Isolation**: Memory-safe Rust implementation
- **Compliance**: Audit trails for regulatory requirements
