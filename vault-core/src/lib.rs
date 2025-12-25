// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Svalinn Vault Core - Secure identity storage with post-quantum cryptography
//
// Security layers:
// - Argon2id: Memory-hard password derivation
// - SHAKE3-256: Extendable output function
// - Kyber-1024: Post-quantum key encapsulation
// - BLAKE3: Fast cryptographic hashing
// - Dilithium: Post-quantum digital signatures
// - Ed448: Edwards curve signatures (448-bit)
// - AES-256-GCM: Authenticated encryption
// - Time-locking: UTC-based access control
// - MFA: TOTP-based multi-factor authentication
// - Strong primes: Miller-Rabin proven with distributed flat primes

pub mod crypto;
pub mod identity;
pub mod mfa;
pub mod primes;
pub mod timelock;
pub mod vault;
pub mod armor;
pub mod polymorphic;
pub mod qrng;
pub mod versioning;
pub mod auth_protection;
pub mod password_policy;
pub mod lockdown;
pub mod error;

pub use crypto::*;
pub use identity::*;
pub use mfa::*;
pub use primes::*;
pub use timelock::*;
pub use vault::*;
pub use armor::*;
pub use polymorphic::*;
pub use qrng::*;
pub use versioning::*;
pub use auth_protection::*;
pub use password_policy::*;
pub use lockdown::*;
pub use error::*;

/// Vault version for compatibility checking
pub const VAULT_VERSION: &str = "0.1.0";

/// Cryptographic suite identifier
pub const CRYPTO_SUITE: &str = "SVALINN-PQ-2025";

/// Minimum Argon2id memory cost (64 MiB)
pub const ARGON2_MIN_MEMORY_KIB: u32 = 65536;

/// Argon2id time cost (iterations)
pub const ARGON2_TIME_COST: u32 = 4;

/// Argon2id parallelism
pub const ARGON2_PARALLELISM: u32 = 4;

/// AES-256-GCM key size in bytes
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes
pub const AES_NONCE_SIZE: usize = 12;

/// BLAKE3 output size for identity hashing
pub const BLAKE3_OUTPUT_SIZE: usize = 32;

/// SHAKE3-256 output size
pub const SHAKE3_OUTPUT_SIZE: usize = 32;

/// Ed448 signature size
pub const ED448_SIG_SIZE: usize = 114;

/// Kyber-1024 public key size
pub const KYBER1024_PK_SIZE: usize = 1568;

/// Kyber-1024 ciphertext size
pub const KYBER1024_CT_SIZE: usize = 1568;

/// Dilithium5 signature size
pub const DILITHIUM5_SIG_SIZE: usize = 4627;

/// Miller-Rabin rounds for prime verification
pub const MILLER_RABIN_ROUNDS: usize = 64;
