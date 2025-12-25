// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath

use thiserror::Error;

/// Vault error types with security-conscious messages
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("key derivation failed")]
    KeyDerivationFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("time-lock not expired")]
    TimeLockActive {
        unlock_time_utc: i64,
    },

    #[error("MFA required")]
    MfaRequired,

    #[error("MFA verification failed")]
    MfaVerificationFailed,

    #[error("identity not found")]
    IdentityNotFound,

    #[error("identity already exists")]
    IdentityAlreadyExists,

    #[error("invalid prime")]
    InvalidPrime,

    #[error("prime verification failed")]
    PrimeVerificationFailed,

    #[error("key encapsulation failed")]
    KeyEncapsulationFailed,

    #[error("key decapsulation failed")]
    KeyDecapsulationFailed,

    #[error("post-quantum signature failed")]
    PostQuantumSignatureFailed,

    #[error("armor encoding failed")]
    ArmorEncodingFailed,

    #[error("armor decoding failed")]
    ArmorDecodingFailed,

    #[error("polymorphic transformation failed")]
    PolymorphicTransformFailed,

    #[error("vault locked")]
    VaultLocked,

    #[error("vault corrupted")]
    VaultCorrupted,

    #[error("insufficient entropy")]
    InsufficientEntropy,

    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("io error: {0}")]
    IoError(String),

    #[error("secure memory allocation failed")]
    SecureMemoryFailed,

    #[error("operation not permitted")]
    OperationNotPermitted,
}

pub type VaultResult<T> = Result<T, VaultError>;
