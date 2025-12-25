// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Main vault implementation
//
// Security features:
// - Multi-layer encryption (AES-GCM + Kyber + Dilithium)
// - Time-locked access
// - MFA protection
// - Identity registry
// - Audit logging
// - Integrity verification

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::armor::ArmoredPayload;
use crate::crypto::{
    AesGcmCipher, Argon2Kdf, Blake3Hasher, CryptoEnvelope, Dilithium5Signer,
    EncryptedPayload, Kyber1024Kem, SecureKey, Shake3_256,
};
use crate::error::{VaultError, VaultResult};
use crate::identity::{Identity, IdentityRegistry, IdentityType};
use crate::mfa::{MfaAuthenticator, MfaMethod, MfaSession};
use crate::timelock::{TimeLock, TimeLockState};

/// Vault state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultState {
    /// Vault is locked, requires authentication
    Locked,
    /// Vault is unlocked but MFA pending
    MfaPending,
    /// Vault is fully unlocked
    Unlocked,
    /// Vault is sealed (requires special recovery)
    Sealed,
}

/// Vault configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Vault name
    pub name: String,
    /// Vault version
    pub version: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last unlock timestamp
    pub last_unlock: Option<DateTime<Utc>>,
    /// Auto-lock timeout in seconds (0 = disabled)
    pub auto_lock_timeout: u64,
    /// Require MFA for all operations
    pub require_mfa: bool,
    /// Allow recovery mode
    pub allow_recovery: bool,
    /// Maximum unlock attempts
    pub max_unlock_attempts: u32,
    /// Seal after max failures
    pub seal_on_max_failures: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            name: "svalinn-vault".to_string(),
            version: crate::VAULT_VERSION.to_string(),
            created_at: Utc::now(),
            last_unlock: None,
            auto_lock_timeout: 300, // 5 minutes
            require_mfa: true,
            allow_recovery: true,
            max_unlock_attempts: 5,
            seal_on_max_failures: true,
        }
    }
}

/// Audit log entry
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: Uuid,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Action performed
    pub action: AuditAction,
    /// Target identity (if applicable)
    pub target_id: Option<Uuid>,
    /// Success or failure
    pub success: bool,
    /// Additional details
    pub details: Option<String>,
    /// Hash of previous entry (chain integrity)
    pub prev_hash: [u8; 32],
}

/// Audit actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    VaultUnlock,
    VaultLock,
    VaultSeal,
    IdentityAdd,
    IdentityRemove,
    IdentityAccess,
    IdentityModify,
    MfaVerify,
    MfaFail,
    ConfigChange,
    RecoveryAttempt,
}

/// Audit log with integrity chain
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add a new audit entry
    pub fn add(&mut self, action: AuditAction, target_id: Option<Uuid>, success: bool, details: Option<String>) {
        let prev_hash = self.entries.last()
            .map(|e| {
                let data = serde_json::to_vec(e).unwrap_or_default();
                Blake3Hasher::hash(&data)
            })
            .unwrap_or([0u8; 32]);

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action,
            target_id,
            success,
            details,
            prev_hash,
        };

        self.entries.push(entry);
    }

    /// Verify audit log integrity
    pub fn verify_integrity(&self) -> bool {
        let mut prev_hash = [0u8; 32];

        for entry in &self.entries {
            if entry.prev_hash != prev_hash {
                return false;
            }
            let data = serde_json::to_vec(entry).unwrap_or_default();
            prev_hash = Blake3Hasher::hash(&data);
        }

        true
    }

    /// Get entries for a specific identity
    pub fn get_identity_history(&self, identity_id: &Uuid) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.target_id.as_ref() == Some(identity_id))
            .collect()
    }
}

/// Main vault structure
#[derive(Clone, Serialize, Deserialize)]
pub struct Vault {
    /// Vault configuration
    pub config: VaultConfig,
    /// Current state
    #[serde(skip)]
    pub state: VaultState,
    /// Encrypted master key (encrypted with password-derived key)
    pub encrypted_master_key: EncryptedPayload,
    /// Salt for password derivation
    pub password_salt: [u8; 32],
    /// Identity registry (encrypted)
    pub encrypted_registry: EncryptedPayload,
    /// MFA authenticator (encrypted)
    pub encrypted_mfa: Option<EncryptedPayload>,
    /// Global time-locks
    pub time_locks: Vec<TimeLock>,
    /// Audit log
    pub audit_log: AuditLog,
    /// Kyber public key for key exchange
    pub kyber_public_key: Vec<u8>,
    /// Dilithium public key for signatures
    pub dilithium_public_key: Vec<u8>,
    /// Vault signature (Dilithium)
    pub vault_signature: Vec<u8>,
    /// Integrity hash (BLAKE3)
    pub integrity_hash: [u8; 32],
    /// Failed unlock attempts
    #[serde(skip)]
    pub unlock_attempts: u32,
    /// Current MFA session
    #[serde(skip)]
    pub mfa_session: Option<MfaSession>,
    /// Decrypted crypto envelope (only when unlocked)
    #[serde(skip)]
    decrypted_envelope: Option<CryptoEnvelope>,
    /// Decrypted identity registry (only when unlocked)
    #[serde(skip)]
    decrypted_registry: Option<IdentityRegistry>,
    /// Decrypted MFA authenticator (only when unlocked)
    #[serde(skip)]
    decrypted_mfa: Option<MfaAuthenticator>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            config: VaultConfig::default(),
            state: VaultState::Locked,
            encrypted_master_key: EncryptedPayload {
                nonce: vec![],
                ciphertext: vec![],
                blake3_hash: vec![],
                shake3_hash: vec![],
            },
            password_salt: [0u8; 32],
            encrypted_registry: EncryptedPayload {
                nonce: vec![],
                ciphertext: vec![],
                blake3_hash: vec![],
                shake3_hash: vec![],
            },
            encrypted_mfa: None,
            time_locks: Vec::new(),
            audit_log: AuditLog::new(),
            kyber_public_key: vec![],
            dilithium_public_key: vec![],
            vault_signature: vec![],
            integrity_hash: [0u8; 32],
            unlock_attempts: 0,
            mfa_session: None,
            decrypted_envelope: None,
            decrypted_registry: None,
            decrypted_mfa: None,
        }
    }
}

impl Vault {
    /// Create a new vault with the given password
    pub fn create(name: &str, password: &[u8]) -> VaultResult<Self> {
        let password_salt = Argon2Kdf::generate_salt();

        // Create crypto envelope from password
        let mut envelope = CryptoEnvelope::from_password(password, &password_salt)?;

        // Generate post-quantum keys
        envelope.generate_pq_keys()?;

        // Generate Dilithium keypair for vault signing
        let (dilithium_pk, dilithium_sk) = Dilithium5Signer::generate_keypair();

        // Create empty identity registry
        let registry = IdentityRegistry::new();
        let registry_json = serde_json::to_vec(&registry)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
        let encrypted_registry = envelope.encrypt(&registry_json)?;

        // Create MFA authenticator
        let mfa = MfaAuthenticator::new();
        let mfa_json = serde_json::to_vec(&mfa)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
        let encrypted_mfa = envelope.encrypt(&mfa_json)?;

        // Encrypt master key itself (for secure storage)
        let master_key_bytes = envelope.master_key.as_bytes().to_vec();
        let kdf = Argon2Kdf::default();
        let storage_key = kdf.derive(password, &Blake3Hasher::hash(&password_salt))?;
        let storage_cipher = AesGcmCipher::new(&storage_key)?;
        let nonce = AesGcmCipher::generate_nonce();
        let encrypted_master = storage_cipher.encrypt(&nonce, &master_key_bytes)?;

        let encrypted_master_key = EncryptedPayload {
            nonce: nonce.to_vec(),
            ciphertext: encrypted_master,
            blake3_hash: Blake3Hasher::hash(&master_key_bytes).to_vec(),
            shake3_hash: Shake3_256::hash(&master_key_bytes).to_vec(),
        };

        // Extract Kyber public key
        let kyber_pk = envelope.kyber_keypair.as_ref()
            .map(|(pk, _)| pk.clone())
            .unwrap_or_default();

        let mut vault = Self {
            config: VaultConfig {
                name: name.to_string(),
                ..VaultConfig::default()
            },
            state: VaultState::Locked,
            encrypted_master_key,
            password_salt,
            encrypted_registry,
            encrypted_mfa: Some(encrypted_mfa),
            time_locks: Vec::new(),
            audit_log: AuditLog::new(),
            kyber_public_key: kyber_pk,
            dilithium_public_key: dilithium_pk,
            vault_signature: vec![],
            integrity_hash: [0u8; 32],
            unlock_attempts: 0,
            mfa_session: None,
            decrypted_envelope: None,
            decrypted_registry: None,
            decrypted_mfa: None,
        };

        // Sign the vault
        vault.sign(&dilithium_sk)?;

        // Calculate integrity hash
        vault.update_integrity()?;

        Ok(vault)
    }

    /// Sign the vault with Dilithium
    fn sign(&mut self, secret_key: &[u8]) -> VaultResult<()> {
        let data_to_sign = self.signable_data()?;
        self.vault_signature = Dilithium5Signer::sign(secret_key, &data_to_sign)?;
        Ok(())
    }

    /// Get data to sign/verify
    fn signable_data(&self) -> VaultResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.password_salt);
        data.extend_from_slice(&self.encrypted_registry.ciphertext);
        data.extend_from_slice(&self.kyber_public_key);
        data.extend_from_slice(&self.dilithium_public_key);
        Ok(data)
    }

    /// Verify vault signature
    pub fn verify_signature(&self) -> VaultResult<bool> {
        let data = self.signable_data()?;
        Dilithium5Signer::verify(&self.dilithium_public_key, &data, &self.vault_signature)
    }

    /// Update integrity hash
    fn update_integrity(&mut self) -> VaultResult<()> {
        let serialized = serde_json::to_vec(&self.encrypted_registry)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
        self.integrity_hash = Blake3Hasher::hash(&serialized);
        Ok(())
    }

    /// Verify vault integrity
    pub fn verify_integrity(&self) -> VaultResult<bool> {
        let serialized = serde_json::to_vec(&self.encrypted_registry)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
        Ok(Blake3Hasher::hash(&serialized) == self.integrity_hash)
    }

    /// Unlock vault with password
    pub fn unlock(&mut self, password: &[u8]) -> VaultResult<()> {
        // Check if sealed
        if self.state == VaultState::Sealed {
            return Err(VaultError::VaultLocked);
        }

        // Check time-locks
        for lock in &self.time_locks {
            if lock.state() == TimeLockState::Locked {
                return Err(VaultError::TimeLockActive {
                    unlock_time_utc: lock.next_unlock_time()
                        .map(|t| t.timestamp())
                        .unwrap_or(0),
                });
            }
        }

        // Derive storage key
        let kdf = Argon2Kdf::default();
        let storage_key = kdf.derive(password, &Blake3Hasher::hash(&self.password_salt))?;
        let storage_cipher = AesGcmCipher::new(&storage_key)?;

        // Decrypt master key
        let nonce: [u8; 12] = self.encrypted_master_key.nonce.clone()
            .try_into()
            .map_err(|_| VaultError::DecryptionFailed)?;

        let master_key_bytes = storage_cipher.decrypt(&nonce, &self.encrypted_master_key.ciphertext)
            .map_err(|_| {
                self.unlock_attempts += 1;
                if self.config.seal_on_max_failures
                    && self.unlock_attempts >= self.config.max_unlock_attempts
                {
                    self.state = VaultState::Sealed;
                }
                VaultError::AuthenticationFailed
            })?;

        // Verify master key integrity
        if Blake3Hasher::hash(&master_key_bytes).to_vec() != self.encrypted_master_key.blake3_hash {
            return Err(VaultError::VaultCorrupted);
        }

        // Create envelope with master key
        let envelope = CryptoEnvelope {
            master_key: SecureKey::from_bytes(master_key_bytes),
            kyber_keypair: None,
            dilithium_keypair: None,
            ed448_keypair: None,
        };

        // Decrypt identity registry
        let registry_json = envelope.decrypt(&self.encrypted_registry)?;
        let registry: IdentityRegistry = serde_json::from_slice(&registry_json)
            .map_err(|e| VaultError::DeserializationFailed(e.to_string()))?;

        // Decrypt MFA authenticator if present
        let mfa = if let Some(ref encrypted_mfa) = self.encrypted_mfa {
            let mfa_json = envelope.decrypt(encrypted_mfa)?;
            Some(serde_json::from_slice(&mfa_json)
                .map_err(|e| VaultError::DeserializationFailed(e.to_string()))?)
        } else {
            None
        };

        // Store decrypted data
        self.decrypted_envelope = Some(envelope);
        self.decrypted_registry = Some(registry);
        self.decrypted_mfa = mfa;
        self.unlock_attempts = 0;

        // Update state based on MFA requirement
        if self.config.require_mfa && self.decrypted_mfa.is_some() {
            self.state = VaultState::MfaPending;
        } else {
            self.state = VaultState::Unlocked;
            self.config.last_unlock = Some(Utc::now());
        }

        self.audit_log.add(AuditAction::VaultUnlock, None, true, None);

        Ok(())
    }

    /// Complete MFA verification
    pub fn verify_mfa(&mut self, method: MfaMethod, code: &str) -> VaultResult<()> {
        if self.state != VaultState::MfaPending {
            return Err(VaultError::OperationNotPermitted);
        }

        let mfa = self.decrypted_mfa.as_mut()
            .ok_or(VaultError::MfaRequired)?;

        if mfa.verify(method, code)? {
            // Create MFA session
            let (session, _token) = MfaSession::create(method, 3600); // 1 hour session
            self.mfa_session = Some(session);
            self.state = VaultState::Unlocked;
            self.config.last_unlock = Some(Utc::now());
            self.audit_log.add(AuditAction::MfaVerify, None, true, None);
            Ok(())
        } else {
            self.audit_log.add(AuditAction::MfaFail, None, false, None);
            Err(VaultError::MfaVerificationFailed)
        }
    }

    /// Lock the vault
    pub fn lock(&mut self) {
        self.decrypted_envelope = None;
        self.decrypted_registry = None;
        self.decrypted_mfa = None;
        self.mfa_session = None;
        self.state = VaultState::Locked;
        self.audit_log.add(AuditAction::VaultLock, None, true, None);
    }

    /// Add an identity to the vault
    pub fn add_identity(&mut self, identity: Identity) -> VaultResult<Uuid> {
        if self.state != VaultState::Unlocked {
            return Err(VaultError::VaultLocked);
        }

        let registry = self.decrypted_registry.as_mut()
            .ok_or(VaultError::VaultLocked)?;

        let id = registry.add(identity)?;

        // Re-encrypt registry
        self.persist_registry()?;

        self.audit_log.add(AuditAction::IdentityAdd, Some(id), true, None);

        Ok(id)
    }

    /// Get an identity by ID
    pub fn get_identity(&mut self, id: &Uuid) -> VaultResult<&Identity> {
        if self.state != VaultState::Unlocked {
            return Err(VaultError::VaultLocked);
        }

        let registry = self.decrypted_registry.as_mut()
            .ok_or(VaultError::VaultLocked)?;

        // Record access
        if let Some(identity) = registry.get_mut(id) {
            identity.record_access();
        }

        self.audit_log.add(AuditAction::IdentityAccess, Some(*id), true, None);

        registry.get(id).ok_or(VaultError::IdentityNotFound)
    }

    /// Remove an identity
    pub fn remove_identity(&mut self, id: &Uuid) -> VaultResult<Identity> {
        if self.state != VaultState::Unlocked {
            return Err(VaultError::VaultLocked);
        }

        let registry = self.decrypted_registry.as_mut()
            .ok_or(VaultError::VaultLocked)?;

        let identity = registry.remove(id)?;

        self.persist_registry()?;

        self.audit_log.add(AuditAction::IdentityRemove, Some(*id), true, None);

        Ok(identity)
    }

    /// List identities by type
    pub fn list_identities(&self, identity_type: Option<IdentityType>) -> VaultResult<Vec<&Identity>> {
        if self.state != VaultState::Unlocked {
            return Err(VaultError::VaultLocked);
        }

        let registry = self.decrypted_registry.as_ref()
            .ok_or(VaultError::VaultLocked)?;

        Ok(if let Some(t) = identity_type {
            registry.find_by_type(t)
        } else {
            registry.identities.iter().collect()
        })
    }

    /// Persist changes to the registry
    fn persist_registry(&mut self) -> VaultResult<()> {
        let envelope = self.decrypted_envelope.as_ref()
            .ok_or(VaultError::VaultLocked)?;

        let registry = self.decrypted_registry.as_ref()
            .ok_or(VaultError::VaultLocked)?;

        let registry_json = serde_json::to_vec(registry)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;

        self.encrypted_registry = envelope.encrypt(&registry_json)?;
        self.update_integrity()?;

        Ok(())
    }

    /// Add a time-lock to the vault
    pub fn add_time_lock(&mut self, time_lock: TimeLock) {
        self.time_locks.push(time_lock);
    }

    /// Enable MFA with TOTP
    pub fn enable_totp(&mut self, account_name: &str, issuer: &str) -> VaultResult<String> {
        if self.state != VaultState::Unlocked {
            return Err(VaultError::VaultLocked);
        }

        let mfa = self.decrypted_mfa.as_mut()
            .ok_or(VaultError::VaultLocked)?;

        let secret = mfa.enable_totp(account_name, issuer)?;

        // Persist MFA changes
        self.persist_mfa()?;

        Ok(secret)
    }

    /// Generate recovery codes
    pub fn generate_recovery_codes(&mut self, count: usize) -> VaultResult<Vec<String>> {
        if self.state != VaultState::Unlocked {
            return Err(VaultError::VaultLocked);
        }

        let mfa = self.decrypted_mfa.as_mut()
            .ok_or(VaultError::VaultLocked)?;

        let codes = mfa.generate_recovery_codes(count);

        self.persist_mfa()?;

        Ok(codes)
    }

    /// Persist MFA changes
    fn persist_mfa(&mut self) -> VaultResult<()> {
        let envelope = self.decrypted_envelope.as_ref()
            .ok_or(VaultError::VaultLocked)?;

        let mfa = self.decrypted_mfa.as_ref()
            .ok_or(VaultError::VaultLocked)?;

        let mfa_json = serde_json::to_vec(mfa)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;

        self.encrypted_mfa = Some(envelope.encrypt(&mfa_json)?);

        Ok(())
    }

    /// Export vault as armored payload
    pub fn export_armored(&self) -> VaultResult<ArmoredPayload> {
        let serialized = serde_json::to_vec(self)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;

        ArmoredPayload::encode(&serialized, "SVALINN VAULT")
    }

    /// Import vault from armored payload
    pub fn import_armored(armored: &ArmoredPayload) -> VaultResult<Self> {
        let data = armored.decode()?;
        serde_json::from_slice(&data)
            .map_err(|e| VaultError::DeserializationFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_create_and_unlock() {
        let mut vault = Vault::create("test-vault", b"password123").unwrap();

        assert_eq!(vault.state, VaultState::Locked);

        // Unlock should work
        vault.config.require_mfa = false;
        vault.unlock(b"password123").unwrap();
        assert_eq!(vault.state, VaultState::Unlocked);

        // Lock and verify
        vault.lock();
        assert_eq!(vault.state, VaultState::Locked);
    }

    #[test]
    fn test_vault_wrong_password() {
        let mut vault = Vault::create("test-vault", b"password123").unwrap();
        vault.config.require_mfa = false;

        assert!(vault.unlock(b"wrongpassword").is_err());
    }

    #[test]
    fn test_vault_identity_management() {
        let mut vault = Vault::create("test-vault", b"password123").unwrap();
        vault.config.require_mfa = false;
        vault.unlock(b"password123").unwrap();

        let identity = Identity::new(
            "test-ssh".to_string(),
            IdentityType::Ssh,
            vec![1, 2, 3],
            None,
        );

        let id = vault.add_identity(identity).unwrap();
        assert!(vault.get_identity(&id).is_ok());

        vault.remove_identity(&id).unwrap();
        assert!(vault.get_identity(&id).is_err());
    }
}
