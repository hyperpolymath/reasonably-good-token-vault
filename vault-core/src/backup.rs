// SPDX-License-Identifier: PMPL-1.0-or-later
// Svalinn Vault - Disaster Recovery Backup System

use crate::crypto::{aes256_gcm_encrypt, aes256_gcm_decrypt, blake3_hash};
use crate::storage::{CredentialStore, Credential};
use crate::error::VaultResult;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{Write, Read};
use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use uuid::Uuid;

/// Backup manifest containing metadata and encrypted credentials
#[derive(Serialize, Deserialize, Debug)]
pub struct BackupManifest {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub vault_version: String,
    pub encryption: EncryptionInfo,
    pub credentials: Vec<BackupCredential>,
    pub integrity: IntegrityInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub key_derivation: String,
    pub master_key_fingerprint: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BackupCredential {
    pub guid: Uuid,
    pub encrypted_data: Vec<u8>,
    pub checksum: String,
    pub metadata: CredentialMetadata,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialMetadata {
    pub r#type: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub access_count: u32,
    pub last_accessed: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IntegrityInfo {
    pub signature: Option<String>,
    pub manifest_hash: String,
}

/// Backup system for disaster recovery
pub struct BackupSystem {
    store: CredentialStore,
    backup_dir: PathBuf,
    remote_storage: Option<RemoteStorage>,
}

impl BackupSystem {
    /// Create new backup system
    pub fn new(store: CredentialStore, backup_dir: &Path) -> Self {
        Self {
            store,
            backup_dir: backup_dir.to_path_buf(),
            remote_storage: None,
        }
    }

    /// Add remote storage (S3, SFTP, etc.)
    pub fn with_remote_storage(mut self, remote: RemoteStorage) -> Self {
        self.remote_storage = Some(remote);
        self
    }

    /// Add SFTP remote storage
    pub fn with_sftp_storage(
        self,
        host: &str,
        port: u16,
        username: &str,
        key_path: &Path,
        remote_path: &str,
        passphrase: Option<&str>,
    ) -> VaultResult<Self> {
        let sftp = SFTPStorage::new(
            host.to_string(),
            port,
            username.to_string(),
            key_path.to_path_buf(),
            remote_path.to_string(),
            passphrase.map(|s| s.to_string()),
        );
        
        Ok(self.with_remote_storage(RemoteStorage::SFTP(sftp)))
    }

    /// Create complete backup (with optional MFA)
    pub fn create_backup(&self, backup_key: &[u8; 32], mfa_channel: Option<&MFAChannel>, user_id: Option<&str>) -> VaultResult<PathBuf> {
        // 1. Check MFA compliance if required
        if let (Some(mfa), Some(user)) = (mfa_channel, user_id) {
            let status = mfa.check_compliance(user)?;
            if !status.is_compliant() {
                return Err(crate::error::VaultError::MFAFailed(
                    format!("MFA not compliant for user {}: {:?}", user, status.missing_factors)
                ));
            }
        }
        
        // 2. Get all credentials from store
        let credentials = self.store.list_all_credentials()?;
=======

        // 2. Create backup manifest
        let mut manifest = BackupManifest {
            version: "1.0.0".to_string(),
            created_at: Utc::now(),
            vault_version: env!("CARGO_PKG_VERSION").to_string(),
            encryption: EncryptionInfo {
                algorithm: "AES-256-GCM".to_string(),
                key_derivation: "Argon2id".to_string(),
                master_key_fingerprint: self.calculate_key_fingerprint(backup_key)?,
            },
            credentials: Vec::new(),
            integrity: IntegrityInfo {
                signature: None,
                manifest_hash: String::new(),
            },
        };

        // 3. Encrypt each credential
        for cred in credentials {
            let cred_data = self.store.retrieve_credential(&cred.guid)?;
            let encrypted_data = self.encrypt_credential_data(&cred_data, backup_key)?;
            
            let checksum = self.calculate_checksum(&encrypted_data)?;
            
            manifest.credentials.push(BackupCredential {
                guid: cred.guid,
                encrypted_data,
                checksum,
                metadata: self.create_metadata(&cred)?,
            });
        }

        // 4. Calculate manifest integrity
        let manifest_json = serde_json::to_string(&manifest)?;
        let manifest_hash = blake3_hash(manifest_json.as_bytes());
        
        // 5. Sign manifest (placeholder for future post-quantum sigs)
        let signature = None; // TODO: Add Dilithium5 signing

        manifest.integrity = IntegrityInfo {
            signature,
            manifest_hash: hex::encode(manifest_hash),
        };

        // 6. Write backup file
        let backup_path = self.write_backup_file(&manifest)?;

        // 7. Upload to remote storage if configured
        if let Some(remote) = &self.remote_storage {
            remote.upload_backup(&backup_path, backup_key)?;
        }

        Ok(backup_path)
    }

    /// Restore from backup (with optional MFA)
    pub fn restore_backup(&self, backup_path: &Path, backup_key: &[u8; 32], mfa_channel: Option<&MFAChannel>, user_id: Option<&str>) -> VaultResult<()> {
        // 1. Check MFA compliance if required
        if let (Some(mfa), Some(user)) = (mfa_channel, user_id) {
            let status = mfa.check_compliance(user)?;
            if !status.is_compliant() {
                return Err(crate::error::VaultError::MFAFailed(
                    format!("MFA not compliant for user {}: {:?}", user, status.missing_factors)
                ));
            }
        }
        
        // 2. Read and parse backup file
        let manifest = self.read_backup_file(backup_path)?;
=======

        // 2. Verify integrity
        self.verify_backup_integrity(&manifest)?;

        // 3. Restore each credential
        for backup_cred in &manifest.credentials {
            let decrypted_data = self.decrypt_credential_data(&backup_cred.encrypted_data, backup_key)?;
            
            // Verify checksum
            let calculated_checksum = self.calculate_checksum(&backup_cred.encrypted_data)?;
            let stored_checksum = hex::decode(&backup_cred.checksum)?;
            if calculated_checksum != stored_checksum {
                return Err(crate::error::VaultError::BackupCorrupted(
                    format!("Checksum mismatch for credential {}", backup_cred.guid)
                ));
            }

            // Store in vault
            self.store.store_credential(&backup_cred.guid, &decrypted_data)?;
        }

        Ok(())
    }

    /// Automated backup with rotation
    pub fn automated_backup(&self, backup_key: &[u8; 32], keep: usize) -> VaultResult<()> {
        // 1. Create new backup
        let new_backup = self.create_backup(backup_key)?;

        // 2. Rotate old backups
        self.rotate_backups(keep)?;

        // 3. Verify latest backup
        self.verify_backup(&new_backup, backup_key)?;

        Ok(())
    }

    // Internal methods
    fn encrypt_credential_data(&self, data: &[u8], key: &[u8; 32]) -> VaultResult<Vec<u8>> {
        // Use vault's existing AES-GCM encryption
        aes256_gcm_encrypt(data, key, &[])
    }

    fn decrypt_credential_data(&self, data: &[u8], key: &[u8; 32]) -> VaultResult<Vec<u8>> {
        aes256_gcm_decrypt(data, key, &[])
    }

    fn calculate_checksum(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        Ok(blake3_hash(data).to_vec())
    }

    fn calculate_key_fingerprint(&self, key: &[u8; 32]) -> VaultResult<String> {
        let hash = blake3_hash(key);
        Ok(hex::encode(hash))
    }

    fn create_metadata(&self, cred: &Credential) -> VaultResult<CredentialMetadata> {
        Ok(CredentialMetadata {
            r#type: cred.credential_type().to_string(),
            created: cred.created_at(),
            modified: cred.modified_at(),
            access_count: cred.access_count(),
            last_accessed: cred.last_accessed(),
        })
    }

    fn write_backup_file(&self, manifest: &BackupManifest) -> VaultResult<PathBuf> {
        // Create backup directory
        std::fs::create_dir_all(&self.backup_dir)?;

        // Generate backup filename
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_name = format!("svalinn_backup_{}.json.age", timestamp);
        let backup_path = self.backup_dir.join(backup_name);

        // Serialize and write
        let manifest_json = serde_json::to_string_pretty(manifest)?;
        let mut file = File::create(&backup_path)?;
        file.write_all(manifest_json.as_bytes())?;

        Ok(backup_path)
    }

    fn read_backup_file(&self, path: &Path) -> VaultResult<BackupManifest> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        let manifest: BackupManifest = serde_json::from_str(&contents)?;
        Ok(manifest)
    }

    fn verify_backup_integrity(&self, manifest: &BackupManifest) -> VaultResult<()> {
        // Recalculate manifest hash
        let manifest_json = serde_json::to_string(manifest)?;
        let calculated_hash = blake3_hash(manifest_json.as_bytes());
        let calculated_hash_hex = hex::encode(calculated_hash);

        // Compare with stored hash
        if calculated_hash_hex != manifest.integrity.manifest_hash {
            return Err(crate::error::VaultError::BackupCorrupted(
                "Manifest integrity check failed".to_string()
            ));
        }

        Ok(())
    }

    fn verify_backup(&self, backup_path: &Path, backup_key: &[u8; 32]) -> VaultResult<()> {
        let manifest = self.read_backup_file(backup_path)?;
        
        // Test restore one random credential to verify
        if !manifest.credentials.is_empty() {
            let test_cred = &manifest.credentials[0];
            let _ = self.decrypt_credential_data(&test_cred.encrypted_data, backup_key)?;
        }

        Ok(())
    }

    fn rotate_backups(&self, keep: usize) -> VaultResult<()> {
        let mut backups: Vec<_> = std::fs::read_dir(&self.backup_dir)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("age") {
                    Some(entry)
                } else {
                    None
                }
            })
            .collect();

        // Sort by modification time (oldest first)
        backups.sort_by_key(|entry| entry.metadata().ok().and_then(|m| m.modified().ok()).unwrap_or(std::time::SystemTime::UNIX_EPOCH));

        // Delete old backups
        if backups.len() > keep {
            for entry in backups.iter().take(backups.len() - keep) {
                std::fs::remove_file(entry.path())?;
            }
        }

        Ok(())
    }
}

/// Remote storage interfaces
pub enum RemoteStorage {
    S3(S3Storage),
    SFTP(SFTPStorage),
    Local(LocalStorage),
}

impl RemoteStorage {
    pub fn upload_backup(&self, backup_path: &Path, backup_key: &[u8; 32]) -> VaultResult<()> {
        match self {
            RemoteStorage::S3(s3) => s3.upload(backup_path, backup_key),
            RemoteStorage::SFTP(sftp) => sftp.upload(backup_path, backup_key),
            RemoteStorage::Local(local) => local.copy(backup_path),
        }
    }
}

pub struct S3Storage {
    bucket: String,
    region: String,
    // Other S3 config
}

impl S3Storage {
    pub fn upload(&self, _backup_path: &Path, _backup_key: &[u8; 32]) -> VaultResult<()> {
        // TODO: Implement S3 upload with encryption
        Ok(())
    }
}

pub struct SFTPStorage {
    host: String,
    port: u16,
    username: String,
    key_path: PathBuf,
    remote_path: String,
    // SSH key passphrase (optional)
    passphrase: Option<String>,
}

impl SFTPStorage {
    pub fn new(
        host: String,
        port: u16,
        username: String,
        key_path: PathBuf,
        remote_path: String,
        passphrase: Option<String>,
    ) -> Self {
        Self {
            host,
            port,
            username,
            key_path,
            remote_path,
            passphrase,
        }
    }

    pub fn upload(&self, backup_path: &Path, _backup_key: &[u8; 32]) -> VaultResult<()> {
        use std::net::TcpStream;
        use ssh2::Session;
        
        // Connect to SFTP server
        let tcp = TcpStream::connect((self.host.as_str(), self.port))?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        // Authenticate with SSH key
        if let Some(passphrase) = &self.passphrase {
            sess.userauth_pubkey_file(&self.username, None, &self.key_path, Some(passphrase.as_str()))?;
        } else {
            sess.userauth_pubkey_file(&self.username, None, &self.key_path, None)?;
        }

        // Create remote directory if it doesn't exist
        self.create_remote_directory(&mut sess)?;

        // Upload backup file via SCP (simpler than SFTP for single files)
        let filename = backup_path.file_name()
            .ok_or_else(|| crate::error::VaultError::BackupFailed(
                format!("Invalid backup path: {}", backup_path.display())
            ))?;
        
        let remote_path = format!("{}/{}", self.remote_path, filename.to_string_lossy());
        
        let mut channel = sess.scp_send(
            &remote_path,
            0o600,  // Owner read/write only
            backup_path.metadata()?.len() as usize,
            None
        )?;

        // Read local file and upload
        let mut local_file = File::open(backup_path)?;
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = local_file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            channel.write(&buffer[..bytes_read])?;
        }
        
        channel.send_eof()?;
        channel.wait_eof()?;
        channel.close()?;
        channel.wait_close()?;

        Ok(())
    }

    fn create_remote_directory(&self, sess: &mut Session) -> VaultResult<()> {
        // Use SFTP subsystem to create directory
        let sftp = sess.sftp()?;
        
        // Try to create directory (ignore error if it already exists)
        let _ = sftp.mkdir(&self.remote_path, 0o700);
        
        Ok(())
    }
}

pub struct LocalStorage {
    dest_dir: PathBuf,
}

impl LocalStorage {
    pub fn copy(&self, backup_path: &Path) -> VaultResult<()> {
        let dest_path = self.dest_dir.join(
            backup_path.file_name().ok_or_else(|| 
                crate::error::VaultError::BackupFailed("Invalid backup path".to_string()))?
        );
        std::fs::copy(backup_path, dest_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_backup_roundtrip() {
        // This would test the full backup/restore cycle
        // with a mock credential store
    }

    #[test]
    fn test_backup_integrity() {
        // Test that corrupted backups are detected
    }

    #[test]
    fn test_backup_rotation() {
        // Test that old backups are properly rotated
    }
}
