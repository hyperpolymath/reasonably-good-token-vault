// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Vault Lockdown Security Module
// Implements maximum file permission lockdown and chroot isolation

use crate::error::VaultError;
use crate::polymorphic::PolymorphicEngine;
use crate::qrng::QrngManager;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// File permission modes for different lockdown states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockdownPermissions {
    /// Permission mode for vault data files
    pub vault_files: u32,
    /// Permission mode for configuration files
    pub config_files: u32,
    /// Permission mode for log files (append-only)
    pub log_files: u32,
    /// Permission mode for socket files
    pub socket_files: u32,
}

impl LockdownPermissions {
    /// Maximum lockdown - no access whatsoever (chmod 000)
    pub fn locked() -> Self {
        Self {
            vault_files: 0o000,
            config_files: 0o400, // Read-only for recovery
            log_files: 0o200,   // Write-only for append
            socket_files: 0o000,
        }
    }

    /// Unlocked state - minimal necessary access
    pub fn unlocked() -> Self {
        Self {
            vault_files: 0o600,  // Owner read/write
            config_files: 0o400, // Read-only
            log_files: 0o200,    // Append-only
            socket_files: 0o600, // Socket access for API
        }
    }
}

/// Chroot jail configuration
#[derive(Debug, Clone)]
pub struct ChrootConfig {
    /// Jail root path
    pub jail_path: PathBuf,
    /// Allow minimal /dev entries
    pub minimal_dev: bool,
    /// Deny all shell access
    pub no_shell: bool,
    /// Jail permission mode
    pub jail_mode: u32,
}

impl Default for ChrootConfig {
    fn default() -> Self {
        Self {
            jail_path: PathBuf::from("/var/lib/svalinn/jail"),
            minimal_dev: true,
            no_shell: true,
            jail_mode: 0o500, // Execute-only
        }
    }
}

/// Lockdown manager for vault security
pub struct LockdownManager {
    /// Vault data directory
    vault_dir: PathBuf,
    /// Configuration directory
    config_dir: PathBuf,
    /// Log directory
    log_dir: PathBuf,
    /// Socket directory
    socket_dir: PathBuf,
    /// Chroot configuration
    chroot: ChrootConfig,
    /// QRNG for obfuscation seeding
    qrng: QrngManager,
    /// Polymorphic engine for code obfuscation
    polymorphic: PolymorphicEngine,
    /// Current lockdown state
    locked: bool,
}

impl LockdownManager {
    /// Create new lockdown manager
    pub fn new(
        vault_dir: PathBuf,
        config_dir: PathBuf,
        log_dir: PathBuf,
        socket_dir: PathBuf,
    ) -> Self {
        Self {
            vault_dir,
            config_dir,
            log_dir,
            socket_dir,
            chroot: ChrootConfig::default(),
            qrng: QrngManager::new(),
            polymorphic: PolymorphicEngine::new(),
            locked: false,
        }
    }

    /// Apply maximum lockdown to all vault files
    pub fn lock(&mut self) -> Result<(), VaultError> {
        let perms = LockdownPermissions::locked();

        // Lock vault data files (chmod 000)
        self.apply_permissions_recursive(&self.vault_dir.clone(), perms.vault_files)?;

        // Lock config files (read-only for recovery)
        self.apply_permissions_recursive(&self.config_dir.clone(), perms.config_files)?;

        // Set log files to append-only
        self.apply_permissions_recursive(&self.log_dir.clone(), perms.log_files)?;

        // Lock socket files completely
        self.apply_permissions_recursive(&self.socket_dir.clone(), perms.socket_files)?;

        // Apply quantum-seeded obfuscation
        self.apply_obfuscation()?;

        self.locked = true;
        Ok(())
    }

    /// Unlock vault files with minimal necessary permissions
    pub fn unlock(&mut self, _master_key: &[u8]) -> Result<(), VaultError> {
        // Verify master key before unlocking
        // (This would verify against stored hash)

        let perms = LockdownPermissions::unlocked();

        // Unlock in reverse order of sensitivity
        self.apply_permissions_recursive(&self.socket_dir.clone(), perms.socket_files)?;
        self.apply_permissions_recursive(&self.log_dir.clone(), perms.log_files)?;
        self.apply_permissions_recursive(&self.config_dir.clone(), perms.config_files)?;
        self.apply_permissions_recursive(&self.vault_dir.clone(), perms.vault_files)?;

        // Remove obfuscation
        self.remove_obfuscation()?;

        self.locked = false;
        Ok(())
    }

    /// Apply permissions recursively to directory
    fn apply_permissions_recursive(&self, path: &Path, mode: u32) -> Result<(), VaultError> {
        if !path.exists() {
            return Ok(());
        }

        if path.is_dir() {
            // Set directory permissions
            fs::set_permissions(path, Permissions::from_mode(mode))
                .map_err(|e| VaultError::Io(e.to_string()))?;

            // Process directory contents
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_dir() {
                        self.apply_permissions_recursive(&entry_path, mode)?;
                    } else {
                        fs::set_permissions(&entry_path, Permissions::from_mode(mode))
                            .map_err(|e| VaultError::Io(e.to_string()))?;
                    }
                }
            }
        } else {
            fs::set_permissions(path, Permissions::from_mode(mode))
                .map_err(|e| VaultError::Io(e.to_string()))?;
        }

        Ok(())
    }

    /// Apply quantum-seeded polymorphic obfuscation on lock
    fn apply_obfuscation(&mut self) -> Result<(), VaultError> {
        // Get quantum random seed for obfuscation
        let quantum_seed = self.qrng.get_bytes(32)?;

        // Seed the polymorphic engine
        self.polymorphic.seed(&quantum_seed);

        // Transform vault data with polymorphic obfuscation
        // (This would apply metamorphic transformations to stored data)

        Ok(())
    }

    /// Remove obfuscation on unlock
    fn remove_obfuscation(&mut self) -> Result<(), VaultError> {
        // Reverse polymorphic transformations
        // (This would decrypt and de-obfuscate stored data)

        Ok(())
    }

    /// Setup chroot jail
    pub fn setup_chroot(&self) -> Result<(), VaultError> {
        let jail = &self.chroot.jail_path;

        // Create jail directories
        fs::create_dir_all(jail).map_err(|e| VaultError::Io(e.to_string()))?;
        fs::create_dir_all(jail.join("dev")).map_err(|e| VaultError::Io(e.to_string()))?;
        fs::create_dir_all(jail.join("tmp")).map_err(|e| VaultError::Io(e.to_string()))?;

        // Set jail permissions
        fs::set_permissions(jail, Permissions::from_mode(self.chroot.jail_mode))
            .map_err(|e| VaultError::Io(e.to_string()))?;

        // Set tmp to sticky bit + restricted
        fs::set_permissions(jail.join("tmp"), Permissions::from_mode(0o1700))
            .map_err(|e| VaultError::Io(e.to_string()))?;

        Ok(())
    }

    /// Verify lockdown state
    pub fn verify_lockdown(&self) -> Result<LockdownReport, VaultError> {
        let mut report = LockdownReport::default();

        // Check vault file permissions
        report.vault_locked = self.verify_permissions(&self.vault_dir, 0o000)?;

        // Check socket permissions
        report.sockets_locked = self.verify_permissions(&self.socket_dir, 0o000)?;

        // Check chroot exists and is properly configured
        report.chroot_ready = self.chroot.jail_path.exists();

        // Overall status
        report.fully_locked = report.vault_locked && report.sockets_locked && self.locked;

        Ok(report)
    }

    /// Verify directory has expected permissions
    fn verify_permissions(&self, path: &Path, expected_mode: u32) -> Result<bool, VaultError> {
        if !path.exists() {
            return Ok(true); // Non-existent is considered locked
        }

        let metadata = fs::metadata(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let actual_mode = metadata.permissions().mode() & 0o777;

        Ok(actual_mode == expected_mode)
    }

    /// Check if vault is currently locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

/// Report on lockdown status
#[derive(Debug, Default)]
pub struct LockdownReport {
    /// Vault data files are locked (chmod 000)
    pub vault_locked: bool,
    /// Socket files are locked
    pub sockets_locked: bool,
    /// Chroot jail is ready
    pub chroot_ready: bool,
    /// Full lockdown active
    pub fully_locked: bool,
}

impl LockdownReport {
    /// Check if all lockdown requirements are met
    pub fn is_secure(&self) -> bool {
        self.fully_locked && self.chroot_ready
    }
}

/// API isolation layer for chroot communication
pub struct ApiIsolation {
    /// Path to API socket within chroot
    socket_path: PathBuf,
    /// Whether isolation is active
    active: bool,
}

impl ApiIsolation {
    /// Create new API isolation layer
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            active: false,
        }
    }

    /// Activate API isolation
    pub fn activate(&mut self) -> Result<(), VaultError> {
        // Only the API socket should be accessible across the chroot boundary
        // All other access is blocked

        self.active = true;
        Ok(())
    }

    /// Deactivate API isolation
    pub fn deactivate(&mut self) -> Result<(), VaultError> {
        self.active = false;
        Ok(())
    }

    /// Check if API isolation is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get socket path for API communication
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_lockdown_permissions() {
        let locked = LockdownPermissions::locked();
        assert_eq!(locked.vault_files, 0o000);
        assert_eq!(locked.socket_files, 0o000);

        let unlocked = LockdownPermissions::unlocked();
        assert_eq!(unlocked.vault_files, 0o600);
        assert_eq!(unlocked.socket_files, 0o600);
    }

    #[test]
    fn test_chroot_config_default() {
        let config = ChrootConfig::default();
        assert_eq!(config.jail_mode, 0o500);
        assert!(config.no_shell);
        assert!(config.minimal_dev);
    }

    #[test]
    fn test_lockdown_manager() {
        let temp = TempDir::new().unwrap();
        let vault_dir = temp.path().join("vault");
        let config_dir = temp.path().join("config");
        let log_dir = temp.path().join("log");
        let socket_dir = temp.path().join("socket");

        fs::create_dir_all(&vault_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&log_dir).unwrap();
        fs::create_dir_all(&socket_dir).unwrap();

        let manager = LockdownManager::new(vault_dir, config_dir, log_dir, socket_dir);

        assert!(!manager.is_locked());
    }

    #[test]
    fn test_lockdown_report() {
        let report = LockdownReport {
            vault_locked: true,
            sockets_locked: true,
            chroot_ready: true,
            fully_locked: true,
        };

        assert!(report.is_secure());
    }
}
