// SPDX-License-Identifier: PMPL-1.0-or-later
// Svalinn Vault - Backup CLI Interface

use crate::backup::{BackupSystem, RemoteStorage, LocalStorage};
use crate::error::VaultResult;
use crate::vault::Vault;
use std::path::PathBuf;
use clap::{Arg, Command};
use dialoguer::{Input, Password, Confirm};
use std::fs;

/// Backup CLI commands
pub fn backup_commands() -> Command {
    Command::new("backup")
        .about("Manage vault backups")
        .subcommand(
            Command::new("create")
                .about("Create a new backup")
                .arg(Arg::new("output")
                    .short('o')
                    .long("output")
                    .help("Output directory for backup")
                    .default_value("/vault/backups"))
                .arg(Arg::new("remote")
                    .short('r')
                    .long("remote")
                    .help("Upload to remote storage after creation")
                    .action(clap::ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("restore")
                .about("Restore from backup")
                .arg(Arg::new("input")
                    .help("Backup file to restore from")
                    .required(true))
                .arg(Arg::new("force")
                    .short('f')
                    .long("force")
                    .help("Skip confirmation prompt")
                    .action(clap::ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("list")
                .about("List available backups")
                .arg(Arg::new("directory")
                    .short('d')
                    .long("directory")
                    .help("Backup directory")
                    .default_value("/vault/backups")),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify backup integrity")
                .arg(Arg::new("input")
                    .help("Backup file to verify")
                    .required(true)),
        )
        .subcommand(
            Command::new("rotate")
                .about("Rotate old backups")
                .arg(Arg::new("keep")
                    .help("Number of backups to keep")
                    .default_value("7"))
                .arg(Arg::new("directory")
                    .short('d')
                    .long("directory")
                    .help("Backup directory")
                    .default_value("/vault/backups")),
        )
}

/// Handle backup commands
pub fn handle_backup_command(
    vault: &Vault,
    matches: &clap::ArgMatches,
) -> VaultResult<()> {
    match matches.subcommand() {
        Some(("create", sub_matches)) => {
            handle_create_backup(vault, sub_matches)?;
        }
        Some(("restore", sub_matches)) => {
            handle_restore_backup(vault, sub_matches)?;
        }
        Some(("list", sub_matches)) => {
            handle_list_backups(sub_matches)?;
        }
        Some(("verify", sub_matches)) => {
            handle_verify_backup(vault, sub_matches)?;
        }
        Some(("rotate", sub_matches)) => {
            handle_rotate_backups(sub_matches)?;
        }
        _ => {
            eprintln!("Invalid backup command");
            std::process::exit(1);
        }
    }
    Ok(())
}

fn handle_create_backup(
    vault: &Vault,
    matches: &clap::ArgMatches,
) -> VaultResult<()> {
    println!("=== Svalinn Vault Backup Creation ===");
    
    // Get backup directory
    let backup_dir = matches.get_one::<String>("output").expect("TODO: handle error");
    let backup_dir = PathBuf::from(backup_dir);
    
    // Create backup directory if it doesn't exist
    fs::create_dir_all(&backup_dir)?;
    
    // Get backup key
    println!("\nBackup encryption key:");
    let backup_key = Password::new()
        .with_prompt("Enter backup encryption key")
        .with_confirmation("Confirm backup key", "Keys do not match")
        .interact()?;
    
    // Convert to 32-byte key
    let backup_key = if backup_key.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&backup_key.as_bytes()[..32]);
        key
    } else {
        // Pad with zeros (in production, use proper KDF)
        let mut key = [0u8; 32];
        key[..backup_key.len()].copy_from_slice(backup_key.as_bytes());
        key
    };
    
    // Create backup system
    let backup_system = BackupSystem::new(vault.store().clone(), &backup_dir);
    
    // Add remote storage if requested
    let backup_system = if matches.get_flag("remote") {
        println!("\nConfiguring SFTP remote storage...");
        
        // Get SFTP credentials
        let sftp_host = Input::new()
            .with_prompt("SFTP host")
            .default("backup.example.com".to_string())
            .interact_text()?;
        
        let sftp_port: u16 = Input::new()
            .with_prompt("SFTP port")
            .default(22)
            .interact_text()?;
        
        let sftp_username = Input::new()
            .with_prompt("SFTP username")
            .interact_text()?;
        
        let sftp_key_path = Input::new()
            .with_prompt("SSH key path")
            .default(format!("{}/.ssh/id_ed25519", std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())))
            .interact_text()?;
        
        let sftp_remote_path = Input::new()
            .with_prompt("Remote backup directory")
            .default("/backups/svalinn".to_string())
            .interact_text()?;
        
        let sftp_passphrase = Password::new()
            .with_prompt("SSH key passphrase (leave empty if none)")
            .allow_empty_password(true)
            .interact()?;
        
        let passphrase = if sftp_passphrase.is_empty() {
            None
        } else {
            Some(sftp_passphrase)
        };
        
        backup_system.with_sftp_storage(
            &sftp_host,
            sftp_port,
            &sftp_username,
            Path::new(&sftp_key_path),
            &sftp_remote_path,
            passphrase.as_deref(),
        )?
    } else {
        backup_system
    };
    
    // Create backup
    println!("\nCreating backup...");
    let backup_path = backup_system.create_backup(&backup_key)?;
    
    println!("✅ Backup created successfully!");
    println!("Location: {}", backup_path.display());
    println!("Size: {} bytes", backup_path.metadata()?.len());
    
    // Security warning
    println!("\n⚠️  SECURITY WARNING:");
    println!("- Store this backup file securely");
    println!("- Keep the encryption key separate from the backup");
    println!("- Without the key, this backup cannot be restored");
    
    Ok(())
}

fn handle_restore_backup(
    vault: &Vault,
    matches: &clap::ArgMatches,
) -> VaultResult<()> {
    println!("=== Svalinn Vault Backup Restore ===");
    
    let backup_path = PathBuf::from(matches.get_one::<String>("input").expect("TODO: handle error"));
    
    if !backup_path.exists() {
        return Err(crate::error::VaultError::BackupFailed(
            format!("Backup file not found: {}", backup_path.display())
        ));
    }
    
    // Confirmation
    if !matches.get_flag("force") {
        println!("\n⚠️  WARNING: Restoring will overwrite existing credentials!");
        let confirmed = Confirm::new()
            .with_prompt("Are you sure you want to restore?")
            .default(false)
            .interact()?;
        
        if !confirmed {
            println!("Restore cancelled.");
            return Ok(());
        }
    }
    
    // Get backup key
    println!("\nBackup encryption key:");
    let backup_key = Password::new()
        .with_prompt("Enter backup encryption key")
        .interact()?;
    
    // Convert to 32-byte key
    let backup_key = if backup_key.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&backup_key.as_bytes()[..32]);
        key
    } else {
        let mut key = [0u8; 32];
        key[..backup_key.len()].copy_from_slice(backup_key.as_bytes());
        key
    };
    
    // Create backup system
    let backup_dir = backup_path.parent().unwrap_or_else(|| PathBuf::from("/vault/backups").as_path());
    let backup_system = BackupSystem::new(vault.store().clone(), backup_dir);
    
    // Restore backup
    println!("\nRestoring backup...");
    backup_system.restore_backup(&backup_path, &backup_key)?;
    
    println!("✅ Backup restored successfully!");
    println!("All credentials have been restored to the vault.");
    
    Ok(())
}

fn handle_list_backups(matches: &clap::ArgMatches) -> VaultResult<()> {
    println!("=== Available Backups ===");
    
    let backup_dir = matches.get_one::<String>("directory").expect("TODO: handle error");
    let backup_dir = PathBuf::from(backup_dir);
    
    if !backup_dir.exists() {
        println!("No backups found in: {}", backup_dir.display());
        return Ok(());
    }
    
    let mut backups: Vec<_> = fs::read_dir(&backup_dir)?
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
    
    // Sort by modification time (newest first)
    backups.sort_by_key(|entry| 
        Reverse(entry.metadata().ok().and_then(|m| m.modified().ok()).unwrap_or(std::time::SystemTime::UNIX_EPOCH))
    );
    
    if backups.is_empty() {
        println!("No backups found in: {}", backup_dir.display());
        return Ok(());
    }
    
    println!("Found {} backups:\n", backups.len());
    
    for (i, entry) in backups.iter().enumerate() {
        let path = entry.path();
        let metadata = entry.metadata()?;
        let modified = metadata.modified()?.elapsed()?;
        
        println!("{}. {}", i + 1, path.file_name().expect("TODO: handle error").to_string_lossy());
        println!("   Size: {} bytes", metadata.len());
        println!("   Created: {} ago", 
            if modified.as_secs() < 60 {
                format!("{} seconds", modified.as_secs())
            } else if modified.as_secs() < 3600 {
                format!("{} minutes", modified.as_secs() / 60)
            } else if modified.as_secs() < 86400 {
                format!("{} hours", modified.as_secs() / 3600)
            } else {
                format!("{} days", modified.as_secs() / 86400)
            }
        );
        println!();
    }
    
    Ok(())
}

fn handle_verify_backup(
    vault: &Vault,
    matches: &clap::ArgMatches,
) -> VaultResult<()> {
    println!("=== Backup Verification ===");
    
    let backup_path = PathBuf::from(matches.get_one::<String>("input").expect("TODO: handle error"));
    
    if !backup_path.exists() {
        return Err(crate::error::VaultError::BackupFailed(
            format!("Backup file not found: {}", backup_path.display())
        ));
    }
    
    // Get backup key
    println!("\nBackup encryption key:");
    let backup_key = Password::new()
        .with_prompt("Enter backup encryption key")
        .interact()?;
    
    // Convert to 32-byte key
    let backup_key = if backup_key.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&backup_key.as_bytes()[..32]);
        key
    } else {
        let mut key = [0u8; 32];
        key[..backup_key.len()].copy_from_slice(backup_key.as_bytes());
        key
    };
    
    // Create backup system
    let backup_dir = backup_path.parent().unwrap_or_else(|| PathBuf::from("/vault/backups").as_path());
    let backup_system = BackupSystem::new(vault.store().clone(), backup_dir);
    
    // Verify backup
    println!("\nVerifying backup integrity...");
    backup_system.verify_backup(&backup_path, &backup_key)?;
    
    println!("✅ Backup verification successful!");
    println!("The backup file is intact and can be restored.");
    
    Ok(())
}

fn handle_rotate_backups(matches: &clap::ArgMatches) -> VaultResult<()> {
    println!("=== Backup Rotation ===");
    
    let backup_dir = matches.get_one::<String>("directory").expect("TODO: handle error");
    let backup_dir = PathBuf::from(backup_dir);
    
    let keep = matches.get_one::<String>("keep")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(7);
    
    println!("Rotating backups in: {}", backup_dir.display());
    println!("Keeping last {} backups", keep);
    
    // Create a temporary backup system for rotation
    let temp_store = crate::storage::MemoryStore::new();
    let backup_system = BackupSystem::new(temp_store, &backup_dir);
    
    backup_system.rotate_backups(keep)?;
    
    println!("✅ Backup rotation complete!");
    println!("Old backups have been removed.");
    
    Ok(())
}

// Helper for reverse sorting
struct Reverse<T>(T);
impl<T: Ord> PartialOrd for Reverse<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.0.partial_cmp(&self.0)
    }
}
impl<T: Ord> Ord for Reverse<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.0.cmp(&self.0)
    }
}
impl<T: Eq> PartialEq for Reverse<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl<T: Eq> Eq for Reverse<T> {}
