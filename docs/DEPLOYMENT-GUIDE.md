# Svalinn Vault - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Svalinn Vault in production environments using systemd for process management and scheduling.

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 10 GB | 50+ GB (for backups) |
| Network | 10 Mbps | 100+ Mbps |

### Software Requirements

- **Operating System:** Linux (Ubuntu 22.04, RHEL 9, or similar)
- **Dependencies:**
  - Rust 1.70+
  - OpenSSL 1.1.1+
  - systemd
  - cron
  - curl
  - jq

## Installation Methods

### Method 1: Binary Installation (Recommended)

```bash
# Download latest release
curl -LO https://github.com/hyperpolymath/reasonably-good-token-vault/releases/latest/download/svalinn-vault-linux-x86_64.tar.gz

# Extract
 tar -xzf svalinn-vault-linux-x86_64.tar.gz

# Install binary
sudo mv svalinn /usr/bin/
sudo chmod 755 /usr/bin/svalinn

# Install systemd services
sudo cp packaging/systemd/*.service /etc/systemd/system/
sudo cp packaging/systemd/*.timer /etc/systemd/system/
sudo cp packaging/cron/svalinn-backup /etc/cron.d/

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable svalinn-vault.service svalinn-backup.timer
sudo systemctl start svalinn-vault.service
```

### Method 2: From Source

```bash
# Clone repository
git clone https://github.com/hyperpolymath/reasonably-good-token-vault.git
cd reasonably-good-token-vault

# Build
cargo build --release

# Install
sudo cp target/release/svalinn /usr/bin/
sudo chmod 755 /usr/bin/svalinn

# Continue with systemd installation as above
```

## Configuration

### Main Configuration

Edit `/etc/svalinn/config.nickel`:

```nickel
{
  vault = {
    # Storage configuration
    storage = {
      engine = "lithoglyph",
      path = "/var/lib/svalinn/data",
      encryption = {
        enabled = true,
        key_path = "/etc/svalinn/keys/master.key"
      }
    },
    
    # Network configuration
    network = {
      bind = "127.0.0.1:8443",
      tls = {
        enabled = true,
        cert_path = "/etc/svalinn/certs/cert.pem",
        key_path = "/etc/svalinn/certs/key.pem"
      }
    },
    
    # Backup configuration
    backup = {
      enabled = true,
      directory = "/var/lib/svalinn/backups",
      remote = {
        sftp = {
          enabled = true,
          host = "backup.example.com",
          port = 22,
          username = "vault-backup",
          key_path = "/etc/svalinn/keys/backup.key"
        }
      }
    }
  }
}
```

### MFA Configuration

Edit `/etc/svalinn/mfa-config.nickel`:

```nickel
{
  compliance = {
    default = "nist_aal2",
    presets = {
      nist_aal2 = {
        required_factors = 2,
        required_factor_types = [ "totp", "backup_code" ]
      }
    }
  }
}
```

## Service Management

### Start/Stop Services

```bash
# Start vault
sudo systemctl start svalinn-vault.service

# Stop vault
sudo systemctl stop svalinn-vault.service

# Restart vault
sudo systemctl restart svalinn-vault.service

# Check status
sudo systemctl status svalinn-vault.service
```

### Backup Management

```bash
# Check backup timer status
sudo systemctl status svalinn-backup.timer

# List timers
systemctl list-timers svalinn-backup.timer

# Manually trigger backup
sudo systemctl start svalinn-backup.service

# Check backup logs
journalctl -u svalinn-backup.service -f
```

## Monitoring

### Service Logs

```bash
# Vault service logs
journalctl -u svalinn-vault.service -f

# Backup service logs
journalctl -u svalinn-backup.service -f

# Cron fallback logs
cat /var/log/svalinn/backup-cron.log
```

### Metrics

```bash
# Check service metrics
sudo systemctl show svalinn-vault.service

# Check resource usage
top -p $(pgrep -f svalinn)

# Check disk usage
du -sh /var/lib/svalinn
```

## Backup and Recovery

### Automated Backups

The system includes two backup mechanisms:

1. **Systemd Timer** (primary)
   - Runs daily at 02:30
   - Persistent across reboots
   - Randomized delay (300 seconds)

2. **Cron Fallback** (secondary)
   - Runs only if systemd backup failed
   - Prevents duplicate backups
   - Lock file for safety

### Manual Backup

```bash
# Create manual backup
sudo svalinn backup create --output /var/lib/svalinn/backups

# List backups
sudo svalinn backup list

# Verify backup
sudo svalinn backup verify /var/lib/svalinn/backups/svalinn_backup_20240410.json.age

# Restore backup
sudo svalinn backup restore /var/lib/svalinn/backups/svalinn_backup_20240410.json.age
```

## Security Hardening

### Firewall Configuration

```bash
# Allow only local access (recommended)
sudo ufw allow from 127.0.0.1 to any port 8443

# If remote access is needed
sudo ufw allow 8443/tcp
sudo ufw limit 8443/tcp
```

### SELinux Configuration

```bash
# Install SELinux policy (if available)
sudo semodule -i packaging/selinux/svalinn.pp

# Verify SELinux status
sudo sestatus

# Check SELinux denials
sudo ausearch -m AVC -ts recent
```

## Troubleshooting

### Common Issues

**Issue: Vault service fails to start**
```bash
# Check logs
journalctl -u svalinn-vault.service -n 50

# Verify configuration
sudo svalinn vault check-config

# Test manually
sudo -u vault /usr/bin/svalinn vault serve
```

**Issue: Backups not running**
```bash
# Check timer status
systemctl list-timers svalinn-backup.timer

# Check timer logs
journalctl -u svalinn-backup.timer

# Manually trigger
sudo systemctl start svalinn-backup.service
```

**Issue: SFTP backups failing**
```bash
# Test SFTP connection
sftp -i /etc/svalinn/keys/backup.key vault-backup@backup.example.com

# Check SSH key permissions
chmod 600 /etc/svalinn/keys/backup.key
chown vault:vault /etc/svalinn/keys/backup.key
```

## Upgrading

### Minor Version Upgrades

```bash
# Stop services
sudo systemctl stop svalinn-vault.service svalinn-backup.timer

# Download new version
curl -LO https://github.com/hyperpolymath/reasonably-good-token-vault/releases/latest/download/svalinn-vault-linux-x86_64.tar.gz

# Extract and replace
 tar -xzf svalinn-vault-linux-x86_64.tar.gz
sudo mv svalinn /usr/bin/

# Restart services
sudo systemctl start svalinn-vault.service svalinn-backup.timer
```

### Major Version Upgrades

```bash
# Follow minor upgrade steps
# Then run migration if needed
sudo svalinn vault migrate
```

## Support

For issues not covered in this guide:

1. **Check GitHub Issues:** https://github.com/hyperpolymath/reasonably-good-token-vault/issues
2. **Review Documentation:** https://github.com/hyperpolymath/reasonably-good-token-vault/wiki
3. **Contact Maintainers:** security@svalinn.example.com

## License

This software is licensed under the **PMPL-1.0-or-later** license. See LICENSE file for details.

© 2024 Hyperpolymath. All rights reserved.
