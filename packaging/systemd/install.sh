#!/bin/bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# Svalinn Vault - Systemd Installation Script

set -euo pipefail

# Configuration
INSTALL_DIR="/etc/svalinn"
BIN_DIR="/usr/bin"
SYSTEMD_DIR="/etc/systemd/system"
CRON_DIR="/etc/cron.d"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}" >&2
    exit 1
fi

# Check if svalinn binary exists
if [ ! -f "$BIN_DIR/svalinn" ]; then
    echo -e "${RED}Error: Svalinn binary not found at $BIN_DIR/svalinn${NC}" >&2
    echo -e "${YELLOW}Please install the vault first or specify the correct path${NC}" >&2
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$SYSTEMD_DIR"
mkdir -p "$CRON_DIR"

# Install systemd services
echo -e "${YELLOW}Installing systemd services...${NC}"
cp packaging/systemd/svalinn-vault.service "$SYSTEMD_DIR/"
cp packaging/systemd/svalinn-backup.service "$SYSTEMD_DIR/"
cp packaging/systemd/svalinn-backup.timer "$SYSTEMD_DIR/"

# Install cron fallback
echo -e "${YELLOW}Installing cron fallback...${NC}"
cp packaging/cron/svalinn-backup "$CRON_DIR/"
chmod 755 "$CRON_DIR/svalinn-backup"

# Reload systemd
echo -e "${YELLOW}Reloading systemd...${NC}"
systemctl daemon-reload

# Enable services
echo -e "${YELLOW}Enabling services...${NC}"
systemctl enable svalinn-vault.service
systemctl enable svalinn-backup.timer

# Start vault service
echo -e "${YELLOW}Starting vault service...${NC}"
systemctl start svalinn-vault.service

# Verify installation
echo -e "${YELLOW}Verifying installation...${NC}"
if systemctl is-active svalinn-vault.service; then
    echo -e "${GREEN}✓ Vault service is running${NC}"
else
    echo -e "${RED}✗ Vault service failed to start${NC}" >&2
    exit 1
fi

if systemctl is-enabled svalinn-backup.timer; then
    echo -e "${GREEN}✓ Backup timer is enabled${NC}"
else
    echo -e "${RED}✗ Backup timer failed to enable${NC}" >&2
    exit 1
fi

if [ -f "$CRON_DIR/svalinn-backup" ]; then
    echo -e "${GREEN}✓ Cron fallback is installed${NC}"
else
    echo -e "${RED}✗ Cron fallback failed to install${NC}" >&2
    exit 1
fi

# Print summary
echo -e "${GREEN}"\n" ============================================"
echo "  Svalinn Vault Systemd Installation Complete"
echo "============================================"
"${NC}"
echo ""
echo "Services installed:"
echo "  • svalinn-vault.service (main vault service)"
echo "  • svalinn-backup.timer (daily backups at 02:30)"
echo "  • svalinn-backup (cron fallback)"
echo ""
echo "Service status:"
systemctl status svalinn-vault.service --no-pager | grep "Active:"
echo ""
echo "Backup timer status:"
systemctl status svalinn-backup.timer --no-pager | grep "Active:"
echo ""
echo "Next backup scheduled:"
systemctl list-timers svalinn-backup.timer --no-pager | grep "Next"
echo ""
echo "Configuration files:"
echo "  • $SYSTEMD_DIR/svalinn-vault.service"
echo "  • $SYSTEMD_DIR/svalinn-backup.service"
echo "  • $SYSTEMD_DIR/svalinn-backup.timer"
echo "  • $CRON_DIR/svalinn-backup"
echo ""
echo "Logs:"
echo "  • journalctl -u svalinn-vault.service"
echo "  • journalctl -u svalinn-backup.service"
echo "  • cat $CRON_DIR/svalinn-backup.log"
echo ""
